"""Recoverable cutover: quiesce, durable intent, authoritative options, atomic identity commit."""
import hashlib
import json
import secrets
import sqlite3
from urllib.parse import urlsplit
from pathlib import Path
from server.app.setup import validate_options,SetupService
from server.app.store import Store,ConflictError
from server.app.journal import Actor,append_event

async def check_readiness(draft):
    from server.app.network_checks import public_addresses,get_json,PinnedResolver
    import aiohttp
    host=urlsplit(draft['server_url']).hostname
    result=dict(dns=False,tls=False,wildcard=False,ready=False)
    try:
        addresses=await public_addresses(host)
        random_host='check-'+secrets.token_hex(8)+'.'+draft['base_domain']
        wildcard=await public_addresses(random_host)
        result['dns']=bool(addresses and set(addresses)==set(wildcard))
        health=await get_json(draft['server_url']+'/health',addresses)
        result['tls']=health.get('status')=='ok' and health.get('protocol')==1
        connector=aiohttp.TCPConnector(resolver=PinnedResolver(random_host,wildcard),use_dns_cache=False)
        async with aiohttp.ClientSession(connector=connector,timeout=aiohttp.ClientTimeout(total=5),trust_env=False) as session:
            async with session.get('https://'+random_host+'/',allow_redirects=False) as response:
                result['wildcard']=response.status==404
        result['ready']=all(result[key] for key in ('dns','tls','wildcard'))
    except (OSError,ValueError,TimeoutError,aiohttp.ClientError): pass
    return result

class DomainMigration:
    def __init__(self,store,setup,access,*,readiness=check_readiness):
        self.store,self.setup,self.access=store,setup,access
        self.readiness=readiness

    def _revision(self,options,db):
        clients=[tuple(row) for row in db.execute('SELECT id,domain,revision,generation,issued,expires,code_hash FROM clients ORDER BY id')]
        return hashlib.sha256(json.dumps([options,clients],sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def _target(self,draft,current):
        target=validate_options(draft)
        for name in set(target)|set(current):
            if name not in ('base_domain','server_url') and target.get(name)!=current.get(name):
                raise ValueError('Only client domain and registration address can change here')
        if target['base_domain']==current['base_domain'] and target['server_url']==current['server_url']:
            raise ValueError('Specify a different client domain or registration address')
        reserved=set(target.get('reserved_names',[]))|{'tunnel','www','mail','smtp','ftp','admin','api',urlsplit(target['server_url']).hostname.split('.')[0]}
        with self.store.connection() as db:
            for row in db.execute('SELECT domain FROM clients'):
                if row['domain'].split('.')[0] in reserved: raise ValueError('Reserved client label conflicts')
        return target

    async def preview(self,draft):
        current=(await self.setup.supervisor.get('/addons/self/info'))['options']
        target=self._target(draft,current)
        with self.store.connection() as db:
            revision=self._revision(current,db)
            clients=[dict(client_id=row['id'],old_domain=row['domain'],
                new_domain=row['domain'].split('.')[0]+'.'+target['base_domain'],revision=row['revision'],
                revoked=bool(row['revoked']),manual_paused=bool(row['paused']))
                for row in db.execute('SELECT * FROM clients ORDER BY id')]
        readiness=await self.readiness(target)
        return dict(revision=revision,old=current['server_url'],new=target['server_url'],
            old_base=current['base_domain'],new_base=target['base_domain'],clients=clients,readiness=readiness)

    def _save_marker(self,marker): self.store.set_metadata('domain_migration',marker)

    def _commit(self,marker):
        target=marker['target']
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            saved=json.loads(db.execute("SELECT value FROM server_metadata WHERE name='domain_migration'").fetchone()[0])
            if saved['phase']=='committed': return saved['result']
            for row in db.execute('SELECT * FROM clients').fetchall():
                new=row['domain'].split('.')[0]+'.'+target['base_domain']
                db.execute('''UPDATE clients SET domain=?,code_hash=NULL,code_ciphertext=NULL,secret_hash=NULL,
                    status_secret_hash=NULL,capabilities='[]',generation=generation+1,revision=revision+1 WHERE id=?''',(new,row['id']))
            db.execute('DELETE FROM access_commands')
            result=dict(phase='committed',old=marker['original']['server_url'],new=target['server_url'],
                base_domain=target['base_domain'],command_id=marker['command_id'])
            marker['phase']='committed';marker['result']=result
            db.execute("INSERT OR REPLACE INTO server_metadata VALUES ('domain_migration',?)",(json.dumps(marker),))
            db.execute('INSERT OR REPLACE INTO server_metadata VALUES (?,?)',
                ('domain_migration:'+marker['command_id'],json.dumps(dict(request=marker['request'],result=result))))
            actor=Actor(**marker['actor'])
            append_event(db,action='domain_migration',actor=actor,at=self.store.now(),
                operation_id='domain-move:'+marker['command_id'],details={'count':db.execute('SELECT COUNT(*) FROM clients').fetchone()[0]})
        self._save_marker(marker)
        return result

    def _activate(self,target):
        self.store.base_domain=target['base_domain']
        self.store.reserved=set(target.get('reserved_names',[]))|{'tunnel','www','mail','smtp','ftp','admin','api',urlsplit(target['server_url']).hostname.split('.')[0]}
        for cache in (self.store.live_proxies,self.store.live_sessions,self.store.login_sessions): cache.clear()
        self.setup.options=dict(target)

    async def apply(self,draft,command_id,expected_revision,*,actor=None):
        if not isinstance(command_id,str) or not 1<=len(command_id)<=128 or not isinstance(expected_revision,str) or len(expected_revision)!=64:
            raise ValueError('Invalid migration command')
        actor=actor or Actor('system')
        target=validate_options(draft)
        request=json.dumps([target,expected_revision],sort_keys=True,separators=(',',':'))
        async with self.setup.lock:
            old=self.store.get_metadata('domain_migration:'+command_id)
            if old:
                if old['request']!=request: raise ValueError('Command identifier was reused')
                return old['result']
            marker=self.store.get_metadata('domain_migration')
            if marker and marker['phase'] not in ('committed','aborted'): raise ConflictError('Recover the interrupted migration first')
            current=(await self.setup.supervisor.get('/addons/self/info'))['options']
            target=self._target(target,current)
            preview=await self.preview(target)
            if preview['revision']!=expected_revision: raise ConflictError('Preview is stale')
            if preview['readiness'].get('ready') is not True: raise ConflictError('DNS, wildcard route and verified TLS must be ready')
            self.store.migrating=True
            marker=dict(phase='prepared',command_id=command_id,request=request,original=current,target=target,
                actor=dict(source=actor.source,user_id=actor.user_id))
            try:
                if self.access is not None: await self.access.quiesce()
                with self.store.connection() as db:
                    if self._revision(current,db)!=expected_revision: raise ConflictError('Preview is stale')
                self._save_marker(marker)
                await self.setup.supervisor.post('/addons/self/options',{'options':target})
                marker['phase']='options_saved';self._save_marker(marker)
                result=self._commit(marker)
                self._activate(target)
                return result
            finally:
                # Keep all authorization closed until the normal app reload has reconciled identity.
                if self.setup.on_saved:self.setup.on_saved()

    async def recover(self):
        marker=self.store.get_metadata('domain_migration')
        if not marker or marker['phase']=='aborted': return False
        if not isinstance(marker,dict) or marker.get('phase') not in ('prepared','options_saved','committed'):
            raise ValueError('Invalid migration recovery marker')
        original,target=validate_options(marker['original']),validate_options(marker['target'])
        current=(await self.setup.supervisor.get('/addons/self/info'))['options']
        self.store.migrating=True
        if marker['phase']=='committed':
            current=validate_options(current)
            if any(current[field]!=target[field] for field in ('base_domain','server_url')):
                raise ValueError('Committed migration identity disagrees')
            self._activate(current);self.store.migrating=False
            return True
        if current==original and marker['phase']=='prepared':
            marker['phase']='aborted';self._save_marker(marker)
            self._activate(original);self.store.migrating=False
            return False
        if current!=target: raise ValueError('Interrupted migration options disagree')
        self._commit(marker)
        self._activate(target);self.store.migrating=False
        return True

async def recover_directory(setup):
    path=setup.directory/'state'/'state.db'
    if not path.exists():return False
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
        table=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='server_metadata'").fetchone()
        if not table:return False
        row=db.execute("SELECT value FROM server_metadata WHERE name='domain_migration'").fetchone()
    if not row:return False
    marker=json.loads(row[0])
    base=marker['target' if marker.get('phase')=='committed' else 'original']['base_domain']
    store=Store(path,base)
    return await DomainMigration(store,setup,None).recover()
