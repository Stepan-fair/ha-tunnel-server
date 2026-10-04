"""Clean-install configuration; Supervisor options remain authoritative."""
import hashlib
import hmac
import json
import secrets
import sqlite3
import asyncio
from pathlib import Path
from urllib.parse import urlsplit
from aiohttp import web
from shared.files import atomic_write
from shared.http import csrf_for,safe_errors
from shared.validation import domain,origin,label
from server.app.journal import Actor,current_actor
from shared.help import documentation


def validate_options(options):
    if set(options)-{'base_domain','server_url','npm_host','admin_user_ids','reserved_names','bandwidth_limit_mb'}:
        raise ValueError('Unknown option')
    result=dict(options)
    result['base_domain']=domain(result.get('base_domain',''))
    result['server_url']=origin(result.get('server_url',''))
    host=urlsplit(result['server_url']).hostname
    if host.split('.')[1:]!=result['base_domain'].split('.'): raise ValueError('Server must be one direct subdomain')
    npm=result.get('npm_host')
    if not isinstance(npm,str) or len(npm)>253: raise ValueError('NPM hostname required')
    for part in npm.split('.'): label(part)
    users=result.get('admin_user_ids')
    if not isinstance(users,list) or not users or len(users)>100 or any(not isinstance(u,str) or not u or len(u)>128 for u in users):
        raise ValueError('Administrator required')
    names=result.get('reserved_names',[])
    if not isinstance(names,list) or len(names)>100: raise ValueError('Invalid reserved names')
    for name in names: label(name)
    limit=result.get('bandwidth_limit_mb',10)
    if type(limit) is not int or not 1<=limit<=1000: raise ValueError('Invalid bandwidth')
    return result


class SetupConflict(ValueError): pass
class SetupAuditError(RuntimeError): pass


class SetupService:
    def __init__(self,directory,supervisor):
        self.directory=Path(directory); self.supervisor=supervisor
        self.options={}; self.detected={}; self.has_clients=self._has_clients
        self.on_saved=None; self.journal=None
        self.lock=asyncio.Lock()
        self.check_lock=asyncio.Lock()

    async def check(self,data):
        from server.app.network_checks import check_network
        if not isinstance(data,dict) or set(data)-{'server_url','wan_ip','static_confirmed','skip_external'}:
            raise ValueError('Invalid diagnostic request')
        if type(data.get('skip_external',False)) is not bool: raise ValueError()
        if self.check_lock.locked(): raise SetupConflict('Diagnostic already running')
        async with self.check_lock:
            return await check_network({'server_url':data.get('server_url',self.options.get('server_url')),
                'skip_external':data.get('skip_external',False)},data.get('wan_ip'),data.get('static_confirmed',False))

    def _has_clients(self):
        path=self.directory/'state'/'state.db'
        if not path.exists(): return False
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
            return bool(db.execute('SELECT 1 FROM clients LIMIT 1').fetchone())

    def validate_existing(self,options):
        path=self.directory/'state/state.db'
        if not path.exists(): return
        reserved=set(options.get('reserved_names',[]))|{'tunnel','www','mail','smtp','ftp','admin','api',urlsplit(options['server_url']).hostname.split('.')[0]}
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
            for domain_name, in db.execute('SELECT domain FROM clients'):
                if domain_name.split('.')[0] in reserved: raise ValueError('Reserved name conflicts with clients')
                if domain_name.split('.')[1:]!=options['base_domain'].split('.'): raise ValueError('Domain conflicts with clients')

    @staticmethod
    def revision(options):
        return hashlib.sha256(json.dumps(options,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def snapshot(self):
        try: validate_options(self.options); ready=True
        except (ValueError,TypeError): ready=False
        return {'ready':ready,'options':dict(self.options),'revision':self.revision(self.options),'detected':dict(self.detected)}

    async def detect(self):
        own=await self.supervisor.get('/addons/self/info')
        self.options=own['options']
        self.detected={'server_host':own['hostname']} if own.get('hostname') else {}
        try:
            info=await self.supervisor.get('/supervisor/info')
            self.detected.update({k:info[k] for k in ('timezone','arch') if k in info})
        except Exception: self.detected['discovery']='unknown'
        # The default Supervisor role permits info for a known app but not listing apps.
        # This is the public Community Apps identifier, never an owner's installation data.
        candidates=['a0d7b954_nginxproxymanager']
        try:
            apps=await self.supervisor.get('/addons')
            candidates=[app['slug'] for app in apps.get('addons',[]) if 'nginxproxymanager' in app.get('slug','')]+candidates
        except Exception: pass
        for candidate in dict.fromkeys(candidates):
            try:
                npm=await self.supervisor.get('/addons/'+candidate+'/info')
                if npm.get('hostname'):
                    self.detected['npm_host']=npm['hostname']; break
            except Exception: continue
        if 'npm_host' not in self.detected: self.detected['discovery']='unknown'
        return self.snapshot()

    async def save(self,draft,expected_revision):
        async with self.lock: return await self._save(draft,expected_revision)

    async def _save(self,draft,expected_revision):
        if not isinstance(draft,dict): raise ValueError('Invalid options')
        current=(await self.supervisor.get('/addons/self/info'))['options']
        self.options=current
        if expected_revision!=self.revision(current): raise SetupConflict('stale options')
        validated=validate_options(draft)
        if current.get('base_domain')!=validated['base_domain'] and self.has_clients():
            raise ValueError('Cannot change domain with clients')
        if current.get('server_url')!=validated['server_url'] and self.has_clients():
            raise ValueError('Cannot change server identity with clients')
        self.validate_existing(validated)
        self.directory.mkdir(parents=True,exist_ok=True)
        atomic_write(self.directory/'setup.draft.json',json.dumps(validated).encode())
        if self.journal is None:
            from server.app.store import Store
            from server.app.journal import Journal
            self.journal=Journal(Store(self.directory/'state'/'state.db',current.get('base_domain') or validated['base_domain']),
                operations_path=self.directory/'journal-operations.json')
        operation=self.journal.request('settings',self.journal.store.now())
        try: await self.supervisor.post('/addons/self/options',{'options':validated})
        except Exception:
            self.journal.finish(operation,'error',self.journal.store.now())
            raise
        self.options=validated
        try: self.journal.finish(operation,'success',self.journal.store.now())
        except Exception: raise SetupAuditError('Settings saved; journal pending') from None
        finally:
            if self.on_saved: self.on_saved()
        return self.snapshot()


def make_setup_app(setup,admin_check,*,ingress_ips=None):
    key=secrets.token_bytes(32)
    @web.middleware
    async def guard(request,handler):
        user=request.headers.get('X-Remote-User-Id','')
        if request.remote not in (ingress_ips or ['172.30.32.2']) or not user: raise web.HTTPForbidden()
        try: verified=await admin_check(user)
        except Exception: verified=False
        if not verified: raise web.HTTPForbidden()
        if request.method not in ('GET','HEAD') and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),csrf_for(key,user)):
            raise web.HTTPForbidden()
        token=current_actor.set(Actor('web',user))
        try: return await handler(request)
        finally: current_actor.reset(token)
    app=web.Application(client_max_size=16384,middlewares=[safe_errors,guard])
    async def snapshot(request):
        result=setup.snapshot(); result.update(csrf=csrf_for(key,request.headers['X-Remote-User-Id']),user_id=request.headers['X-Remote-User-Id'])
        return web.json_response(result)
    async def save(request):
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'draft','revision'}: raise ValueError()
        try: return web.json_response(await setup.save(data['draft'],data['revision']))
        except SetupConflict: raise web.HTTPConflict(reason='Настройки изменились. Обновите страницу.')
        except SetupAuditError: return web.json_response({'error':'audit_pending','message':'Настройки сохранены. Запись журнала не завершена; приложение перезапускается для согласования состояния.'},status=503)
    async def index(request):
        return web.FileResponse(Path(__file__).parent/'templates'/'index.html')
    async def help_page(request): return web.json_response({'text':documentation(__file__)})
    async def asset(request):
        name=request.match_info['name']
        if name not in ('app.js','style.css'): raise web.HTTPNotFound()
        return web.Response(body=(Path(__file__).parent/'templates'/name).read_bytes(),
            content_type='text/javascript' if name.endswith('.js') else 'text/css')
    async def check(request):
        try: return web.json_response(await setup.check(await request.json()))
        except SetupConflict: raise web.HTTPConflict()
    app.add_routes([web.get('/',index),web.get('/api/setup',snapshot),web.get('/api/state',snapshot),web.post('/api/setup',save),web.post('/api/setup/check',check),web.get('/api/help',help_page),web.get('/{name}',asset)])
    return app
