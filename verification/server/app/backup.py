"""Encrypted portable state; restore only to an empty server, retaining rollback."""
import base64
import json
import math
import os
from pathlib import Path
import re
import secrets
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from server.app.store import Store
from server.app.store import digest
from server.app.migrations import EXTRA_COLUMNS
from server.app.duration import parse_duration
from server.app.invitations import InvitationVault
from zoneinfo import ZoneInfo
from server.app.identity import Authority
from server.app.pki import ensure_pki
from shared.files import atomic_write
from shared.validation import domain

FILES=('identity.key','pki/ca.key','pki/ca.pem','pki/server.pem')
COLUMNS=('id','domain','code_hash','issued','expires','secret_hash','revoked','last_seen')
HEADER=b'HATB3'
EXPORT_EVENT_LIMIT=100000
EXPORT_RAW_LIMIT=8*1024*1024


class BackupTooLarge(ValueError):
    pass


def key(password,salt):
    if not isinstance(password,str) or not 16<=len(password)<=1024:
        raise ValueError('Backup password must contain 16 to 1024 characters')
    return Scrypt(salt=salt,length=32,n=2**14,r=8,p=1).derive(password.encode())


def export_state(directory,store,password):
    directory=Path(directory)
    with store.connection() as db:
        db.execute('BEGIN')
        rows=[dict(row) for row in db.execute('SELECT * FROM clients')]
        metadata=[dict(row) for row in db.execute('SELECT * FROM server_metadata')]
        commands=[dict(row) for row in db.execute('SELECT * FROM access_commands')]
        if db.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0]>EXPORT_EVENT_LIMIT:
            raise BackupTooLarge('Journal exceeds portable backup limit')
        audit=[dict(row) for row in db.execute('SELECT * FROM audit_events LIMIT ?', (EXPORT_EVENT_LIMIT,))]
    for row in rows:
        if row['code_ciphertext'] is not None:
            row['code_ciphertext']=base64.b64encode(row['code_ciphertext']).decode()
    names=FILES+(('invitations.key',) if (directory/'invitations.key').exists() else ())
    payload={'version':3,'audit':audit,'base_domain':store.base_domain,'clients':rows,'metadata':metadata,'commands':commands,
             'files':{name:base64.b64encode((directory/name).read_bytes()).decode() for name in names}}
    raw=json.dumps(payload,separators=(',',':')).encode()
    if len(raw)>EXPORT_RAW_LIMIT:
        raise BackupTooLarge('State exceeds portable backup limit')
    salt,nonce=secrets.token_bytes(16),secrets.token_bytes(12)
    return HEADER+salt+nonce+AESGCM(key(password,salt)).encrypt(nonce,raw,HEADER)


def validate_row(row,base_domain,version=1):
    columns=set(COLUMNS) | (set(EXTRA_COLUMNS) if version>=2 else set())
    if not isinstance(row,dict) or set(row)!=columns: raise ValueError()
    if not isinstance(row['id'],str) or not re.fullmatch('[a-f0-9]{32}',row['id']): raise ValueError()
    host=domain(row['domain'])
    if host.split('.')[1:]!=base_domain.split('.'): raise ValueError()
    for field in ('code_hash','secret_hash'):
        if row[field] is not None and (not isinstance(row[field],str) or not re.fullmatch('[a-f0-9]{64}',row[field])):
            raise ValueError()
    for field in ('issued','expires','revoked'):
        if type(row[field]) is not int: raise ValueError()
    if row['last_seen'] is not None and type(row['last_seen']) is not int: raise ValueError()
    if row['revoked'] not in (0,1) or row['expires']!=row['issued']+900: raise ValueError()
    if row['revoked'] and row['secret_hash']: raise ValueError()
    if version==1:
        if row['code_hash'] and (row['secret_hash'] or row['revoked']): raise ValueError()
        return
    if type(row['paused']) is not int or row['paused'] not in (0,1): raise ValueError()
    for field in ('revision','generation','to_client_bytes','from_client_bytes'):
        if type(row[field]) is not int or not 0<=row[field]<=2**63-1: raise ValueError()
    for field in ('deadline','traffic_started_at'):
        value=row[field]
        if value is not None and (type(value) not in (int,float) or not math.isfinite(value) or value<0): raise ValueError()
    ZoneInfo(row['timezone'])
    if row['duration'] is not None: parse_duration(json.loads(row['duration']))
    if (row['duration'] is None)!=(row['deadline'] is None): raise ValueError()
    caps=json.loads(row['capabilities'])
    if not isinstance(caps,list) or len(caps)>2 or any(c not in ('access-v1','telemetry-v1') for c in caps): raise ValueError()
    value=row['status_secret_hash']
    if value is not None and (not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value)): raise ValueError()
    if row['code_ciphertext'] is not None:
        row['code_ciphertext']=base64.b64decode(row['code_ciphertext'],validate=True)
        if not row['code_hash'] or not 28<=len(row['code_ciphertext'])<=2048: raise ValueError()


def restore_metadata(db,payload):
    if not isinstance(payload['metadata'],list) or not isinstance(payload['commands'],list): raise ValueError()
    db.execute('DELETE FROM server_metadata')
    names=set()
    for item in payload['metadata']:
        if not isinstance(item,dict) or set(item)!={'name','value'} or item['name'] in names: raise ValueError()
        value=json.loads(item['value'])
        if item['name']=='instance_id':
            if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{32}',value): raise ValueError()
        elif item['name']=='clock_anchor':
            if type(value) not in (int,float) or not math.isfinite(value) or value<0: raise ValueError()
        elif item['name']=='audit_running':
            if type(value) is not bool: raise ValueError()
        elif re.fullmatch(r'audit:(ha_available|frp_connected):[a-f0-9]{32}',item['name']):
            if type(value) is not bool: raise ValueError()
        else: raise ValueError()
        names.add(item['name'])
        db.execute('INSERT INTO server_metadata VALUES (?,?)',(item['name'],item['value']))
    if 'instance_id' not in names: raise ValueError()
    for item in payload['commands']:
        if not isinstance(item,dict) or set(item)!={'client_id','command_id','request','result'}: raise ValueError()
        if not isinstance(item['command_id'],str) or not 1<=len(item['command_id'])<=128: raise ValueError()
        if not db.execute('SELECT 1 FROM clients WHERE id=?',(item['client_id'],)).fetchone(): raise ValueError()
        request,result=json.loads(item['request']),json.loads(item['result'])
        if not isinstance(request,list) or len(request)!=4 or not isinstance(result,dict) or result.get('client_id')!=item['client_id']: raise ValueError()
        db.execute('INSERT INTO access_commands VALUES (?,?,?,?)',tuple(item[name] for name in ('client_id','command_id','request','result')))


def restore_audit(db, rows):
    from server.app.journal import Actor, append_event
    fields={'id','at','action','source','user_id','client_id','domain','result','details','operation_id'}
    if not isinstance(rows,list) or len(rows)>100000: raise ValueError()
    db.execute('DELETE FROM audit_events')
    for row in rows:
        if not isinstance(row,dict) or set(row)!=fields or type(row['id']) is not int or row['id']<1: raise ValueError()
        if row['client_id'] is not None and not re.fullmatch('[a-f0-9]{32}', row['client_id']): raise ValueError()
        if row['domain'] is not None: domain(row['domain'])
        if row['user_id'] is not None and (not isinstance(row['user_id'],str) or len(row['user_id'])>128): raise ValueError()
        if row['operation_id'] is not None and (not isinstance(row['operation_id'],str) or len(row['operation_id'])>256): raise ValueError()
        details=json.loads(row['details'])
        if not isinstance(details,dict): raise ValueError()
        # Reuse production validation/redaction before preserving original event IDs.
        temporary=append_event(db,action=row['action'],actor=Actor(row['source'],row['user_id']),
            client_id=row['client_id'],domain=row['domain'],result=row['result'],at=row['at'],details=details)
        safe=db.execute('SELECT details FROM audit_events WHERE id=?',(temporary,)).fetchone()['details']
        db.execute('DELETE FROM audit_events WHERE id=?',(temporary,))
        db.execute('INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?)',
            tuple(row[name] if name!='details' else safe for name in ('id','at','action','source','user_id','client_id','domain','result','details','operation_id')))


def restore_state(blob,password,directory,base_domain,hostname,reserved=()):
    directory=Path(directory)
    current=Store(directory/'state.db',base_domain)
    previous=directory.with_name(directory.name+'.pre-restore')
    if current.list_clients() or previous.exists():
        raise ValueError('Restore requires an empty server without a previous restore')
    if not isinstance(blob,bytes) or not 49<=len(blob)<=10*1024*1024 or blob[:5] not in (b'HATB1',b'HATB2',HEADER):
        raise ValueError('Invalid backup')
    try:
        raw=AESGCM(key(password,blob[5:21])).decrypt(blob[21:33],blob[33:],blob[:5])
        if len(raw)>8*1024*1024: raise ValueError()
        payload=json.loads(raw)
        version=int(chr(blob[4]))
        fields={'version','base_domain','clients','files'} | ({'metadata','commands'} if version>=2 else set()) | ({'audit'} if version==3 else set())
        if (set(payload)!=fields or payload['version']!=version or
                payload['base_domain']!=base_domain or not set(FILES)<=set(payload['files']) or
                not set(payload['files'])<=set(FILES+(('invitations.key',) if version>=2 else ())) or
                not isinstance(payload['clients'],list)):
            raise ValueError()
        with tempfile.TemporaryDirectory(prefix='.restore-',dir=directory.parent) as temp:
            staged=Path(temp)/'state'
            fresh=Store(staged/'state.db',base_domain,reserved,hostname)
            with fresh.connection() as db:
                for row in payload['clients']:
                    validate_row(row,base_domain,version)
                    if not row['revoked'] and row['domain'].split('.')[0] in fresh.reserved:
                        raise ValueError('Restored client conflicts with server name')
                    columns=COLUMNS+tuple(EXTRA_COLUMNS) if version>=2 else COLUMNS+('status_secret_hash',)
                    values=[row[name] for name in columns] if version>=2 else [row[name] for name in COLUMNS]+[row['secret_hash']]
                    db.execute('INSERT INTO clients ('+','.join(columns)+') VALUES ('+','.join('?' for _ in columns)+')',values)
                if version>=2: restore_metadata(db,payload)
                if version==3: restore_audit(db,payload['audit'])
            for name in payload['files']:
                data=base64.b64decode(payload['files'][name],validate=True)
                if len(data)>16384: raise ValueError()
                if name=='invitations.key' and len(data)!=32: raise ValueError()
                atomic_write(staged/name,data)
            if any(row.get('code_ciphertext') is not None for row in payload['clients']):
                vault=InvitationVault(staged,require_existing=True)
                for row in payload['clients']:
                    if row['code_ciphertext'] is not None and digest(vault.open(row['id'],row['code_ciphertext']))!=row['code_hash']: raise ValueError()
            # An older snapshot cannot know which credentials were revoked later.
            # Restore identities/history, never historical authorization material.
            with fresh.connection() as db:
                db.execute('UPDATE clients SET revoked=1,paused=0,secret_hash=NULL,status_secret_hash=NULL,code_hash=NULL,code_ciphertext=NULL,generation=generation+1,revision=revision+1')
                db.execute('DELETE FROM access_commands')
            (staged/'identity.key').unlink()
            Authority(staged/'identity.key','http://127.0.0.1:19000')
            ensure_pki(staged/'pki',hostname)
            # Final conflict check before moving: keep the previous empty state.
            if current.list_clients(): raise ValueError()
            directory.rename(previous)
            try:
                staged.rename(directory)
            except BaseException:
                previous.rename(directory)
                raise
    except OSError:
        raise
    except Exception:
        raise ValueError('Backup password, contents, domain or destination are invalid') from None
