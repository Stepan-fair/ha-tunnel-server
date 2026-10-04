import base64
import asyncio
import errno
from dataclasses import asdict
from pathlib import Path
import secrets
import time
from urllib.parse import unquote
from aiohttp import web
from shared.http import Limits, safe_errors, ingress_middleware, csrf_for
from shared.protocol import Invitation
from server.app.policy import authorize
from server.app.store import ConflictError
from server.app.duration import parse_duration,deadline_at
from datetime import datetime,timezone,timedelta,date
from zoneinfo import ZoneInfo,ZoneInfoNotFoundError
from server.app.journal import Actor, Journal, current_actor
from shared.presentation import format_metrics
from shared.help import documentation


def basic_credentials(request):
    auth=request.headers.get('Authorization','')
    if not auth.startswith('Basic '): raise web.HTTPUnauthorized()
    try:
        raw=base64.b64decode(auth[6:],validate=True).decode()
        if ':' not in raw: raise ValueError()
        return tuple(map(unquote,raw.split(':',1)))
    except (ValueError,UnicodeError): raise web.HTTPUnauthorized()


def make_public_app(store, authority, options, access=None, telemetry=None):
    limits=Limits()
    authenticated_limits=Limits()
    inflight=0
    peer_inflight={}
    authenticated_inflight=0
    client_inflight={}
    @web.middleware
    async def gate(request, handler):
        nonlocal inflight,authenticated_inflight
        if (request.remote not in options.get('trusted_proxy_ips',[]) or
                request.headers.get('X-Forwarded-Proto')!='https'):
            raise web.HTTPForbidden()
        request['trusted_https']=True
        from ipaddress import ip_address
        try: peer=str(ip_address(request.headers.get('X-Real-IP',request.remote)))
        except ValueError: raise web.HTTPForbidden()
        # Authenticate headers before assigning a resource lane. Real clients
        # use Basic auth; bounded reserved capacity remains available behind
        # CGNAT even if unauthenticated neighbours exhaust their IP budget.
        client=None
        if request.method=='POST' and request.path in ('/v1/token','/v1/client/status'):
            try:
                username,password=basic_credentials(request)
                authenticate=store.authenticate if request.path=='/v1/token' else store.status_authenticate
                client=authenticate(username,password)
            except web.HTTPUnauthorized: pass
        if client is not None:
            if authenticated_inflight>=32 or client_inflight.get(client.client_id,0)>=2:
                raise web.HTTPTooManyRequests()
            authenticated_inflight+=1
            client_inflight[client.client_id]=client_inflight.get(client.client_id,0)+1
        else:
            if not limits.allow(('peer',peer),120): raise web.HTTPTooManyRequests()
            if request.path=='/v1/enroll' and not limits.allow(('enroll',peer),20):
                raise web.HTTPTooManyRequests()
            if inflight>=64 or peer_inflight.get(peer,0)>=8: raise web.HTTPTooManyRequests()
            inflight+=1
            peer_inflight[peer]=peer_inflight.get(peer,0)+1
        try:
            async with asyncio.timeout(15):
                return await handler(request)
        finally:
            if client is not None:
                authenticated_inflight-=1
                client_inflight[client.client_id]-=1
                if not client_inflight[client.client_id]: del client_inflight[client.client_id]
            else:
                inflight-=1
                peer_inflight[peer]-=1
                if not peer_inflight[peer]: del peer_inflight[peer]
    app=web.Application(client_max_size=8192,middlewares=[safe_errors,gate])

    async def enroll(request):
        data=await request.json()
        if not isinstance(data,dict) or 'code' not in data or set(data)-{'code','expected_client_id'}:
            raise ValueError()
        expected=data.get('expected_client_id')
        if 'expected_client_id' in data and (not isinstance(expected,str) or len(expected)!=32): raise ValueError()
        c=await access.redeem(data['code'],expected) if access else store.redeem(data['code'],int(store.now()),expected)
        return web.json_response({**asdict(c),'server_url':options['server_url'],
            'tunnel_host':options['tunnel_host'],'tunnel_port':options['tunnel_port'],
            'ca_pem':options['ca_pem'],'protocol':1})

    async def token(request):
        data=await request.post()
        if data.get('grant_type')!='client_credentials':
            raise web.HTTPBadRequest()
        auth=request.headers.get('Authorization','')
        if auth.startswith('Basic '):
            try:
                raw=base64.b64decode(auth[6:],validate=True).decode()
                username,password=map(unquote,raw.split(':',1))
            except (ValueError, UnicodeError):
                raise web.HTTPUnauthorized()
        else:
            username,password=data.get('client_id',''),data.get('client_secret','')
        c=store.authenticate(username,password)
        if c is None:
            raise web.HTTPUnauthorized()
        if not authenticated_limits.allow(('token',c.client_id),30): raise web.HTTPTooManyRequests()
        generation=store.access_snapshot(c.client_id,store.now())['generation']
        return web.json_response({'access_token':authority.issue(c.client_id,generation=generation),'token_type':'Bearer','expires_in':3600})

    async def client_status(request):
        username,password=basic_credentials(request)
        client=store.status_authenticate(username,password)
        if client is None: raise web.HTTPUnauthorized()
        if not authenticated_limits.allow(('status',client.client_id),60): raise web.HTTPTooManyRequests()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'capabilities'}: raise ValueError()
        store.set_capabilities(client.client_id,data['capabilities'])
        result=store.access_snapshot(client.client_id,store.now())
        if telemetry is not None: result['telemetry']=telemetry.snapshot(client.client_id)
        return web.json_response(result)

    async def health(request):
        return web.json_response({'status':'ok','protocol':1,'capabilities':['access-v1','telemetry-v1']})
    app.add_routes([web.post('/v1/enroll',enroll),web.post('/v1/token',token),web.post('/v1/client/status',client_status),web.get('/health',health)])
    return app


def make_plugin_app(store, authority, bandwidth_limit_mb=10):
    if type(bandwidth_limit_mb) is not int or not 1<=bandwidth_limit_mb<=1000:
        raise ValueError('Bandwidth limit must be 1 to 1000 MB/s')
    @web.middleware
    async def local_only(request, handler):
        if request.remote not in ('127.0.0.1','::1'):
            raise web.HTTPForbidden()
        return await handler(request)
    app=web.Application(client_max_size=16384,middlewares=[safe_errors,local_only])
    async def handler(request):
        body=await request.json()
        if (not isinstance(body,dict) or body.get('version')!='0.1.0' or
                body.get('op')!=request.query.get('op') or request.query.get('version')!='0.1.0'):
            raise ValueError()
        result=authorize(body['op'],body.get('content'),store,authority,bandwidth_limit_mb)
        return web.json_response(result)
    async def discovery(request):
        return web.json_response(authority.discovery())
    async def jwks(request):
        return web.json_response(authority.jwks())
    app.add_routes([web.post('/handler',handler),web.get('/.well-known/openid-configuration',discovery),web.get('/jwks',jwks)])
    return app


def make_ingress_app(store, authority, options, disconnect, backup_export=None, backup_restore=None, access=None, telemetry=None, mqtt=None, setup=None,journal=None,admin_check=None):
    key=secrets.token_bytes(32)
    journal=journal or Journal(store)
    def actor(request): return Actor('web',request.headers['X-Remote-User-Id'])
    @web.middleware
    async def audit_errors(request,handler):
        token=current_actor.set(actor(request))
        try: return await handler(request)
        except Exception:
            if request.method=='POST':
                try: journal.record('operation_failed',store.now(),actor=actor(request),result='error',details={'reason':'invalid_request'})
                except Exception: pass
            raise
        finally: current_actor.reset(token)
    app=web.Application(client_max_size=14*1024*1024,middlewares=[safe_errors,ingress_middleware(options,key,admin_check),audit_errors])
    def filters(request):
        result={}
        for name in ('client_id','action','result','since','until'):
            value=request.query.get(name)
            if value: result[name]=float(value) if name in ('since','until') else value
        try: zone=ZoneInfo(setup.detected.get('timezone','UTC') if setup else 'UTC')
        except (ZoneInfoNotFoundError,ValueError): zone=ZoneInfo('UTC')
        for name in ('since','until'):
            value=request.query.get(name+'_day')
            if value:
                if len(value)!=10: raise ValueError('Invalid calendar date')
                day=date.fromisoformat(value)
                start=datetime(day.year,day.month,day.day,tzinfo=zone)
                result[name]=(start+timedelta(days=1)).timestamp()-0.001 if name=='until' else start.timestamp()
        return result
    async def journal_page(request):
        return web.json_response(journal.page(**filters(request),
            before_id=int(request.query['before_id']) if request.query.get('before_id') else None,
            limit=int(request.query.get('limit','50'))))
    async def journal_meta(request):
        return web.json_response(await asyncio.to_thread(journal.catalog))
    async def journal_export(request):
        selected=filters(request)
        journal.page(**selected,limit=1)  # Reject invalid filters before committing HTTP headers.
        iterator=journal.csv(selected)
        first=next(iterator)  # Validate before preparing a streaming response.
        response=web.StreamResponse(headers={'Content-Type':'text/csv; charset=utf-8',
            'Content-Disposition':'attachment; filename="ha-tunnel-journal.csv"','Cache-Control':'no-store'})
        await response.prepare(request)
        await response.write(('\ufeff'+first).encode())
        for line in iterator: await response.write(line.encode())
        await response.write_eof()
        return response
    async def state(request):
        clients=store.list_clients()
        if telemetry is not None:
            for client in clients: client['telemetry']=telemetry.snapshot(client['client_id'])
        for client in clients:
            client['presentation']=format_metrics(client.get('telemetry'),client,
                setup.detected.get('timezone','UTC') if setup else client.get('timezone','UTC'))
        return web.json_response({'clients':[c for c in clients if not c['revoked']],
            'archived':[c for c in clients if c['revoked']],
            'csrf':csrf_for(key,request.headers['X-Remote-User-Id']), 'server':options['server_url'],
            'timezone':setup.detected.get('timezone','UTC') if setup else 'UTC',
            'mqtt':mqtt.status() if mqtt else {'state':'not_configured'}})
    async def setup_state(request):
        if setup is None: raise web.HTTPServiceUnavailable()
        result=setup.snapshot(); result['csrf']=csrf_for(key,request.headers['X-Remote-User-Id'])
        return web.json_response(result)
    async def setup_save(request):
        if setup is None: raise web.HTTPServiceUnavailable()
        from server.app.setup import SetupConflict,SetupAuditError
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'draft','revision'}: raise ValueError()
        try: return web.json_response(await setup.save(data['draft'],data['revision']))
        except SetupConflict: raise web.HTTPConflict(reason='Настройки изменились. Обновите страницу.')
        except SetupAuditError: return web.json_response({'error':'audit_pending','message':'Настройки сохранены. Запись журнала не завершена; приложение перезапускается для согласования состояния.'},status=503)
    async def setup_check(request):
        if setup is None: raise web.HTTPServiceUnavailable()
        from server.app.setup import SetupConflict
        try: return web.json_response(await setup.check(await request.json()))
        except SetupConflict: raise web.HTTPConflict()
    async def issue(request):
        data=await request.json()
        if not isinstance(data,dict) or set(data)-{'name'}:
            raise ValueError()
        try: invite=store.issue(data.get('name') or None,int(store.now()),actor=actor(request))
        except ConflictError as exc:
            return web.json_response({'error':'revoked_domain','client_id':exc.client_id,'message':'Подключение отозвано. Восстановите его в разделе «Отозванные» или удалите окончательно.'},status=409)
        return web.json_response({'client_id':invite.client_id,'domain':invite.domain,
            'expires':invite.expires,'invitation':Invitation(options['server_url'],invite.code).encode()})
    async def revoke(request):
        if access is not None:
            cid=request.match_info['client_id']; snap=store.access_snapshot(cid,store.now())
            await access.command(cid,'revoke',secrets.token_hex(16),snap['revision'],actor=actor(request))
        else: await disconnect(request.match_info['client_id'])
        return web.json_response({'status':'revoked'})
    async def delete(request):
        if access is None: raise web.HTTPServiceUnavailable()
        data=await request.json(); cid=request.match_info['client_id']
        if not isinstance(data,dict) or set(data)!={'revision','confirm_domain'}: raise ValueError()
        snap=store.access_snapshot(cid,store.now())
        if data['confirm_domain']!=snap['domain']: raise ValueError('Confirm the domain to delete')
        try: result=await access.delete_revoked(cid,data['revision'],actor=actor(request))
        except ConflictError: raise web.HTTPConflict()
        if mqtt: await mqtt.reconcile(force=True)
        return web.json_response(result)
    async def change_access(request):
        if access is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)-{'action','command_id','revision','duration','timezone'} or not {'action','command_id','revision'}<=set(data): raise ValueError()
        try:
            result=await access.command(request.match_info['client_id'],data['action'],data['command_id'],data['revision'],data.get('duration'),data.get('timezone','UTC'),actor=actor(request))
        except ConflictError: raise web.HTTPConflict(reason='Client policy changed or client update required')
        return web.json_response(result)
    async def invitation(request):
        data=await request.json()
        if data!={}: raise ValueError()
        fn=store.reissue if request.match_info['operation']=='reissue' else store.show_code
        invite=fn(request.match_info['client_id'],int(store.now()),actor=actor(request))
        return web.json_response({'client_id':invite.client_id,'domain':invite.domain,'expires':invite.expires,
            'invitation':Invitation(options['server_url'],invite.code).encode()})
    async def preview_duration(request):
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'duration','timezone'}: raise ValueError()
        deadline=deadline_at(datetime.fromtimestamp(store.now(),timezone.utc),parse_duration(data['duration']),data['timezone'])
        return web.json_response({'deadline':deadline.timestamp(),'timezone':data['timezone']})
    async def export(request):
        if backup_export is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'password'}: raise ValueError()
        from server.app.backup import BackupTooLarge
        try: blob=backup_export(data['password'])
        except BackupTooLarge:
            return web.json_response({'error':'backup_too_large','message':'Переносимая копия слишком велика. Сохраните журнал в CSV; для переноса без потери истории используйте полную копию каталога состояния по инструкции. История не удалена.'},status=413)
        except OSError as exc:
            if exc.errno!=errno.ENOSPC: raise
            return web.json_response({'error':'storage_full','message':'Недостаточно места для копии. Освободите место и повторите.'},status=507)
        journal.record('backup_export',store.now(),actor=actor(request))
        return web.Response(body=blob,content_type='application/octet-stream',
                            headers={'Content-Disposition':'attachment; filename="ha-tunnel.hatb"'})
    async def restore(request):
        if backup_restore is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'password','backup'}: raise ValueError()
        blob=base64.b64decode(data['backup'],validate=True)
        operation=journal.request('backup_restore',store.now(),actor=actor(request))
        try: await backup_restore(blob,data['password'])
        except OSError as exc:
            journal.finish(operation,'error',store.now())
            if exc.errno!=errno.ENOSPC: raise
            return web.json_response({'error':'storage_full','message':'Недостаточно места для восстановления. Исходное состояние сохранено; освободите место и повторите.'},status=507)
        except Exception:
            journal.finish(operation,'error',store.now())
            raise
        journal.finish(operation,'success',store.now())
        return web.json_response({'status':'restarting'})
    async def index(request):
        return web.Response(text=(Path(__file__).parent/'templates/index.html').read_text(encoding='utf-8'),content_type='text/html')
    async def help_page(request): return web.json_response({'text':documentation(__file__)})
    async def asset(request):
        name=request.match_info['name']
        if name not in ('app.js','command_id.js','style.css'):
            raise web.HTTPNotFound()
        kind='text/javascript' if name.endswith('.js') else 'text/css'
        return web.Response(body=(Path(__file__).parent/'templates'/name).read_bytes(),content_type=kind)
    app.add_routes([web.get('/',index),web.get('/api/help',help_page),web.get('/api/state',state),web.get('/api/journal',journal_page),web.get('/api/journal/meta',journal_meta),
                    web.get('/api/setup',setup_state),web.post('/api/setup',setup_save),
                    web.post('/api/setup/check',setup_check),
                    web.get('/api/journal/export',journal_export),web.post('/api/clients',issue),
                    web.post('/api/clients/{client_id}/revoke',revoke),
                    web.post('/api/clients/{client_id}/delete',delete),
                    web.post('/api/clients/{client_id}/access',change_access),
                    web.post('/api/clients/{client_id}/invitation/{operation:show|reissue}',invitation),
                    web.post('/api/duration/preview',preview_duration),
                    web.post('/api/backup/export',export),web.post('/api/backup/restore',restore),web.get('/{name}',asset)])
    return app
