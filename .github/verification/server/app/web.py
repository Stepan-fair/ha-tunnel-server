import base64
import asyncio
import errno
from dataclasses import asdict
from pathlib import Path
import secrets
import time
from urllib.parse import unquote
from aiohttp import web
from shared.http import Limits, safe_errors, ingress_middleware, csrf_for, TRUSTED_HTTPS
from shared.protocol import Invitation
from server.app.policy import authorize
from server.app.store import ConflictError, BoundDomainError
from server.app.duration import parse_duration,deadline_at
from datetime import datetime,timezone,timedelta,date
from zoneinfo import ZoneInfo,ZoneInfoNotFoundError
from server.app.journal import Actor, Journal, current_actor
from shared.presentation import format_metrics,format_billing
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
    from server.app.binding import BindingRepository
    binding_repository=BindingRepository(store)
    limits=Limits()
    authenticated_limits=Limits()
    inflight=0
    peer_inflight={}
    authenticated_inflight=0
    client_inflight={}
    @web.middleware
    async def gate(request, handler):
        nonlocal inflight,authenticated_inflight
        dependency=options.get('npm_runtime')
        addresses=dependency.addresses if dependency is not None else options.get('trusted_proxy_ips',[])
        if dependency is not None and request.remote not in addresses: raise web.HTTPServiceUnavailable()
        if (request.remote not in addresses or
                request.headers.get('X-Forwarded-Proto')!='https'):
            raise web.HTTPForbidden()
        request[TRUSTED_HTTPS]=True
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
            if (request.path=='/v1/enroll' or request.path.startswith('/v2/enroll/')) and not limits.allow(('enroll',peer),20):
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
        binding=None
        if request.headers.get('Authorization'):
            try: binding=basic_credentials(request)
            except web.HTTPUnauthorized: pass
        try:
            c=await access.redeem(data['code'],expected,binding=binding) if access else store.redeem(data['code'],int(store.now()),expected,binding=binding)
        except BoundDomainError as error:
            return web.json_response({'error':error.reason},status=409)
        except ConflictError:
            return web.json_response({'error':'binding_conflict'},status=409)
        return web.json_response({**asdict(c),'server_url':options['server_url'],
            'tunnel_host':options['tunnel_host'],'tunnel_port':options['tunnel_port'],
            'ca_pem':options['ca_pem'],'protocol':1})

    async def binding_operation(request):
        data=await request.json()
        if not isinstance(data,dict): raise ValueError()
        action=request.match_info['action']
        try:
            if action=='prepare':
                if set(data)-{'code','operation_id','secret','expected_client_id'}: raise ValueError()
                expected=data.get('expected_client_id')
                proof=None
                if request.headers.get('Authorization'):
                    username,proof=basic_credentials(request)
                    if username!=expected: raise web.HTTPUnauthorized()
                result=binding_repository.prepare(data['code'],data['operation_id'],data['secret'],store.now(),expected_client_id=expected,binding_secret=proof)
                if result['state']=='prepared':
                    result['credentials']={name:options[name] for name in ('server_url','tunnel_host','tunnel_port','ca_pem')}
                    result['credentials'].update(protocol=1,client_id=result['client_id'],domain=result['domain'],secret=data['secret'])
            elif action in ('commit','status','cancel'):
                if set(data)!={'operation_id'}: raise ValueError()
                username,secret=basic_credentials(request)
                changing=action=='commit' and binding_repository.status(data['operation_id'],username,secret,store.now())['state']=='prepared'
                result=getattr(binding_repository,action)(data['operation_id'],username,secret,store.now())
                if changing and access:
                    await access.relay.disconnect(username)
            else: raise web.HTTPNotFound()
        except BoundDomainError as error:
            return web.json_response({'error':error.reason},status=409)
        except ConflictError:
            return web.json_response({'error':'binding_conflict'},status=409)
        return web.json_response(result)

    async def token(request):
        # OAuth client credentials uses URL-encoded forms, never file uploads.
        # Reject multipart before Request.post can allocate temporary files.
        if request.content_type!='application/x-www-form-urlencoded':
            raise web.HTTPUnsupportedMediaType()
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
        result['server_instance_id']=store.get_metadata('instance_id')
        result['billing']['updated_at']=store.now()
        # Local, bounded monotonic contact evidence; it is not a financial or
        # telemetry wire field and does not claim that remote HA is reachable.
        from shared.notifications import record_server_contact
        record_server_contact(store,client.client_id)
        if telemetry is not None: result['telemetry']=telemetry.snapshot(client.client_id)
        return web.json_response(result)

    async def health(request):
        return web.json_response({'status':'ok','protocol':1,'capabilities':['access-v1','telemetry-v1','enrollment-v2']})
    app.add_routes([web.post('/v2/enroll/{action}',binding_operation),web.post('/v1/enroll',enroll),web.post('/v1/token',token),web.post('/v1/client/status',client_status),web.get('/health',health)])
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
        # Only these accepted operations prove activity of the matched owner.
        # CloseProxy can intentionally ignore stale callbacks; it is no contact.
        if not result.get('reject',True) and body['op'] in ('Login','Ping','NewWorkConn','NewProxy'):
            from shared.notifications import record_server_contact
            content=body['content']
            cid=content['user'] if body['op']=='Login' else content['user']['user']
            record_server_contact(store,cid)
        return web.json_response(result)
    async def discovery(request):
        return web.json_response(authority.discovery())
    async def jwks(request):
        return web.json_response(authority.jwks())
    app.add_routes([web.post('/handler',handler),web.get('/.well-known/openid-configuration',discovery),web.get('/jwks',jwks)])
    return app


def make_ingress_app(store, authority, options, disconnect, backup_export=None, backup_restore=None, access=None, telemetry=None, mqtt=None, setup=None,journal=None,admin_check=None,diagnostics=None,migration=None,notifications=None):
    key=secrets.token_bytes(32)
    journal=journal or Journal(store)
    if setup is not None:
        setup.administration=store.administration
        if admin_check is not None: setup.admin_validator=admin_check
    def actor(request): return Actor('web',request.headers['X-Remote-User-Id'])
    @web.middleware
    async def audit_errors(request,handler):
        token=current_actor.set(actor(request))
        try:
            if request.method=='POST': store.administration.ensure_mutation_allowed()
            return await handler(request)
        except ConflictError as exc:
            return web.json_response({'error':'conflict','message':str(exc)},status=409)
        except Exception:
            if request.method=='POST':
                try: journal.record('operation_failed',store.now(),actor=actor(request),result='error',details={'reason':'invalid_request'})
                except Exception: pass
            raise
        finally: current_actor.reset(token)
    app=web.Application(client_max_size=14*1024*1024,middlewares=[safe_errors,ingress_middleware(options,key,admin_check),audit_errors])
    from shared.notifications import add_notification_routes
    add_notification_routes(app,notifications,key,administration=store.administration,ensure_allowed=store.ensure_mutation_allowed)
    from server.app.diagnostics_web import add_diagnostics_routes
    add_diagnostics_routes(app,diagnostics)
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
            client['billing']['updated_at']=store.now()
            client['billing_presentation']=format_billing(client['billing'])
            client['presentation']=format_metrics(client.get('telemetry'),client,
                setup.detected.get('timezone','UTC') if setup else client.get('timezone','UTC'))
        return web.json_response({'clients':[c for c in clients if not c['revoked']],
            'archived':[c for c in clients if c['revoked']],
            'csrf':csrf_for(key,request.headers['X-Remote-User-Id']), 'server':options['server_url'],
            'timezone':setup.detected.get('timezone','UTC') if setup else 'UTC',
            'mqtt':mqtt.status() if mqtt else {'state':'not_configured'},
            'dependency':options['npm_runtime'].status() if options.get('npm_runtime') else None})
    from server.app.clock_repair import ClockRepair
    clock_repair=ClockRepair(store,store.clock) if hasattr(store.clock,'confirmed_snapshot') else None

    async def clock_preview(request):
        if clock_repair is None: raise web.HTTPServiceUnavailable()
        return web.json_response(clock_repair.preview())

    async def clock_apply(request):
        if clock_repair is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'command_id','revision','confirmed_snapshot'}: raise ValueError()
        try: result=await clock_repair.repair(data['command_id'],data['revision'],data['confirmed_snapshot'],actor=actor(request))
        except ConflictError: raise web.HTTPConflict()
        return web.json_response(result)

    async def period_preview(request):
        if clock_repair is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'revision','paid_from','paid_until','timezone','reason','operation_ids'}: raise ValueError()
        try:
            result=clock_repair.preview_period(request.match_info['client_id'],data['revision'],
                data['paid_from'],data['paid_until'],data['timezone'],data['reason'],data['operation_ids'])
        except ConflictError: raise web.HTTPConflict()
        return web.json_response(result)

    async def period_reconcile(request):
        if clock_repair is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'command_id','revision','paid_from','paid_until','timezone','reason','operation_ids'}: raise ValueError()
        try:
            result=await clock_repair.reconcile_period(request.match_info['client_id'],data['command_id'],data['revision'],
                data['paid_from'],data['paid_until'],data['timezone'],data['reason'],data['operation_ids'],actor=actor(request))
        except ConflictError: raise web.HTTPConflict()
        return web.json_response(result)

    async def migration_preview(request):
        if migration is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'draft'}: raise ValueError()
        try:return web.json_response(await migration.preview(data['draft']))
        except ConflictError:raise web.HTTPConflict()

    async def migration_apply(request):
        if migration is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'draft','command_id','revision'}: raise ValueError()
        try:return web.json_response(await migration.apply(data['draft'],data['command_id'],data['revision'],actor=actor(request)))
        except ConflictError:raise web.HTTPConflict(reason='Обновите предпросмотр и проверьте DNS/TLS.')

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
            if exc.client_id is None: raise
            return web.json_response({'error':'revoked_domain','client_id':exc.client_id,'message':'Подключение отозвано. Восстановите его в разделе «Отозванные» или удалите окончательно.'},status=409)
        return web.json_response({'client_id':invite.client_id,'domain':invite.domain,
            'expires':invite.expires,'invitation':Invitation(options['server_url'],invite.code).encode()})
    async def revoke(request):
        if access is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'revision','command_id'}: raise ValueError()
        await access.command(request.match_info['client_id'],'revoke',data['command_id'],data['revision'],actor=actor(request))
        return web.json_response({'status':'revoked'})
    async def delete(request):
        if access is None: raise web.HTTPServiceUnavailable()
        data=await request.json(); cid=request.match_info['client_id']
        if not isinstance(data,dict) or set(data)!={'revision','confirm_domain'}: raise ValueError()
        snap=store.access_snapshot(cid,store.now())
        if data['confirm_domain']!=snap['domain']: raise ValueError('Confirm the domain to delete')
        try: result=await access.delete_revoked(cid,data['revision'],actor=actor(request))
        except ConflictError as exc:
            return web.json_response({'error':'delete_blocked','message':str(exc)},status=409)
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
    async def change_billing(request):
        if access is None: raise web.HTTPServiceUnavailable()
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'action','command_id','revision','value_kopecks'}: raise ValueError()
        zone=setup.detected.get('timezone','UTC') if setup else 'UTC'
        try:
            result=await access.billing_command(request.match_info['client_id'],data['action'],data['command_id'],
                data['revision'],value_kopecks=data['value_kopecks'],timezone=zone,actor=actor(request))
        except ConflictError: raise web.HTTPConflict()
        return web.json_response(result)

    async def invitation(request):
        data=await request.json()
        operation=request.match_info['operation']
        if operation=='show':
            if data!={}: raise ValueError()
            invite=store.show_code(request.match_info['client_id'],int(store.now()),actor=actor(request))
        else:
            required={'revision','command_id'} | ({'confirm_domain'} if operation=='transfer' else set())
            if not isinstance(data,dict) or not required<=set(data) or set(data)-required-{'replace_pending'}: raise ValueError()
            if type(data['revision']) is not int or not isinstance(data['command_id'],str) or not data['command_id']: raise ValueError()
            invite=store.reissue(request.match_info['client_id'],int(store.now()),actor=actor(request),
                transfer=operation=='transfer',expected_revision=data['revision'],command_id=data['command_id'],
                confirm_domain=data.get('confirm_domain'),replace_pending=data.get('replace_pending',False))
        return web.json_response({'client_id':invite.client_id,'domain':invite.domain,'expires':invite.expires,
            'invitation':Invitation(options['server_url'],invite.code).encode(),'purpose':invite.purpose})
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
    def restore_configuration():
        return setup.options if setup is not None else options

    async def preview_backup(request):
        from server.app.backup import backup_preview,restore_revision,require_empty_destination
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'password','backup'}: raise ValueError()
        require_empty_destination(store)
        result=backup_preview(base64.b64decode(data['backup'],validate=True),data['password'])
        result['revision']=restore_revision(store,restore_configuration())
        return web.json_response(result)

    async def restore(request):
        if backup_restore is None: raise web.HTTPServiceUnavailable()
        from server.app.backup import validate_restore_confirmation
        data=await request.json()
        if not isinstance(data,dict) or set(data)!={'password','backup','digest','revision','confirm_unknown_date'}: raise ValueError()
        blob=base64.b64decode(data['backup'],validate=True)
        async with store.administration.exclusive('restore'):
            validate_restore_confirmation(store,blob,data['password'],data['digest'],data['revision'],
                confirm_unknown_date=data['confirm_unknown_date'],configuration=restore_configuration())
            operation=journal.request('backup_restore',store.now(),actor=actor(request))
            try:
                await backup_restore(blob,data['password'],expected_revision=data['revision'])
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
        if name not in ('app.js','clock_repair.js','command_id.js','dependency_status.js','notification_settings.js','style.css'):
            raise web.HTTPNotFound()
        kind='text/javascript' if name.endswith('.js') else 'text/css'
        from shared.notifications import notification_asset
        body=notification_asset() if name=='notification_settings.js' else (Path(__file__).parent/'templates'/name).read_bytes()
        return web.Response(body=body,content_type=kind)
    app.add_routes([web.get('/',index),web.get('/api/help',help_page),web.get('/api/state',state),web.get('/api/journal',journal_page),web.get('/api/journal/meta',journal_meta),
                    web.get('/api/clock/preview',clock_preview),web.post('/api/clock/repair',clock_apply),
                    web.post('/api/clients/{client_id}/period-preview',period_preview),
                    web.post('/api/clients/{client_id}/period-reconciliation',period_reconcile),web.get('/api/setup',setup_state),web.post('/api/setup',setup_save),
                    web.post('/api/setup/check',setup_check),
                    web.post('/api/domain-migration/preview',migration_preview),web.post('/api/domain-migration/apply',migration_apply),
                    web.get('/api/journal/export',journal_export),web.post('/api/clients',issue),
                    web.post('/api/clients/{client_id}/revoke',revoke),
                    web.post('/api/clients/{client_id}/delete',delete),
                    web.post('/api/clients/{client_id}/access',change_access),
                    web.post('/api/clients/{client_id}/billing',change_billing),
                    web.post('/api/clients/{client_id}/invitation/{operation:show|reissue|transfer}',invitation),
                    web.post('/api/duration/preview',preview_duration),
                    web.post('/api/backup/preview',preview_backup),web.post('/api/backup/export',export),web.post('/api/backup/restore',restore),web.get('/{name}',asset)])
    return app
