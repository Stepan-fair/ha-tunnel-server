import pytest
from aiohttp.test_utils import TestClient, TestServer
from server.app.setup import SetupService, make_setup_app


class Supervisor:
    def __init__(self): self.options={}; self.writes=[]
    async def get(self,path):
        if path=='/addons/self/info': return {'options':dict(self.options)}
        if path=='/supervisor/info': return {'timezone':'Europe/Moscow','arch':'amd64'}
        if path=='/addons': return {'addons':[{'slug':'test_nginxproxymanager','name':'Nginx Proxy Manager'}]}
        if path=='/addons/test_nginxproxymanager/info': return {'hostname':'test-nginxproxymanager'}
        raise ValueError(path)
    async def post(self,path,payload):
        assert path=='/addons/self/options'
        self.writes.append(payload); self.options=dict(payload['options']); return {}


def draft():
    return {'base_domain':'example.org','server_url':'https://tunnel.example.org',
            'npm_host':'test-nginxproxymanager','admin_user_ids':['admin'],
            'reserved_names':[],'bandwidth_limit_mb':10}


async def test_blank_options_and_detection(tmp_path):
    service=SetupService(tmp_path,Supervisor())
    await service.detect()
    snap=service.snapshot()
    assert not snap['ready'] and not snap['options'].get('base_domain')
    assert snap['detected']['timezone']=='Europe/Moscow'
    assert snap['detected']['npm_host']=='test-nginxproxymanager'


async def test_npm_discovery_with_default_supervisor_role(tmp_path):
    class RestrictedSupervisor(Supervisor):
        async def get(self,path):
            if path=='/addons': raise ValueError('403: default role cannot list applications')
            if path=='/addons/a0d7b954_nginxproxymanager/info': return {'hostname':'a0d7b954-nginxproxymanager'}
            return await super().get(path)
    service=SetupService(tmp_path,RestrictedSupervisor())
    data=await service.detect()
    assert data['detected']['npm_host']=='a0d7b954-nginxproxymanager'
    assert data['detected']['timezone']=='Europe/Moscow'


async def test_blank_options_only_starts_setup_listener(tmp_path,monkeypatch):
    from server.app import main
    service=SetupService(tmp_path,Supervisor()); await service.detect()
    listeners=[]
    class Runner:
        async def cleanup(self): pass
    async def listen(app,host,port): listeners.append((app,host,port)); return Runner()
    async def shutdown(): return None
    monkeypatch.setattr(main,'listen',listen)
    monkeypatch.setattr(main,'shutdown_event',shutdown)
    monkeypatch.setattr(main,'HEALTH_PATH',tmp_path/'health')
    assert await main.run_setup(service) is False
    assert [port for app,host,port in listeners]==[8099]
    assert all('/v1/enroll' not in str(route.resource) for route in listeners[0][0].router.routes())


async def test_stale_save_never_overwrites_supervisor(tmp_path):
    supervisor=Supervisor(); service=SetupService(tmp_path,supervisor)
    await service.detect(); rev=service.snapshot()['revision']
    supervisor.options={'base_domain':'changed.org'}
    with pytest.raises(Exception,match='stale'): await service.save(draft(),rev)
    assert supervisor.writes==[]


async def test_save_and_existing_domain_guard(tmp_path):
    supervisor=Supervisor(); service=SetupService(tmp_path,supervisor)
    await service.detect()
    result=await service.save(draft(),service.snapshot()['revision'])
    assert result['ready'] and supervisor.options==draft()
    service.has_clients=lambda:True
    changed={**draft(),'base_domain':'other.org','server_url':'https://tunnel.other.org'}
    with pytest.raises(ValueError,match='clients'): await service.save(changed,result['revision'])
    assert supervisor.options==draft()


async def test_setup_logs_external_save_and_preserves_existing_domain(tmp_path):
    from server.app.store import Store
    from server.app.journal import Journal
    supervisor=Supervisor(); supervisor.options=draft()
    store=Store(tmp_path/'state'/'state.db','example.org'); store.issue('alpha',2000)
    service=SetupService(tmp_path,supervisor); await service.detect()
    changed={**draft(),'base_domain':'other.org','server_url':'https://tunnel.other.org'}
    with pytest.raises(ValueError,match='clients'): await service.save(changed,service.snapshot()['revision'])
    await service.save(draft(),service.snapshot()['revision'])
    events=Journal(store).page()['items']
    assert [(e['action'],e['result']) for e in events[:2]]==[('settings','success'),('settings','requested')]


@pytest.mark.parametrize('change',[
    {'server_url':'https://nested.tunnel.example.org'},
    {'server_url':'https://gateway.example.org'},
    {'server_url':'https://alpha.example.org'},
    {'reserved_names':['alpha']},
])
async def test_invalid_or_identity_breaking_setup_never_saved(tmp_path,change):
    from server.app.store import Store
    supervisor=Supervisor(); supervisor.options=draft()
    store=Store(tmp_path/'state/state.db','example.org'); store.issue('alpha',2000)
    service=SetupService(tmp_path,supervisor); await service.detect()
    with pytest.raises(ValueError): await service.save({**draft(),**change},service.snapshot()['revision'])
    assert supervisor.writes==[] and supervisor.options==draft()


async def test_confirmed_save_still_reloads_after_final_audit_failure(tmp_path):
    from server.app.store import Store
    from server.app.journal import Journal
    supervisor=Supervisor(); supervisor.options=draft()
    store=Store(tmp_path/'state/state.db','example.org')
    service=SetupService(tmp_path,supervisor); await service.detect(); service.journal=Journal(store)
    with store.connection() as db:
        db.execute("CREATE TRIGGER fail_result BEFORE INSERT ON audit_events WHEN NEW.action='settings' AND NEW.result='success' BEGIN SELECT RAISE(ABORT,'audit failed'); END")
    reloaded=[]; service.on_saved=lambda:reloaded.append(True)
    with pytest.raises(Exception): await service.save({**draft(),'bandwidth_limit_mb':20},service.snapshot()['revision'])
    assert supervisor.options['bandwidth_limit_mb']==20 and reloaded==[True]
    rows=service.journal.page(action='settings')['items']
    assert len(rows)==1 and rows[0]['result']=='requested' and rows[0]['operation_id']


async def test_setup_auth_csrf_and_closed_admin_failure(tmp_path):
    service=SetupService(tmp_path,Supervisor()); await service.detect()
    async def admin(uid): return uid=='admin'
    async with TestClient(TestServer(make_setup_app(service,admin,ingress_ips=['127.0.0.1']))) as client:
        assert (await client.get('/api/setup')).status==403
        assert (await client.get('/api/setup',headers={'X-Remote-User-Id':'forged'})).status==403
        headers={'X-Remote-User-Id':'admin'}
        state=await(await client.get('/api/setup',headers=headers)).json()
        assert (await client.post('/api/setup',headers=headers,json={'draft':draft(),'revision':state['revision']})).status==403
        headers['X-CSRF-Token']=state['csrf']
        assert (await client.post('/api/setup',headers=headers,json={'draft':draft(),'revision':state['revision']})).status==200
    async def broken(uid): raise RuntimeError('private')
    async with TestClient(TestServer(make_setup_app(service,broken,ingress_ips=['127.0.0.1']))) as client:
        assert (await client.get('/api/setup',headers={'X-Remote-User-Id':'admin'})).status==403
    async with TestClient(TestServer(make_setup_app(service,admin))) as client:
        assert (await client.get('/api/setup',headers={'X-Remote-User-Id':'admin'})).status==403
