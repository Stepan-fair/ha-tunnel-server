import json
import sys
import pytest
from server.app.admission import Admission
from server.app.policy import authorize
from server.app.store import Store
from server.app.identity import Authority


@pytest.fixture
def clock():
    class Clock:
        value = 1000.0
        def __call__(self): return self.value
    return Clock()


def activity(admission, owner, operation='NewProxy'):
    return admission.activity(owner['client_id'], owner['generation'], owner['run_id'], owner['epoch'], operation)


def test_clone_does_not_change_healthy_owner_or_extend_lease(clock):
    a = Admission(clock=clock)
    owner = a.login('a', 0, 'untrusted-run', 'owner')
    assert owner['run_id'] != 'untrusted-run'
    assert len(owner['run_id']) == 32
    assert activity(a, owner)
    clock.value += 119
    for i in range(1000):
        assert a.login('a', 0, str(i), 'clone') is None
    assert a.connected('a', 0)
    assert a.counts() == {'owners': 1, 'reservations': 0, 'active': 1}
    clock.value += 1
    assert a.login('a', 0, '', 'clone') is not None
    assert not activity(a, owner, 'Ping')


@pytest.mark.parametrize('nonce', ['modern', None])
def test_same_owner_reconnect_rotates_epoch_but_keeps_canonical_runid(clock, nonce):
    a = Admission(clock=clock)
    old = a.login('a', 0, '', nonce)
    assert activity(a, old)
    new = a.login('a', 0, old['run_id'] if nonce is None else '', nonce)
    assert new['run_id'] == old['run_id']
    assert new['epoch'] != old['epoch']
    assert not activity(a, old, 'Ping')
    assert not a.close_proxy('a', 0, old['run_id'], old['epoch'])
    assert activity(a, new)
    assert a.close_proxy('a', 0, new['run_id'], new['epoch'])
    assert a.connected('a', 0)  # CloseProxy is not logout.


def test_legacy_fresh_process_waits_for_lease(clock):
    a = Admission(clock=clock)
    old = a.login('a', 0, 'client-chosen', None)
    assert activity(a, old)
    clock.value += 119
    assert a.login('a', 0, '', None) is None
    assert a.login('a', 0, 'client-chosen', None) is None
    clock.value += 1
    new = a.login('a', 0, '', None)
    assert new['run_id'] == old['run_id']  # Replace old FRP control, never accumulate.


@pytest.mark.parametrize('operation', ['NewProxy', 'NewWorkConn', 'Ping'])
def test_activity_before_first_30_second_ping_promotes_reservation(clock, operation):
    a = Admission(clock=clock)
    owner = a.login('a', 0, '', 'process')
    assert a.counts()['reservations'] == 1
    clock.value += 14
    assert activity(a, owner, operation)
    clock.value += 30
    assert a.connected('a', 0)
    assert a.login('a', 0, '', 'clone') is None


def test_unconfirmed_login_and_repeated_login_cannot_reserve_forever(clock):
    a = Admission(clock=clock)
    owner = a.login('a', 0, '', 'process')
    clock.value += 14
    assert a.login('a', 0, '', 'process')
    clock.value += 1
    assert a.login('a', 0, '', 'other')
    assert not activity(a, owner)


def test_generation_and_old_callbacks_cannot_renew_or_close_new_owner(clock):
    a = Admission(clock=clock)
    old = a.login('a', 0, '', 'first')
    assert activity(a, old)
    a.remove('a')
    new = a.login('a', 1, '', 'second')
    assert activity(a, new)
    clock.value += 119
    assert not activity(a, old, 'Ping')
    assert not a.activity('a', 0, new['run_id'], new['epoch'], 'Ping')
    assert not a.close_proxy('a', 1, old['run_id'], old['epoch'])
    clock.value += 1
    assert not a.connected('a', 1)


def test_global_budgets_and_expiry_cleanup_without_proxy(clock):
    a = Admission(clock=clock, max_owners=3, max_reservations=2)
    one = a.login('a', 0, '', 'a')
    assert a.login('b', 0, '', 'b')
    assert a.login('c', 0, '', 'c') is None
    assert activity(a, one)
    assert a.login('c', 0, '', 'c')
    assert a.login('d', 0, '', 'd') is None
    clock.value += 15
    assert a.counts() == {'owners': 1, 'reservations': 0, 'active': 1}
    assert a.login('d', 0, '', 'd')
    a.clear()
    assert a.counts()['owners'] == 0


@pytest.fixture
def policy(tmp_path, clock):
    store = Store(tmp_path/'db', 'example.org', clock=lambda: 2000)
    creds = [store.redeem(store.issue(n, 1000).code, 1001) for n in ('alpha', 'bravo')]
    store.admission = Admission(clock=clock)
    authority = Authority(tmp_path/'key', 'http://127.0.0.1:19000')
    def login(client=creds[0], nonce='owner', **kw):
        return authorize('Login', {'user': client.client_id, 'privilege_key': authority.issue(client.client_id),
            'metas': {'ha_tunnel_process': nonce} if nonce else {}, **kw}, store, authority)
    return store, authority, creds, login


def user_info(login):
    value = login['content']
    return {key: value[key] for key in ('user', 'run_id', 'metas')}


def test_policy_clone_rejection_does_not_modify_seen_or_owner(policy, clock):
    store, authority, (a,b), login = policy
    first = login()
    user = user_info(first)
    proxy = {'user': user, 'proxy_type': 'http', 'proxy_name': a.client_id+'.ha', 'custom_domains': [a.domain]}
    assert not authorize('NewProxy', proxy, store, authority)['reject']
    assert first['content']['client_id'] == a.client_id
    assert not getattr(store, 'live_proxies', {})  # Approval is not publication proof.
    seen = store.access_snapshot(a.client_id, 2000)['last_seen']
    store.clock = lambda: 2001
    for i in range(100): assert login(nonce='clone')['reject']
    assert store.access_snapshot(a.client_id, 2001)['last_seen'] == seen
    assert not authorize('Ping', {'user': user, 'privilege_key': authority.issue(a.client_id)}, store, authority)['reject']
    assert not login(b)['reject']


@pytest.mark.parametrize('operation', ['Ping', 'NewWorkConn', 'NewProxy', 'CloseProxy'])
def test_policy_requires_full_matching_session(policy, operation):
    store, authority, (a,b), login = policy
    owner = login()
    user = user_info(owner)
    content = {'user': user, 'privilege_key': authority.issue(a.client_id)}
    if operation == 'NewWorkConn': content['run_id'] = user['run_id']
    if operation in ('NewProxy', 'CloseProxy'):
        content.pop('privilege_key')
        content.update(proxy_type='http', proxy_name=a.client_id+'.ha', custom_domains=[a.domain])
    assert not authorize(operation, content, store, authority)['reject']
    for broken in ({'run_id':'other'}, {'metas':{}}, {'metas':{**user['metas'],'ha_tunnel_generation':'1'}}, {'metas':{**user['metas'],'ha_tunnel_session':'old'}}):
        assert authorize(operation, {**content,'user':{**user,**broken}}, store, authority)['reject']
    if operation == 'NewWorkConn':
        assert authorize(operation, {**content,'run_id':'other'}, store, authority)['reject']


def test_revoke_and_rebind_invalidate_only_target_owner(policy):
    store, authority, (a,b), login = policy
    first, second = login(), login(b)
    store.redeem(store.reissue(a.client_id, 2000).code, 2000, binding=(a.client_id,a.secret))
    assert store.admission.counts()['owners'] == 1
    assert not authorize('Ping', {'user':user_info(second),'privilege_key':authority.issue(b.client_id)},store,authority)['reject']
    assert authorize('Ping', {'user':user_info(first),'privilege_key':authority.issue(a.client_id)},store,authority)['reject']
    store.revoke(b.client_id)
    assert store.admission.counts()['owners'] == 0


async def test_client_launch_nonce_changes_on_actual_process_restart(tmp_path):
    from client.app.runtime import ClientRuntime
    helper=tmp_path/'helper.py'
    helper.write_text('import time; time.sleep(60)')
    runtime=ClientRuntime(sys.executable,tmp_path/'runtime.json',prefix=[str(helper)],verify=False)
    config={'metadatas': {'keep':'value'}}
    try:
        await runtime.start(config)
        first=json.loads(runtime.path.read_text())['metadatas']
        await runtime.restart()
        second=json.loads(runtime.path.read_text())['metadatas']
        assert first['ha_tunnel_process'] != second['ha_tunnel_process']
        assert first['keep'] == second['keep'] == 'value'
        assert config == {'metadatas': {'keep':'value'}}
    finally: await runtime.stop()


async def test_telemetry_discarded_across_same_generation_owner_change(policy, monkeypatch):
    from server.app.telemetry import TelemetryService
    from server.app.relay import ClientRelay
    store, authority, (a,b), login = policy
    def connect():
        owner=login()
        authorize('Ping', {'user':user_info(owner),'privilege_key':authority.issue(a.client_id)},store,authority)
    connect()
    service=TelemetryService(store,ClientRelay(store,store.now),store.now)
    async def success(domain): return 1.0
    monkeypatch.setattr(service,'_probe',success)
    await service.probe_once(a.client_id)
    assert service.snapshot(a.client_id)['ha_available']
    connect()
    assert service.snapshot(a.client_id)['frp_connected']
    assert not service.snapshot(a.client_id)['ha_available']
    async def stale(domain):
        connect()
        return 2.0
    monkeypatch.setattr(service,'_probe',stale)
    await service.probe_once(a.client_id)
    assert not service.snapshot(a.client_id)['ha_available']


async def test_server_child_restart_clears_runtime_only(tmp_path, monkeypatch):
    from server.app.runtime import ServerRuntime
    store=Store(tmp_path/'db','example.org')
    client=store.redeem(store.issue('alpha',store.now()).code,store.now())
    runtime=ServerRuntime(sys.executable,tmp_path/'server.json',store)
    runtime.prefix=['-c','import time; time.sleep(60)']
    runtime.verify=False
    try:
        await runtime.start({})
        owner=store.admission.login(client.client_id,0,'','process')
        assert activity(store.admission,owner)
        before=store.list_clients()
        await runtime.restart()
        assert store.admission.counts()['owners']==0
        assert store.list_clients()==before
        assert not activity(store.admission,owner,'Ping')
    finally: await runtime.stop()


def test_reservation_churn_retains_one_canonical_control_id(clock):
    a=Admission(clock=clock)
    ids=set()
    for i in range(1000):
        ids.add(a.login('a',0,'',str(i))['run_id'])
        clock.value+=15
    assert len(ids)==1
    assert a.counts()['owners']==0


def test_two_phase_rebind_invalidates_owner_after_commit_only(policy):
    from server.app.binding import BindingRepository
    store, authority, (a,b), login=policy
    login(); login(b)
    invite=store.reissue(a.client_id,2000)
    service=BindingRepository(store)
    import secrets
    secret=secrets.token_urlsafe(32)
    operation=secrets.token_hex(16)
    service.prepare(invite.code,operation,secret,2000,expected_client_id=a.client_id,binding_secret=a.secret)
    assert store.admission.counts()['owners']==2
    service.commit(operation,a.client_id,secret,2000)
    assert store.admission.counts()['owners']==1
    # Idempotent commit must not kick out the subsequently connected owner.
    store.admission.login(a.client_id,1,'','new')
    service.commit(operation,a.client_id,secret,2000)
    assert store.admission.counts()['owners']==2

async def test_matching_close_clears_ha_proof_without_logging_out(policy,monkeypatch):
    from server.app.telemetry import TelemetryService
    from server.app.relay import ClientRelay
    store,authority,(a,b),login=policy
    owner=login()
    user=user_info(owner)
    authorize('Ping',{'user':user,'privilege_key':authority.issue(a.client_id)},store,authority)
    service=TelemetryService(store,ClientRelay(store,store.now),store.now)
    async def success(domain): return 1.0
    monkeypatch.setattr(service,'_probe',success)
    await service.probe_once(a.client_id)
    assert service.snapshot(a.client_id)['ha_available']
    authorize('CloseProxy',{'user':user,'proxy_name':a.client_id+'.ha'},store,authority)
    assert service.snapshot(a.client_id)['frp_connected']
    assert not service.snapshot(a.client_id)['ha_available']
    # A fresh real probe may restore proof, including after delayed close notice.
    await service.probe_once(a.client_id)
    assert service.snapshot(a.client_id)['ha_available']
