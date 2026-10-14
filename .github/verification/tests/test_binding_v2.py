"""Loss-safe enrollment using real SQLite transactions and HTTP boundaries."""
import importlib.util
import secrets

import pytest
from aiohttp import encode_basic_auth
from aiohttp.test_utils import TestClient, TestServer
from server.app.store import Store, ConflictError
from server.app.identity import Authority
from server.app.web import make_public_app


def repository(store):
    assert importlib.util.find_spec('server.app.binding'), 'Server lacks staged binding transactions'
    from server.app.binding import BindingRepository
    return BindingRepository(store)


@pytest.fixture
def binding(tmp_path):
    store=Store(tmp_path/'state.db','example.org',clock=lambda:1002)
    old=store.redeem(store.issue('alpha',1000).code,1000)
    code=store.reissue(old.client_id,1001).code
    return store,old,code,secrets.token_hex(16),secrets.token_urlsafe(32)


def prepare(binding):
    store,old,code,operation,secret=binding
    return repository(store).prepare(code,operation,secret,1002,
        expected_client_id=old.client_id,binding_secret=old.secret)


def test_prepare_keeps_old_authority_and_replay_rotates_only_once(binding):
    store,old,code,operation,secret=binding
    before=store.access_snapshot(old.client_id,1002)
    candidate=prepare(binding)
    assert store.authenticate(old.client_id,old.secret)
    assert store.status_authenticate(old.client_id,secret) is None
    assert store.show_code(old.client_id,1002).code==code
    assert prepare(binding)==candidate
    repo=repository(Store(store.path,'example.org',clock=lambda:1002))
    result=repo.commit(operation,old.client_id,secret,1003)
    assert result['state']=='committed'
    assert store.authenticate(old.client_id,old.secret) is None
    assert store.authenticate(old.client_id,secret)
    assert repo.commit(operation,old.client_id,secret,1004)==result
    assert store.access_snapshot(old.client_id,1004)['generation']==before['generation']+1
    assert repo.status(operation,old.client_id,secret,1004)==result


def test_v1_cannot_consume_a_reserved_invitation(binding):
    store,old,code,operation,secret=binding
    prepare(binding)
    with pytest.raises(ConflictError):
        store.redeem(code,1003,binding=(old.client_id,old.secret))
    assert store.authenticate(old.client_id,old.secret)
    repository(store).cancel(operation,old.client_id,secret,1003)
    assert store.redeem(code,1004,binding=(old.client_id,old.secret))


@pytest.mark.parametrize('change',['revoke','reissue','policy'])
def test_changed_invitation_or_authority_invalidates_pending(binding,change):
    store,old,code,operation,secret=binding
    prepare(binding)
    if change=='revoke': store.revoke(old.client_id)
    elif change=='reissue': store.reissue(old.client_id,1003)
    else: store.apply_access(old.client_id,'pause','pause-1',store.access_snapshot(old.client_id,1003)['revision'],1003)
    with pytest.raises(ConflictError): repository(store).commit(operation,old.client_id,secret,1004)
    assert store.status_authenticate(old.client_id,secret) is None


def test_revoke_after_commit_is_not_undone_by_replay(binding):
    store,old,code,operation,secret=binding
    prepare(binding)
    repo=repository(store)
    repo.commit(operation,old.client_id,secret,1003)
    store.revoke(old.client_id)
    result=repo.commit(operation,old.client_id,secret,1004)
    assert result['state']=='committed' and result['current_state']=='revoked'
    assert store.authenticate(old.client_id,secret) is None


def test_reservation_expires_without_rotating_and_wrong_proof_never_reveals_result(binding):
    store,old,code,operation,secret=binding
    prepare(binding)
    repo=repository(store)
    with pytest.raises(ValueError): repo.status(operation,old.client_id,'x'*43,1003)
    with pytest.raises(ConflictError): repo.prepare(code,secrets.token_hex(16),'x'*43,1003,expected_client_id=old.client_id,binding_secret=old.secret)
    assert repo.status(operation,old.client_id,secret,1901)['state']=='expired'
    with pytest.raises(ConflictError): repo.commit(operation,old.client_id,secret,1901)
    assert store.authenticate(old.client_id,old.secret)


async def test_v2_routes_keep_https_gate_and_bounded_request(binding,tmp_path):
    store,old,code,operation,secret=binding
    options={'server_url':'https://tunnel.example.org','tunnel_host':'tunnel.example.org',
        'tunnel_port':7000,'ca_pem':'PUBLIC CA','trusted_proxy_ips':['127.0.0.1']}
    authority=Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    async with TestClient(TestServer(make_public_app(store,authority,options))) as client:
        payload={'code':code,'operation_id':operation,'secret':secret,'expected_client_id':old.client_id}
        headers={'X-Forwarded-Proto':'https','Authorization':encode_basic_auth(old.client_id,old.secret)}
        assert (await client.post('/v2/enroll/prepare',json=payload)).status==403
        response=await client.post('/v2/enroll/prepare',json=payload,headers=headers)
        assert response.status==200
        result=await response.json()
        assert result['credentials']['secret']==secret
        assert result['server_instance_id']==store.get_metadata('instance_id')
        assert (await client.post('/v1/enroll',json={'code':code},headers=headers)).status==409
        assert (await client.post('/v2/enroll/prepare',json={**payload,'extra':'x'*8192},headers=headers)).status==413
        headers['Authorization']=encode_basic_auth(old.client_id,secret)
        response=await client.post('/v2/enroll/commit',json={'operation_id':operation},headers=headers)
        assert response.status==200 and (await response.json())['state']=='committed'

def test_reusing_existing_secret_is_rejected_before_reservation(binding):
    store,old,code,operation,secret=binding
    with pytest.raises(ValueError): repository(store).prepare(code,operation,old.secret,1002,expected_client_id=old.client_id,binding_secret=old.secret)
    assert store.authenticate(old.client_id,old.secret)


async def test_commit_replay_does_not_disconnect_current_session(binding,tmp_path):
    store,old,code,operation,secret=binding
    prepare(binding)
    options={'server_url':'https://tunnel.example.org','tunnel_host':'tunnel.example.org','tunnel_port':7000,'ca_pem':'CA','trusted_proxy_ips':['127.0.0.1']}
    class Relay:
        disconnected=[]
        async def disconnect(self,client_id): self.disconnected.append(client_id)
    class Access: relay=Relay()
    async with TestClient(TestServer(make_public_app(store,Authority(tmp_path/'key','http://127.0.0.1:19000'),options,access=Access()))) as client:
        headers={'X-Forwarded-Proto':'https','Authorization':encode_basic_auth(old.client_id,secret)}
        for _ in range(2): assert (await client.post('/v2/enroll/commit',headers=headers,json={'operation_id':operation})).status==200
        assert Access.relay.disconnected==[old.client_id]


def test_operation_capacity_is_bounded_and_expired_records_are_reclaimed(binding,monkeypatch):
    import server.app.binding as module
    store,old,code,operation,secret=binding
    monkeypatch.setattr(module,'MAX_RECORDS',2)
    repo=repository(store)
    for name in ('bravo','charlie'):
        invite=store.issue(name,1000)
        repo.prepare(invite.code,secrets.token_hex(16),secrets.token_urlsafe(32),1002)
    with pytest.raises(ConflictError): prepare(binding)
    later=store.reissue(old.client_id,90000)
    result=repo.prepare(later.code,operation,secret,90000,expected_client_id=old.client_id,binding_secret=old.secret)
    assert result['state']=='prepared'
    with store.connection() as db: assert db.execute('SELECT count(*) FROM binding_operations').fetchone()[0]==1


def test_prepare_operation_cannot_be_reused_with_different_proof(binding):
    store,old,code,operation,secret=binding
    prepare(binding)
    with pytest.raises(ConflictError): repository(store).prepare(code,operation,secret,1002,expected_client_id=old.client_id,binding_secret='z'*43)
    assert store.authenticate(old.client_id,old.secret)

def test_initial_paid_v2_enrollment_buys_exactly_one_period(tmp_path):
    from server.app.billing import BillingRepository
    from tests.test_billing_store import command,operations
    from tests.test_subscription_calendar import stamp
    now=stamp(2026,10,15,10)
    store=Store(tmp_path/'state.db','example.org',clock=lambda:now)
    invitation=store.issue('alpha',int(now))
    billing=BillingRepository(store)
    command(billing,invitation.client_id,'set_price',30000,now)
    command(billing,invitation.client_id,'topup',90000,now)
    assert not operations(store,'purchase')
    operation,secret=secrets.token_hex(16),secrets.token_urlsafe(32)
    repo=repository(store); repo.prepare(invitation.code,operation,secret,now)
    assert not operations(store,'purchase')
    repo.commit(operation,invitation.client_id,secret,now)
    repo.commit(operation,invitation.client_id,secret,now+1)
    snap=store.access_snapshot(invitation.client_id,now)
    assert snap['billing']['balance_kopecks']==60000
    assert snap['billing']['paid_until']==stamp(2026,11,15)
    assert len(operations(store,'purchase'))==1


@pytest.mark.parametrize('transfer',[False,True])
def test_v2_rebinding_preserves_finances_pause_and_history(tmp_path,transfer):
    from tests.test_billing_store import funded,operations
    store,old,billing,now,snap=funded(tmp_path)
    store.apply_access(old.client_id,'pause','pause',snap['revision'],now[0])
    before=store.access_snapshot(old.client_id,now[0])
    ledger=operations(store)
    code=store.reissue(old.client_id,int(now[0]),transfer=transfer,expected_revision=before['revision'],confirm_domain=old.domain).code
    operation,secret=secrets.token_hex(16),secrets.token_urlsafe(32)
    repo=repository(store)
    repo.prepare(code,operation,secret,now[0],**({} if transfer else {'expected_client_id':old.client_id,'binding_secret':old.secret}))
    repo.commit(operation,old.client_id,secret,now[0])
    repo.commit(operation,old.client_id,secret,now[0]+1)
    after=store.access_snapshot(old.client_id,now[0])
    assert after['billing']==before['billing'] and after['paused']==before['paused']
    assert after['client_id']==old.client_id and after['domain']==old.domain
    assert operations(store)==ledger


def test_portable_restore_excludes_pending_and_cannot_replay_commit(binding,tmp_path):
    from server.app.backup import export_state,restore_state
    from server.app.pki import ensure_pki
    store,old,code,operation,secret=binding
    Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    ensure_pki(tmp_path/'pki','tunnel.example.org')
    prepare(binding)
    blob=export_state(tmp_path,store,'a strong test password')
    target=tmp_path/'restored'
    restore_state(blob,'a strong test password',target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org')
    with pytest.raises(ValueError): repository(restored).commit(operation,old.client_id,secret,1003)
    assert restored.authenticate(old.client_id,secret) is None

def test_concurrent_commit_rotates_only_once(binding):
    from concurrent.futures import ThreadPoolExecutor
    store,old,code,operation,secret=binding
    prepare(binding)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:repository(store).commit(operation,old.client_id,secret,1003),range(2)))
    assert results[0]==results[1]
    assert store.access_snapshot(old.client_id,1003)['generation']==1
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM audit_events WHERE client_id=? AND action='redeem'",(old.client_id,)).fetchone()[0]==2

from tests.test_access_relay import network


@pytest.mark.parametrize('transfer',[False,True])
async def test_v2_commit_closes_only_previous_binding_streams_and_replay_keeps_new_stream(network,tmp_path,transfer):
    import asyncio
    from tests.test_access_relay import connect
    store,clients,relay,access=network
    old,other=clients
    old_reader,old_writer,_=await connect(relay,old.domain)
    other_reader,other_writer,_=await connect(relay,other.domain)
    now=int(store.now())
    invitation=store.reissue(old.client_id,now,transfer=transfer,expected_revision=0,confirm_domain=old.domain)
    operation,secret=secrets.token_hex(16),secrets.token_urlsafe(32)
    repository(store).prepare(invitation.code,operation,secret,now,**({} if transfer else {'expected_client_id':old.client_id,'binding_secret':old.secret}))
    old_writer.write(b'old'); await old_writer.drain()
    assert await asyncio.wait_for(old_reader.readexactly(3),1)==b'old'
    options={'trusted_proxy_ips':['127.0.0.1']}
    new_writer=None
    try:
        async with TestClient(TestServer(make_public_app(store,Authority(tmp_path/'key','http://127.0.0.1:19000'),options,access=access))) as client:
            headers={'X-Forwarded-Proto':'https','Authorization':encode_basic_auth(old.client_id,secret)}
            assert (await client.post('/v2/enroll/commit',headers=headers,json={'operation_id':operation})).status==200
            assert await asyncio.wait_for(old_reader.read(1),1)==b''
            other_writer.write(b'survivor'); await other_writer.drain()
            assert await asyncio.wait_for(other_reader.readexactly(8),1)==b'survivor'
            new_reader,new_writer,_=await connect(relay,old.domain)
            assert (await client.post('/v2/enroll/commit',headers=headers,json={'operation_id':operation})).status==200
            new_writer.write(b'new'); await new_writer.drain()
            assert await asyncio.wait_for(new_reader.readexactly(3),1)==b'new'
    finally:
        for writer in (old_writer,other_writer,new_writer):
            if writer is not None: writer.close(); await writer.wait_closed()
