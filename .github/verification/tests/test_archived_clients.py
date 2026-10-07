import pytest
from aiohttp.test_utils import TestClient, TestServer

from server.app.store import Store, ConflictError
from server.app.journal import Journal
from server.app.identity import Authority
from server.app.web import make_ingress_app


def connected(tmp_path):
    store=Store(tmp_path/'state.db','example.org',clock=lambda:2000)
    c=store.redeem(store.issue('alpha',1000).code,1001)
    store.set_capabilities(c.client_id,['access-v1'])
    return store,c


async def test_revoke_moves_to_archive_without_erasing_history(tmp_path):
    store,c=connected(tmp_path)
    store.revoke(c.client_id)
    async def disconnect(cid): store.revoke(cid)
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner'],'server_url':'https://tunnel.example.org'}
    async with TestClient(TestServer(make_ingress_app(store,Authority(tmp_path/'identity.key','http://localhost'),options,disconnect))) as client:
        state=await(await client.get('/api/state',headers={'X-Remote-User-Id':'owner'})).json()
        assert state['clients']==[]
        assert state['archived'][0]['client_id']==c.client_id
    assert Journal(store).page(action='revoke')['items']


def test_restore_revoked_restarts_saved_duration(tmp_path):
    store,c=connected(tmp_path)
    store.apply_access(c.client_id,'set_duration','period',0,2000,{'minutes':1})
    store.apply_access(c.client_id,'pause','pause',1,2010)
    store.revoke(c.client_id)
    invite=store.reissue(c.client_id,3000)
    assert store.access_snapshot(c.client_id,3000)['revoked']
    new=store.redeem(invite.code,3001)
    snap=store.access_snapshot(c.client_id,3001)
    assert new.client_id==c.client_id and snap['deadline']==3061 and not snap['paused']
    assert store.authenticate(c.client_id,c.secret) is None


def test_delete_requires_revoke_and_matching_revision(tmp_path):
    store,c=connected(tmp_path)
    with pytest.raises(ConflictError): store.delete_revoked(c.client_id,0)
    store.revoke(c.client_id)
    with pytest.raises(ConflictError): store.delete_revoked(c.client_id,0)
    result=store.delete_revoked(c.client_id,1)
    assert result['deleted'] and not store.list_clients()
    assert Journal(store).page(action='delete')['items'][0]['domain']=='alpha.example.org'


def test_deleted_domain_can_be_reissued_with_new_id(tmp_path):
    store,c=connected(tmp_path)
    store.revoke(c.client_id); store.delete_revoked(c.client_id,1)
    new=store.redeem(store.issue('alpha',2000).code,2001)
    assert new.domain==c.domain and new.client_id!=c.client_id
    assert store.authenticate(c.client_id,c.secret) is None
    assert store.status_authenticate(c.client_id,c.secret) is None
    assert len(Journal(store).page(client_id=c.client_id)['items'])==4
    from server.app.routing import upstream_domain
    generation=store.access_snapshot(new.client_id,2001)['generation']
    assert upstream_domain(c.client_id,c.domain,0)!=upstream_domain(new.client_id,new.domain,generation)


def test_issue_revoked_collision_reports_recoverable_identity(tmp_path):
    store,c=connected(tmp_path); store.revoke(c.client_id)
    with pytest.raises(ConflictError) as caught: store.issue('alpha',2000)
    assert caught.value.client_id==c.client_id
    assert len(store.list_clients())==1


async def test_removed_discovery_is_cleared_after_bridge_restart(tmp_path):
    from types import SimpleNamespace
    from shared.mqtt import MqttBridge
    store,c=connected(tmp_path)
    sent=[]
    class Broker:
        def publish(self,topic,payload,qos,retain):
            sent.append((topic,payload,retain))
            return SimpleNamespace(rc=0,wait_for_publish=lambda timeout:None,is_published=lambda:True)
    async def service(): return None
    cache=tmp_path/'discovery.json'
    bridge=MqttBridge(store.get_metadata('instance_id'),'server',service,store.list_clients,discovery_cache=cache)
    bridge.client=Broker(); bridge.connected=True
    await bridge.reconcile()
    assert len([p for p in sent if p[0].endswith('/config')])==19  # 17 sensors and removal of two legacy buttons.
    store.revoke(c.client_id); store.delete_revoked(c.client_id,1)
    sent.clear()
    restarted=MqttBridge(store.get_metadata('instance_id'),'server',service,store.list_clients,discovery_cache=cache)
    restarted.client=Broker(); restarted.connected=True
    await restarted.reconcile()
    removed=[p for p in sent if p[0].endswith('/config')]
    assert len(removed)==17 and all(payload=='' and retained for _,payload,retained in removed)
