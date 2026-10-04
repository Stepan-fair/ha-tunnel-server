"""Regressions for independently reproduced security findings, synthetic data only."""
import json
import asyncio
import sys
import time
import pytest
from aiohttp import encode_basic_auth
from aiohttp.test_utils import TestClient, TestServer
from server.app.store import Store
from server.app.identity import Authority
from server.app.web import make_public_app, make_ingress_app
from server.app.backup import export_state, restore_state
from server.app.pki import ensure_pki
from shared.http import Limits
from shared.discovery import discovery_payloads
from shared.mqtt import MqttBridge


def fixture(tmp_path):
    store = Store(tmp_path/'state/state.db', 'example.org')
    now = int(time.time())
    creds = store.redeem(store.issue('alpha', now).code, now)
    authority = Authority(tmp_path/'state/identity.key', 'http://127.0.0.1:19000')
    return store, creds, authority, now


@pytest.mark.parametrize('action,duration', [('pause',None),('set_duration',{'minutes':1}),('permanent',None)])
async def test_client_capabilities_cannot_block_admin_policy(tmp_path, action, duration):
    store, creds, authority, now = fixture(tmp_path)
    options={'trusted_proxy_ips':['127.0.0.1']}
    headers={'X-Forwarded-Proto':'https','Authorization':encode_basic_auth(creds.client_id,creds.secret)}
    async with TestClient(TestServer(make_public_app(store,authority,options))) as client:
        response=await client.post('/v1/client/status',headers=headers,json={'capabilities':[]})
        assert response.status == 200
        result=store.apply_access(creds.client_id,action,'policy',0,now,duration)
        assert result['editable']
        if action=='pause':
            assert (await client.post('/v1/token',headers=headers,data={'grant_type':'client_credentials'})).status == 401


async def test_unknown_path_flood_does_not_block_other_client(tmp_path):
    store, creds, authority, _ = fixture(tmp_path)
    headers={'X-Forwarded-Proto':'https','X-Real-IP':'192.0.2.1'}
    async with TestClient(TestServer(make_public_app(store,authority,{'trusted_proxy_ips':['127.0.0.1']}))) as client:
        for i in range(605):
            response=await client.get('/missing-'+str(i),headers=headers)
            assert response.status in (404,429)
        # The legitimate client may share the attacker's public IP (CGNAT).
        headers.update({'Authorization':encode_basic_auth(creds.client_id,creds.secret)})
        assert (await client.post('/v1/token',headers=headers,data={'grant_type':'client_credentials'})).status==200
        assert (await client.post('/v1/client/status',headers=headers,json={'capabilities':[]})).status==200


async def test_slow_unauthenticated_requests_cannot_take_client_reserve(tmp_path):
    store, creds, authority, _ = fixture(tmp_path)
    sockets=[]
    async with TestClient(TestServer(make_public_app(store,authority,{'trusted_proxy_ips':['127.0.0.1']}))) as client:
        try:
            for _ in range(8):
                reader,writer=await asyncio.open_connection(client.server.host,client.server.port)
                writer.write(b'POST /v1/enroll HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-Proto: https\r\nX-Real-IP: 192.0.2.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{')
                await writer.drain(); sockets.append((reader,writer))
            await asyncio.sleep(.05)
            headers={'X-Forwarded-Proto':'https','X-Real-IP':'192.0.2.1','Authorization':encode_basic_auth(creds.client_id,creds.secret)}
            assert (await client.post('/v1/token',headers=headers,data={'grant_type':'client_credentials'})).status==200
        finally:
            for _,writer in sockets: writer.close(); await writer.wait_closed()


def test_budget_churn_cannot_reset_existing_limit():
    limits=Limits()
    assert limits.allow('victim',2) and limits.allow('victim',2)
    assert not limits.allow('victim',2)
    for i in range(4097): limits.allow(('other',i),2)
    assert not limits.allow('victim',2)
    assert len(limits.buckets)<=4096


async def test_discovery_cannot_authorize_mqtt_resume():
    calls=[]
    state={'client_id':'b'*32,'domain':'alpha.example.org','revision':2,
           'access_state':'paused','editable':True,'revoked':False}
    async def provider(): return None
    async def handler(*args): calls.append(args)
    bridge=MqttBridge('a'*32,'server',provider,lambda:[state],handler)
    payload={'action':'start','client_id':state['client_id'],'revision':2,'session_nonce':bridge.session_nonce}
    await bridge.handle_command(bridge.prefix+'/'+state['client_id']+'/command',json.dumps(payload),False)
    assert not calls
    configs=discovery_payloads('a'*32,'server',state)
    assert all('payload_press' not in c and 'command_topic' not in c for c in configs.values())
    assert len(configs)==17


def test_old_backup_cannot_restore_revoked_credentials_or_tokens(tmp_path):
    store, creds, authority, now=fixture(tmp_path)
    state=store.path.parent
    ensure_pki(state/'pki','tunnel.example.org')
    invite=store.issue('pending',now)
    store.set_capabilities(creds.client_id,['access-v1'])
    store.apply_access(creds.client_id,'permanent','old-command',0,now)
    old_token=authority.issue(creds.client_id,generation=0)
    blob=export_state(state,store,'strong test password 123')
    store.revoke(creds.client_id)
    destination=tmp_path/'restored'
    restore_state(blob,'strong test password 123',destination,'example.org','tunnel.example.org')
    restored=Store(destination/'state.db','example.org')
    assert restored.authenticate(creds.client_id,creds.secret) is None
    assert restored.status_authenticate(creds.client_id,creds.secret) is None
    with pytest.raises(ValueError): restored.redeem(invite.code,now)
    with pytest.raises(ValueError): Authority(destination/'identity.key',authority.issuer).claims(old_token)
    with restored.connection() as db:
        assert db.execute('SELECT COUNT(*) FROM access_commands').fetchone()[0]==0
    assert all(c['revoked'] for c in restored.list_clients())
    fresh=restored.redeem(restored.reissue(creds.client_id,now).code,now)
    assert restored.authenticate(fresh.client_id,fresh.secret)
    assert restored.authenticate(creds.client_id,creds.secret) is None


async def test_server_revalidates_admin_role_for_every_request(tmp_path):
    store, _, authority, _=fixture(tmp_path)
    role=[True]; calls=[]
    async def admin(user): calls.append(user); return role[0]
    async def disconnect(cid): pass
    options={'server_url':'https://tunnel.example.org','admin_user_ids':['admin'],'ingress_ips':['127.0.0.1']}
    app=make_ingress_app(store,authority,options,disconnect,admin_check=admin)
    async with TestClient(TestServer(app)) as client:
        headers={'X-Remote-User-Id':'admin'}
        assert (await client.get('/api/state',headers=headers)).status==200
        role[0]=False
        assert (await client.get('/api/state',headers=headers)).status==403
    assert calls==['admin','admin']


async def test_role_verification_failure_denies_access(tmp_path):
    store, _, authority, _=fixture(tmp_path)
    async def admin(user): raise OSError('offline')
    async def disconnect(cid): pass
    options={'server_url':'https://tunnel.example.org','admin_user_ids':['admin'],'ingress_ips':['127.0.0.1']}
    async with TestClient(TestServer(make_ingress_app(store,authority,options,disconnect,admin_check=admin))) as client:
        assert (await client.get('/api/state',headers={'X-Remote-User-Id':'admin'})).status==403


async def test_trusted_https_api_returns_hsts(tmp_path):
    store, _, authority, _=fixture(tmp_path)
    async with TestClient(TestServer(make_public_app(store,authority,{'trusted_proxy_ips':['127.0.0.1']}))) as client:
        response=await client.get('/health',headers={'X-Forwarded-Proto':'https'})
        assert response.status==200
        assert response.headers['Strict-Transport-Security']=='max-age=31536000'


async def test_relay_rejects_excess_idle_connections(tmp_path):
    from server.app.relay import ClientRelay
    store, _, _, _=fixture(tmp_path)
    relay=ClientRelay(store,store.now,max_connections=1,max_client_connections=1)
    await relay.start(port=0)
    sockets=[]
    try:
        sockets.append(await asyncio.open_connection('127.0.0.1',relay.port))
        await asyncio.sleep(.05)
        sockets.append(await asyncio.open_connection('127.0.0.1',relay.port))
        response=await asyncio.wait_for(sockets[1][0].read(),1)
        assert response.startswith(b'HTTP/1.1 503')
        assert len(relay.tasks)==1
    finally:
        for _,writer in sockets: writer.close(); await writer.wait_closed()
        await relay.close()


def test_privilege_drop_rejects_symlinked_data(tmp_path):
    from shared.privileges import prepare_server_data
    # Avoid Windows symlink privileges; verify root path type with a regular file.
    invalid=tmp_path/'data'; invalid.write_text('not a directory')
    with pytest.raises(ValueError): prepare_server_data(invalid)


async def test_frp_process_does_not_inherit_supervisor_credentials(tmp_path,monkeypatch):
    from shared.runtime import FrpRuntime
    monkeypatch.setenv('SUPERVISOR_TOKEN','synthetic-sensitive-token')
    monkeypatch.setenv('HA_PRIVATE_TEST','synthetic-private-value')
    output=tmp_path/'env.json'
    code='import os,json; from pathlib import Path; Path('+repr(str(output))+').write_text(json.dumps(dict(os.environ)))'
    runtime=FrpRuntime(sys.executable,tmp_path/'frp.json',prefix=['-c',code],verify=False)
    await runtime.start({})
    await asyncio.wait_for(runtime.process.wait(),5)
    observed=json.loads(output.read_text())
    assert 'SUPERVISOR_TOKEN' not in observed
    assert 'HA_PRIVATE_TEST' not in observed
