import json
import secrets
import ssl
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from shared.protocol import Invitation


def test_invitation_roundtrip_and_rejects_insecure_origins():
    invite=Invitation('https://tunnel.example.org',secrets.token_urlsafe(32))
    assert Invitation.parse(invite.encode())==invite
    for bad in ('http://tunnel.example.org','https://user:pass@example.org','https://example.org/path','https://example.org?secret=a'):
        with pytest.raises(ValueError):
            Invitation(bad,invite.code).encode()
    assert invite.code not in repr(invite)


def test_credentials_require_same_origin_and_public_ca(tmp_path):
    from client.app.enrollment import validate_response, save_credentials, load_credentials
    from server.app.pki import ensure_pki
    ca=ensure_pki(tmp_path/'pki','tunnel.example.org').ca.read_text()
    invite=Invitation('https://tunnel.example.org',secrets.token_urlsafe(32))
    data={'protocol':1,'client_id':'a'*32,'secret':secrets.token_urlsafe(32),'domain':'home.example.org',
          'server_url':invite.server,'tunnel_host':'tunnel.example.org','tunnel_port':7000,'ca_pem':ca}
    assert validate_response(data,invite)==data
    save_credentials(tmp_path/'client',data)
    assert load_credentials(tmp_path/'client')==data
    for key,value in [('server_url','https://evil.example.org'),('tunnel_host','evil.example.org'),
                      ('tunnel_port',True),('tunnel_port',0),('domain','x.other.org'),
                      ('ca_pem',ca+'\n-----BEGIN PRIVATE KEY-----'),('protocol',2)]:
        with pytest.raises(ValueError):
            validate_response({**data,key:value},invite)


async def test_enrollment_never_follows_redirect_or_disables_tls(tmp_path):
    from client.app.enrollment import enroll, post_json
    from server.app.pki import ensure_pki
    files=ensure_pki(tmp_path/'pki','tunnel.example.org')
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(files.cert,files.key)
    app=web.Application()
    async def redirect(request): raise web.HTTPFound('/target')
    reached=[]
    async def target(request):
        reached.append(True)
        return web.json_response({})
    app.router.add_post('/v1/enroll',redirect)
    app.router.add_get('/target',target)
    from aiohttp import ClientSession,ClientConnectorCertificateError
    async with TestServer(app) as srv, ClientSession() as session:
        with pytest.raises(ValueError):
            await post_json(session,str(srv.make_url('/v1/enroll')),json={})
        assert not reached
    app2=web.Application()
    app2.router.add_post('/v1/enroll',target)
    async with TestServer(app2) as srv, ClientSession() as session:
        await srv.close()
    secure_server=TestServer(web.Application(),scheme='https')
    await secure_server.start_server(ssl=ctx)
    try:
        async with ClientSession() as session:
            with pytest.raises(ClientConnectorCertificateError):
                await post_json(session,str(secure_server.make_url('/v1/enroll')),json={})
    finally:
        await secure_server.close()
    # No transport/verify=false parameter is exposed to callers.
    import inspect
    assert set(inspect.signature(enroll).parameters)=={'invitation','expected_client_id','expected_server_url'}
    with pytest.raises(ValueError):
        await enroll('HT1.invalid')


async def test_json_reader_limits_response_size():
    from client.app.enrollment import read_json
    app=web.Application()
    async def large(request): return web.Response(body=b'x'*32769)
    app.router.add_get('/',large)
    from aiohttp import ClientSession
    async with TestServer(app) as srv, ClientSession() as session:
        async with session.get(srv.make_url('/')) as response:
            with pytest.raises(ValueError):
                await read_json(response)


async def test_json_reader_handles_fragmented_response():
    from client.app.enrollment import read_json
    from aiohttp import ClientSession
    import asyncio
    app=web.Application()
    async def fragmented(request):
        response=web.StreamResponse(headers={'Content-Type':'application/json'})
        await response.prepare(request)
        for chunk in (b'{"value":',b'"hello"',b'}'):
            await response.write(chunk)
            await asyncio.sleep(.02)
        return response
    app.router.add_get('/',fragmented)
    async with TestServer(app) as server,ClientSession() as session:
        async with session.get(server.make_url('/')) as response:
            assert await read_json(response)=={'value':'hello'}
