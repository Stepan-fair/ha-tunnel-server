import ssl
from unittest.mock import AsyncMock

import pytest


def controller(tmp_path):
    from client.app.controller import Controller
    config=tmp_path/'configuration.yaml'
    config.write_text('http:\n  use_x_forwarded_for: true\n  trusted_proxies: [127.0.0.1/32]\n')
    ctrl=Controller(tmp_path/'state',config,AsyncMock(),AsyncMock())
    ctrl.supervisor.get_http_config.return_value=None
    ctrl.credentials={'domain':'home.example.org','tunnel_host':'connect.example.org',
                      'tunnel_port':7000,'ca_pem':'test','client_id':'a'*32}
    ctrl.launch=AsyncMock()
    return ctrl


async def test_resume_configuration_error_keeps_status_available(tmp_path):
    ctrl=controller(tmp_path)
    ctrl.config_path.write_text('http: !secret http\n')
    await ctrl.resume()
    assert ctrl.status()['state']=='error'
    assert 'вручную' in ctrl.status()['message']
    ctrl.launch.assert_not_awaited()


async def test_resume_slow_core_can_recover_without_edit_or_restart(tmp_path):
    ctrl=controller(tmp_path)
    before=ctrl.config_path.read_bytes()
    ctrl.supervisor.wait_proxy_ready.side_effect=[TimeoutError(),None]
    await ctrl.resume()
    assert ctrl.status()['state']=='waiting_ha'
    await ctrl.monitor_once()
    ctrl.launch.assert_awaited_once()
    ctrl.supervisor.restart_core.assert_not_awaited()
    assert ctrl.config_path.read_bytes()==before


async def test_frp_certificate_failure_is_reported_without_api_call(tmp_path,monkeypatch):
    from client.app import controller as module
    ctrl=controller(tmp_path)
    ctrl.set_state('connecting','')
    monkeypatch.setattr(module,'verify_tunnel_tls',AsyncMock(side_effect=ssl.SSLCertVerificationError('untrusted')))
    await ctrl.monitor_once()
    assert ctrl.status()['state']=='certificate_error'
    ctrl.runtime.stop.assert_awaited_once()


def test_custom_server_label_reserved_and_existing_collision_refused(tmp_path):
    from server.app.store import Store
    store=Store(tmp_path/'state.db','example.org',server_host='connect.example.org')
    with pytest.raises(ValueError): store.issue('connect',0)
    other=Store(tmp_path/'other.db','example.org')
    other.issue('connect',0)
    with pytest.raises(ValueError): Store(other.path,'example.org',server_host='connect.example.org')


def test_package_includes_readme_documents(tmp_path):
    from tools.package import package
    package(tmp_path/'repo')
    for name in ('docs/ACCEPTANCE.md','docs/DEPLOYMENT.md','SECURITY.md','THIRD_PARTY.md'):
        assert (tmp_path/'repo'/name).is_file()


@pytest.mark.parametrize('status',[200,400,302])
async def test_proxy_readiness_requires_forwarded_request_accepted(status,monkeypatch):
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from client.app import supervisor
    app=web.Application()
    async def frontend(request):
        assert request.headers['X-Forwarded-For']=='192.0.2.1'
        assert request.headers['X-Forwarded-Proto']=='https'
        assert 'Authorization' not in request.headers
        return web.Response(status=status,headers={'Location':'/'})
    app.router.add_get('/',frontend)
    async with TestServer(app) as server:
        monkeypatch.setattr(supervisor,'CORE_ORIGIN',str(server.make_url('')).rstrip('/'))
        if status==200:
            await supervisor.Supervisor().wait_proxy_ready(timeout=.1)
        else:
            with pytest.raises(TimeoutError):
                await supervisor.Supervisor().wait_proxy_ready(timeout=.1)


@pytest.mark.parametrize('bad_name',[False,True])
async def test_tunnel_probe_validates_real_tls_certificate(tmp_path,bad_name,monkeypatch):
    import asyncio
    from server.app.pki import ensure_pki
    from client.app.controller import verify_tunnel_tls
    pki=ensure_pki(tmp_path/'pki','tunnel.example.org' if not bad_name else 'wrong.example.org')
    connect=asyncio.open_connection
    async def local_connect(host,port,**kwargs):
        return await connect('127.0.0.1',port,**kwargs)
    monkeypatch.setattr(asyncio,'open_connection',local_connect)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pki.cert,pki.key)
    async def accept(reader,writer):
        await reader.read()
        writer.close()
        await writer.wait_closed()
    async with await asyncio.start_server(accept,'127.0.0.1',0,ssl=context) as server:
        credentials={'tunnel_host':'tunnel.example.org','tunnel_port':server.sockets[0].getsockname()[1],
                     'ca_pem':pki.ca.read_text()}
        if bad_name:
            with pytest.raises(ssl.SSLCertVerificationError): await verify_tunnel_tls(credentials)
        else:
            await verify_tunnel_tls(credentials)


async def test_tunnel_probe_reaches_ipv4_when_first_ipv6_address_stalls(tmp_path,monkeypatch):
    import asyncio
    import socket
    from server.app.pki import ensure_pki
    from client.app.controller import verify_tunnel_tls
    pki=ensure_pki(tmp_path/'pki','tunnel.example.org')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pki.cert,pki.key)
    async def accept(reader,writer):
        await reader.read()
        writer.close()
        await writer.wait_closed()
    async with await asyncio.start_server(accept,'127.0.0.1',0,ssl=context) as server:
        port=server.sockets[0].getsockname()[1]
        loop=asyncio.get_running_loop()
        connect=loop.sock_connect
        async def addresses(*args,**kwargs):
            return [(socket.AF_INET6,socket.SOCK_STREAM,6,'',('::1',port,0,0)),
                    (socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',port))]
        async def stalled_ipv6(sock,address):
            if sock.family==socket.AF_INET6:
                await asyncio.Future()
            return await connect(sock,address)
        monkeypatch.setattr(loop,'getaddrinfo',addresses)
        monkeypatch.setattr(loop,'sock_connect',stalled_ipv6)
        credentials={'tunnel_host':'tunnel.example.org','tunnel_port':port,'ca_pem':pki.ca.read_text()}
        await asyncio.wait_for(verify_tunnel_tls(credentials),timeout=2)
