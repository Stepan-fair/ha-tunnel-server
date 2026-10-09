"""Exercise real, verified TLS and HTTP pooling; no production credentials."""
import socket
import ssl

import aiohttp
from aiohttp import web
from aiohttp.abc import AbstractResolver
from aiohttp.test_utils import TestServer
import pytest

from server.app.pki import ensure_pki
from client.app.status import ClientStatusClient


class LocalResolver(AbstractResolver):
    def __init__(self, address): self.address = address

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{'hostname': host, 'host': '127.0.0.1', 'port': self.address['port'],
                 'family': socket.AF_INET, 'proto': 0, 'flags': 0}]

    async def close(self): pass


@pytest.fixture
def verified_connector(tmp_path, monkeypatch):
    import client.app.status as module
    pki = ensure_pki(tmp_path/'pki', 'tunnel.example.org')
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.load_cert_chain(pki.cert, pki.key)
    client_ssl = ssl.create_default_context(cafile=pki.ca)
    address = {}
    original = aiohttp.TCPConnector
    def connector(**kwargs):
        return original(ssl=client_ssl, resolver=LocalResolver(address), **kwargs)
    # Existing implementation has no connector configuration yet. Patching the
    # constructor preserves verification and exercises the actual network stack.
    monkeypatch.setattr(module, 'TCPConnector', connector, raising=False)
    original_session = aiohttp.ClientSession
    def session(**kwargs):
        if 'connector' not in kwargs: kwargs['connector'] = connector()
        return original_session(**kwargs)
    monkeypatch.setattr(module, 'ClientSession', session)
    return server_ssl, address


async def test_status_polls_reuse_verified_connection_without_cookies_or_health_auth(verified_connector):
    transports = []
    authorizations = []
    app = web.Application()
    async def health(request):
        assert 'Authorization' not in request.headers
        assert 'Cookie' not in request.headers
        transports.append(request.transport)
        response = web.json_response({'status':'ok', 'protocol':1, 'capabilities':['access-v1']})
        response.set_cookie('untrusted', 'must-not-persist', secure=True)
        return response
    async def status(request):
        assert 'Cookie' not in request.headers
        transports.append(request.transport)
        authorizations.append(request.headers['Authorization'])
        return web.json_response({'client_id':'a'*32, 'access_state':'allowed', 'revision':1, 'generation':0})
    app.router.add_get('/health', health)
    app.router.add_post('/v1/client/status', status)
    server_ssl, address = verified_connector
    server = TestServer(app, scheme='https')
    await server.start_server(ssl=server_ssl)
    address['port'] = server.port
    service = ClientStatusClient('https://tunnel.example.org')
    try:
        for secret in ('old-test-secret', 'replacement-test-secret'):
            assert (await service.fetch('a'*32, secret))['access_state'] == 'allowed'
        assert authorizations == [aiohttp.encode_basic_auth('a'*32, s) for s in ('old-test-secret','replacement-test-secret')]
        assert len(set(transports)) == 1, 'Each poll unnecessarily repeats TCP/TLS setup'
    finally:
        if hasattr(service, 'close'): await service.close()
        await server.close()


async def test_status_session_rejects_redirect_and_closes_cleanly(verified_connector):
    visits = []
    app = web.Application()
    async def health(request): raise web.HTTPFound('/stolen')
    async def stolen(request):
        visits.append(True)
        return web.json_response({})
    app.router.add_get('/health', health)
    app.router.add_get('/stolen', stolen)
    server_ssl, address = verified_connector
    server = TestServer(app, scheme='https')
    await server.start_server(ssl=server_ssl)
    address['port'] = server.port
    service = ClientStatusClient('https://tunnel.example.org')
    try:
        with pytest.raises(ValueError): await service.fetch('a'*32, 'test-secret')
        assert visits == []
        await service.close()
        await service.close()
        # Explicit close permits a clean new lifecycle, never a leaked session.
        with pytest.raises(ValueError): await service.fetch('a'*32, 'new-secret')
    finally:
        if hasattr(service, 'close'): await service.close()
        await server.close()
