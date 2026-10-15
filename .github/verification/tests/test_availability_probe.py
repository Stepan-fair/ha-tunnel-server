import asyncio
import ssl
from types import SimpleNamespace

import pytest
from aiohttp import web,TCPConnector
from aiohttp.test_utils import TestServer
from server.app.pki import ensure_pki
from server.app import availability_probe


@pytest.mark.parametrize('case',['fragmented','oversize','eof'])
async def test_pinned_tls_health_collects_bounded_complete_json(tmp_path,monkeypatch,case):
    pki=ensure_pki(tmp_path/'pki','tunnel.example.org')
    server_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_tls.load_cert_chain(pki.cert,pki.key)
    client_tls=ssl.create_default_context(cafile=str(pki.ca))
    async def health(request):
        response=web.StreamResponse(headers={'Content-Type':'application/json'})
        if case=='eof':response.content_length=100
        await response.prepare(request)
        await response.write(b'{"status":"ok",')
        await asyncio.sleep(.02)
        if case=='eof':request.transport.close()
        elif case=='oversize':await response.write(b' '*1025)
        else:await response.write(b'"protocol":1}')
        return response
    app=web.Application();app.router.add_get('/health',health)
    server=TestServer(app,scheme='https');await server.start_server(ssl=server_tls)
    monkeypatch.setattr(availability_probe,'TCPConnector',lambda **kw:TCPConnector(ssl=client_tls,**kw))
    probe=availability_probe.ServiceProbe(SimpleNamespace(status=lambda:{'running':False}),
        SimpleNamespace(returncode=1),f'https://tunnel.example.org:{server.port}',('127.0.0.1',))
    try:assert (await probe())['npm'] is (case=='fragmented')
    finally:await server.close()
