import json
import ssl

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from tools.external_acceptance import parse_targets, check


@pytest.mark.parametrize('value',[
    '[]','["http://example.org"]','["https://u:p@example.org"]',
    '["https://example.org/path"]','["https://example.org?q=x"]',
    '["https://example.org#x"]','["https://example.org\\n"]',
    '["https://example.org", "https://example.org"]',
])
def test_targets_reject_ambiguous_or_non_origin_input(value):
    with pytest.raises(ValueError): parse_targets(value)


async def test_anonymous_https_wss_and_redacted_failures(tmp_path):
    from server.app.pki import ensure_pki
    from tests.test_status_connections import LocalResolver
    from aiohttp import TCPConnector
    pki=ensure_pki(tmp_path/'pki','tunnel.example.org')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(pki.cert,pki.key)
    client_context=ssl.create_default_context(cafile=pki.ca)
    seen=[]
    async def shell(request):
        seen.append((request.method,request.path,request.headers.get('Authorization')))
        return web.Response(text='<html><home-assistant></home-assistant></html>',content_type='text/html')
    async def websocket(request):
        seen.append((request.method,request.path,request.headers.get('Authorization')))
        ws=web.WebSocketResponse(); await ws.prepare(request)
        await ws.send_json({'type':'auth_required','ha_version':'synthetic'})
        await ws.receive(); return ws
    app=web.Application(); app.router.add_get('/',shell); app.router.add_get('/api/websocket',websocket)
    server=TestServer(app,scheme='https',host='127.0.0.1'); await server.start_server(ssl=context)
    origin=f'https://tunnel.example.org:{server.port}'
    address={'port':server.port}
    try:
        result=await check(origin,1,connector_factory=lambda:TCPConnector(ssl=client_context,resolver=LocalResolver(address)))
        assert result['https'] and result['wss'] and result['error'] is None
        assert seen==[('GET','/',None),('GET','/api/websocket',None)]
        assert origin not in json.dumps(result) and 'localhost' not in json.dumps(result)
        failed=await check(origin,2,connector_factory=lambda:TCPConnector(resolver=LocalResolver(address)))
        assert failed['error']=='tls' and not failed['https']
        assert 'localhost' not in json.dumps(failed)
    finally: await server.close()


@pytest.mark.parametrize('mode,error',[
    ('redirect_other','redirect'),('redirect_loop','redirect'),('ws_redirect','redirect'),
    ('large_html','size'),('wrong_shell','shell'),('wrong_frame','protocol'),
    ('large_frame','websocket'),('slow','timeout'),('same_origin',None),
])
async def test_bounded_negative_routes_never_send_credentials(tmp_path,monkeypatch,mode,error):
    import asyncio
    from tools import external_acceptance as module
    from server.app.pki import ensure_pki
    from tests.test_status_connections import LocalResolver
    from aiohttp import TCPConnector
    pki=ensure_pki(tmp_path/'pki','tunnel.example.org')
    server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server_context.load_cert_chain(pki.cert,pki.key)
    client_context=ssl.create_default_context(cafile=pki.ca)
    seen=[]
    async def route(request):
        assert 'Authorization' not in request.headers and 'Cookie' not in request.headers
        seen.append(request.path)
        if request.path=='/api/websocket':
            if mode=='ws_redirect': raise web.HTTPFound('/forbidden')
            ws=web.WebSocketResponse(); await ws.prepare(request)
            await ws.send_str('x'*9000 if mode=='large_frame' else json.dumps({'type':'auth_ok' if mode=='wrong_frame' else 'auth_required'}))
            await ws.receive(); return ws
        if mode=='slow': await asyncio.sleep(.4)
        if mode=='redirect_other': raise web.HTTPFound('https://foreign.example.org/forbidden')
        if mode=='redirect_loop': raise web.HTTPFound('/')
        if mode=='same_origin' and request.path=='/': raise web.HTTPFound('/frontend')
        return web.Response(text='x'*(module.BODY_LIMIT+1) if mode=='large_html' else 'unrelated' if mode=='wrong_shell' else '<home-assistant></home-assistant>',content_type='text/html')
    app=web.Application();app.router.add_get('/{path:.*}',route)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_context)
    target=f'https://tunnel.example.org:{server.port}'
    if mode=='slow': monkeypatch.setattr(module,'DEADLINE',.1)
    try:
        result=await check(target,3,connector_factory=lambda:TCPConnector(ssl=client_context,resolver=LocalResolver({'port':server.port})))
        assert result['error']==error
        assert '/forbidden' not in seen
        assert len(seen)<=3
        assert 'example.org' not in json.dumps(result)
        if mode=='same_origin': assert result['https'] and result['wss']
    finally: await server.close()
