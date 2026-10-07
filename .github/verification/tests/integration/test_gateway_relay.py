import asyncio
import shutil
import time
import pytest
from aiohttp import web,ClientSession
from aiohttp.test_utils import TestServer
from test_frp import unused_port
from server.app.store import Store
from server.app.relay import ClientRelay
from server.app.gateway import nginx_config

pytestmark=pytest.mark.skipif(not shutil.which('nginx'),reason='Requires real Nginx')


async def test_real_nginx_normalizes_headers_and_rejects_framing(tmp_path):
    store=Store(tmp_path/'state.db','example.org')
    now=int(time.time()); c=store.redeem(store.issue('alpha',now).code,now)
    app=web.Application()
    upload_started = asyncio.Event()
    async def echo(request): return web.json_response(dict(request.headers))
    async def upload(request):
        assert await request.content.readexactly(3) == b'one'
        upload_started.set()
        assert await request.read() == b'two'
        return web.Response(text='ok')
    app.router.add_get('/',echo)
    app.router.add_post('/upload',upload)
    async with TestServer(app) as upstream:
        relay=ClientRelay(store,store.now,upstream_port=upstream.port)
        await relay.start(port=0)
        port=unused_port()
        config=tmp_path/'nginx.conf'
        config.write_text(nginx_config(['127.0.0.1']).replace('listen 8080;',f'listen 127.0.0.1:{port};').replace('127.0.0.1:18081',f'127.0.0.1:{relay.port}'))
        process=await asyncio.create_subprocess_exec('nginx','-c',str(config),'-g','daemon off;',stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    r,w=await asyncio.open_connection('127.0.0.1',port);w.close();await w.wait_closed();break
                except OSError: await asyncio.sleep(.05)
            async with ClientSession() as session:
                async with session.get(f'http://127.0.0.1:{port}/',headers={'Host':c.domain,'X-Forwarded-Proto':'https','X-Real-IP':'192.0.2.10','X-Forwarded-For':'127.0.0.1','X-Remote-User-Id':'admin'}) as response:
                    assert response.status==200
                    headers=await response.json()
                    assert headers['X-Forwarded-For']=='192.0.2.10' and 'X-Remote-User-Id' not in headers
                    assert headers['X-Forwarded-Proto']=='https' and headers['Connection']=='close'
                async def body():
                    yield b'one'
                    await asyncio.wait_for(upload_started.wait(), 2)
                    yield b'two'
                async with session.post(f'http://127.0.0.1:{port}/upload',data=body(),headers={'Host':c.domain,'X-Forwarded-Proto':'https','X-Real-IP':'192.0.2.10'}) as response:
                    assert response.status == 200
            for suffix in (
                b'Host: alpha.example.org\r\nHost: bravo.example.org\r\n',
                b'Host: alpha.example.org\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n',
            ):
                r,w=await asyncio.open_connection('127.0.0.1',port)
                w.write(b'GET / HTTP/1.1\r\nX-Forwarded-Proto: https\r\nX-Real-IP: 192.0.2.10\r\n'+suffix+b'\r\n')
                await w.drain()
                assert b'400' in await asyncio.wait_for(r.readuntil(b'\r\n\r\n'),3)
                w.close();await w.wait_closed()
        finally:
            process.terminate();await process.wait();await relay.close()
