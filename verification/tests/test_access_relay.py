import asyncio
import pytest
from server.app.store import Store
from server.app.relay import ClientRelay
from server.app.access import AccessService


@pytest.fixture
async def network(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org', clock=lambda: 2000)
    clients = [store.redeem(store.issue(name, 1000).code, 1001) for name in ('alpha', 'bravo')]
    for c in clients: store.set_capabilities(c.client_id, ['access-v1'])
    async def echo(reader, writer):
        try:
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    upstream = await asyncio.start_server(echo, '127.0.0.1', 0)
    relay = ClientRelay(store, store.clock, upstream_port=upstream.sockets[0].getsockname()[1])
    await relay.start(port=0)
    try: yield store, clients, relay, AccessService(store, relay, store.clock)
    finally:
        await relay.close()
        upstream.close()
        await upstream.wait_closed()


async def connect(relay, host):
    reader, writer = await asyncio.open_connection('127.0.0.1', relay.port)
    writer.write(f'GET /api/websocket HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'.encode())
    await writer.drain()
    header = await reader.readuntil(b'\r\n\r\n')
    return reader, writer, header


async def test_pause_closes_only_selected_client(network):
    store, clients, relay, access = network
    a, b = clients
    ra, wa, ha = await connect(relay, a.domain)
    rb, wb, hb = await connect(relay, b.domain)
    assert b'101' in ha and b'101' in hb
    wa.write(b'hello'); await wa.drain()
    assert await ra.readexactly(5) == b'hello'
    await access.command(a.client_id, 'pause', 'pause-a', 0)
    assert await asyncio.wait_for(ra.read(1), 1) == b''
    wb.write(b'survivor'); await wb.drain()
    assert await rb.readexactly(8) == b'survivor'
    r, w, header = await connect(relay, a.domain)
    assert b'403' in header
    w.close(); wa.close(); wb.close()
    await relay.flush()
    snap = store.access_snapshot(b.client_id, 2000)
    assert snap['to_client_bytes'] >= 8 and snap['from_client_bytes'] >= 8


@pytest.mark.parametrize('wire_request', [
    b'GET / HTTP/1.1\r\nHost: alpha.example.org\r\nHost: bravo.example.org\r\n\r\n',
    b'GET https://bravo.example.org/ HTTP/1.1\r\nHost: alpha.example.org\r\n\r\n',
    b'POST / HTTP/1.1\r\nHost: alpha.example.org\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc',
    b'GET / HTTP/1.1\r\nHost: alpha.example.org:443\r\n\r\n',
    b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
    b'GET / HTTP/1.1\r\nHost: alpha.example.org\r\n Upgrade: websocket\r\n\r\n',
])
async def test_ambiguous_requests_rejected(network, wire_request):
    _, _, relay, _ = network
    r, w = await asyncio.open_connection('127.0.0.1', relay.port)
    w.write(wire_request); await w.drain()
    assert b'400' in await r.readuntil(b'\r\n\r\n')
    w.close()


async def test_expiry_disconnect_and_graceful_flush(network):
    store, clients, relay, access = network
    c = clients[0]
    await access.command(c.client_id, 'set_duration', 'timer', 0, {'minutes': 1})
    r, w, _ = await connect(relay, c.domain)
    w.write(b'123'); await w.drain(); assert await r.readexactly(3) == b'123'
    store.clock = lambda: 2061
    access.clock = store.clock
    await access.expire_once()
    assert await asyncio.wait_for(r.read(1), 1) == b''
    await relay.flush()
    before = store.access_snapshot(c.client_id, 2061)
    await relay.flush()
    assert store.access_snapshot(c.client_id, 2061) == before
    w.close()


async def test_stream_backpressure_and_half_close(network):
    _, clients, relay, _ = network
    r, w, _ = await connect(relay, clients[0].domain)
    block = b'x'*65536
    async def send():
        for _ in range(2050):
            w.write(block)
            await w.drain()
        w.write_eof()
    task = asyncio.create_task(send())
    total = 0
    while data := await asyncio.wait_for(r.read(32768), 5):
        assert data == b'x'*len(data)
        total += len(data)
    await task
    assert total == 2050*len(block)
    w.close()


async def test_cross_host_pipeline_never_forwarded(network):
    _, _, relay, _ = network
    received = []
    async def http(reader, writer):
        received.append(await reader.readuntil(b'\r\n\r\n'))
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
        await writer.drain()
        received.append(await reader.read())
        writer.close()
    upstream = await asyncio.start_server(http, '127.0.0.1', 0)
    relay.upstream_port = upstream.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection('127.0.0.1', relay.port)
    w.write(b'GET / HTTP/1.1\r\nHost: alpha.example.org\r\n\r\nGET / HTTP/1.1\r\nHost: bravo.example.org\r\n\r\n')
    await w.drain(); await asyncio.wait_for(r.read(), 2)
    await asyncio.sleep(.02)
    assert len(received) == 2 and received[1] == b''
    w.close(); upstream.close(); await upstream.wait_closed()


async def test_http_half_close_retains_delayed_response(network):
    _, clients, relay, _ = network
    async def http(reader, writer):
        await reader.readuntil(b'\r\n\r\n')
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n')
        await writer.drain()
        await asyncio.sleep(.15)
        writer.write(b'hello'); await writer.drain(); writer.close()
    upstream = await asyncio.start_server(http, '127.0.0.1', 0)
    relay.upstream_port = upstream.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection('127.0.0.1', relay.port)
    try:
        w.write(f'GET / HTTP/1.1\r\nHost: {clients[0].domain}\r\n\r\n'.encode())
        await w.drain(); w.write_eof()
        assert (await asyncio.wait_for(r.read(), 2)).endswith(b'hello')
    finally:
        w.close(); upstream.close(); await upstream.wait_closed()
