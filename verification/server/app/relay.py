"""Bounded single-request relay and per-client stream isolation."""
import asyncio
from collections import defaultdict
import re
import time
from server.app.routing import upstream_domain

LIMIT = 65536
TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


async def header(reader):
    data = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
    if len(data) > LIMIT: raise ValueError('Header too large')
    lines = data[:-4].split(b'\r\n')
    fields = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b':')
        if not sep or not TOKEN.fullmatch(name) or any(c < 32 and c != 9 or c == 127 for c in value):
            raise ValueError('Invalid header')
        name = name.lower()
        if name in fields and name in (b'host', b'content-length', b'transfer-encoding', b'upgrade', b'connection'):
            raise ValueError('Duplicate framing header')
        fields[name] = value.strip()
    if b'transfer-encoding' in fields and b'content-length' in fields: raise ValueError('Ambiguous body')
    if b'transfer-encoding' in fields and fields[b'transfer-encoding'].lower() != b'chunked': raise ValueError('Unsupported encoding')
    if b'content-length' in fields and not re.fullmatch(rb'[0-9]{1,19}', fields[b'content-length']): raise ValueError('Invalid length')
    return data, lines[0], fields


class ClientRelay:
    def __init__(self, store, clock, upstream_host='127.0.0.1', upstream_port=18080,*,max_connections=256,max_client_connections=32):
        if any(type(v) is not int or v<1 for v in (max_connections,max_client_connections)):
            raise ValueError('Invalid connection limits')
        self.max_connections,self.max_client_connections=max_connections,max_client_connections
        self.store, self.clock = store, clock
        self.upstream_host, self.upstream_port = upstream_host, upstream_port
        self.locks = defaultdict(asyncio.Lock)
        self.streams = defaultdict(set)
        self.pending = defaultdict(lambda: [0, 0])
        self.samples = {}
        self.rate_values = {}
        self.telemetry_error = None
        self.tasks = set()
        self.client_tasks = defaultdict(set)
        self.rates_updated = {}
        self.server = None
        self.flusher = None
        self.closing = False

    def now(self): return self.clock.now() if hasattr(self.clock, 'now') else self.clock()

    async def start(self, host='127.0.0.1', port=18081):
        self.server = await asyncio.start_server(self._accept, host, port, limit=LIMIT)
        self.port = self.server.sockets[0].getsockname()[1]
        self.flusher = asyncio.create_task(self._flush_loop())

    def _accept(self, reader, writer):
        if len(self.tasks)>=self.max_connections:
            writer.write(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            writer.close()
            return
        task = asyncio.create_task(self._serve(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _write(self, writer, data, client_id, direction):
        writer.write(data)
        await writer.drain()
        self.pending[client_id][direction] += len(data)

    async def _copy(self, reader, writer, client_id, direction, length=None):
        remaining = length
        while remaining is None or remaining:
            data = await reader.read(LIMIT if remaining is None else min(LIMIT, remaining))
            if not data:
                if remaining: raise ValueError('Incomplete body')
                break
            await self._write(writer, data, client_id, direction)
            if remaining is not None: remaining -= len(data)

    async def _body(self, reader, writer, fields, client_id, direction, eof=False):
        if b'transfer-encoding' in fields:
            while True:
                line = await reader.readuntil(b'\r\n')
                if len(line) > 8192 or not re.fullmatch(rb'[0-9a-fA-F]{1,16}\r\n', line): raise ValueError('Invalid chunk')
                size = int(line[:-2], 16)
                await self._write(writer, line, client_id, direction)
                if not size:
                    # Trailers are deliberately unsupported to avoid ambiguous routing.
                    if await reader.readexactly(2) != b'\r\n': raise ValueError('Unsupported trailer')
                    await self._write(writer, b'\r\n', client_id, direction)
                    return
                await self._copy(reader, writer, client_id, direction, size)
                if await reader.readexactly(2) != b'\r\n': raise ValueError('Invalid chunk end')
                await self._write(writer, b'\r\n', client_id, direction)
        else:
            length = int(fields[b'content-length']) if b'content-length' in fields else None if eof else 0
            await self._copy(reader, writer, client_id, direction, length)

    async def _serve(self, reader, writer):
        upstream = None
        client_id = None
        pumps = []
        try:
            data, first, fields = await header(reader)
            parts = first.split(b' ')
            if len(parts) != 3 or not TOKEN.fullmatch(parts[0]) or not parts[1].startswith(b'/') or parts[2] != b'HTTP/1.1':
                raise ValueError('Invalid request line')
            host = fields.get(b'host', b'').decode('ascii')
            if not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', host): raise ValueError('Invalid host')
            client = self.store.client_by_domain(host)
            if client is None:
                writer.write(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                await writer.drain(); return
            client_id = client.client_id
            self.client_tasks[client_id].add(asyncio.current_task())
            async with self.locks[client_id]:
                if len(self.client_tasks[client_id])>self.max_client_connections:
                    writer.write(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    await writer.drain()
                    return
                snapshot = self.store.access_snapshot(client_id, self.now())
                if self.closing or snapshot['access_state'] != 'allowed':
                    writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    await writer.drain(); return
                self.streams[client_id].add(writer)
            ur, upstream = await asyncio.wait_for(asyncio.open_connection(self.upstream_host, self.upstream_port, limit=LIMIT), 10)
            async with self.locks[client_id]:
                current = self.store.access_snapshot(client_id, self.now())
                if writer.is_closing() or current['access_state'] != 'allowed' or current['generation'] != snapshot['generation']: return
                self.streams[client_id].add(upstream)
            route = upstream_domain(client_id, host, snapshot['generation']).encode('ascii')
            data = b'\r\n'.join(b'Host: '+route if line.partition(b':')[0].lower() == b'host' else line for line in data.split(b'\r\n'))
            await self._write(upstream, data, client_id, 0)
            body_done = asyncio.Event()
            upgrade = asyncio.Future()
            async def request():
                await self._body(reader, upstream, fields, client_id, 0)
                body_done.set()
                ws = await upgrade
                if ws:
                    await self._copy(reader, upstream, client_id, 0)
                    if upstream.can_write_eof(): upstream.write_eof()
                elif await reader.read(1):
                    raise ValueError('HTTP pipelining is forbidden')
            async def response():
                while True:
                    reply, status, response_fields = await header(ur)
                    bits = status.split(b' ', 2)
                    if len(bits) < 2 or bits[0] != b'HTTP/1.1' or not re.fullmatch(rb'[0-9]{3}', bits[1]): raise ValueError('Invalid response')
                    code = int(bits[1])
                    ws = code == 101
                    if ws and (fields.get(b'upgrade', b'').lower() != b'websocket' or response_fields.get(b'upgrade', b'').lower() != b'websocket' or b'upgrade' not in response_fields.get(b'connection', b'').lower().split(b', ')):
                        raise ValueError('Unexpected upgrade')
                    await self._write(writer, reply, client_id, 1)
                    if 100 <= code < 200 and not ws: continue
                    upgrade.set_result(ws)
                    if ws: await self._copy(ur, writer, client_id, 1)
                    elif parts[0] != b'HEAD' and code not in (204, 304):
                        await self._body(ur, writer, response_fields, client_id, 1, eof=True)
                    return
            pumps = [asyncio.create_task(request()), asyncio.create_task(response())]
            done, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for task in done: task.result()
            # Request EOF is valid for both HTTP and WS; retain the complete reply.
            # A pipelined byte raises above and still cancels the response.
            if pumps[0] in done:
                await pumps[1]
        except (ValueError, UnicodeError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
            if client_id is None and not writer.is_closing():
                writer.write(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                try: await writer.drain()
                except OSError: pass
        finally:
            for task in pumps: task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            for stream in (writer, upstream):
                if stream is not None:
                    if client_id: self.streams[client_id].discard(stream)
                    stream.close()
                    try: await asyncio.wait_for(stream.wait_closed(), 1)
                    except (OSError, asyncio.TimeoutError): stream.transport.abort()
            if client_id: self.client_tasks[client_id].discard(asyncio.current_task())

    async def disconnect(self, client_id):
        async with self.locks[client_id]:
            streams = tuple(self.streams[client_id])
            for stream in streams: stream.transport.abort()
            for task in tuple(self.client_tasks[client_id]):
                if task is not asyncio.current_task(): task.cancel()

    async def flush(self):
        try:
            for client_id, counts in list(self.pending.items()):
                to_client, from_client = counts
                if to_client or from_client:
                    self.store.add_traffic(client_id, to_client, from_client)
                    counts[0] -= to_client; counts[1] -= from_client
            now = time.monotonic()
            for client in self.store.list_clients():
                cid = client['client_id']
                counts = (client['to_client_bytes']+self.pending[cid][0], client['from_client_bytes']+self.pending[cid][1])
                old = self.samples.get(cid)
                if old is None: self.samples[cid] = (now, counts)
                elif now-old[0] >= 5:
                    self.rate_values[cid] = tuple(max(0, (v-o)/(now-old[0])) for v, o in zip(counts, old[1]))
                    self.rates_updated[cid] = now
                    self.samples[cid] = (now, counts)
            self.telemetry_error = None
        except Exception:
            self.telemetry_error = 'traffic_storage_error'
            self.rate_values.clear()
            self.rates_updated.clear()
            self.samples.clear()

    def rates(self, client_id):
        updated = self.rates_updated.get(client_id)
        return self.rate_values.get(client_id) if updated is not None and 0 <= time.monotonic()-updated <= 45 else None

    async def _flush_loop(self):
        while True:
            await asyncio.sleep(1)
            await self.flush()

    async def close(self):
        self.closing = True
        if self.server:
            self.server.close(); await self.server.wait_closed()
        if self.flusher:
            self.flusher.cancel(); await asyncio.gather(self.flusher, return_exceptions=True)
        for cid in list(self.streams): await self.disconnect(cid)
        for task in tuple(self.tasks): task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
        await self.flush()
