"""Finite process-lifetime DNS work, independent of HTTP-session lifetimes.

No queue or result cache: an occupied key fails closed, including after its
caller timed out. The owned child is killed and reaped on deadline; a later
attempt starts a fresh lookup. Slots remain quarantined until reaping succeeds.
"""
import asyncio
import ipaddress
import json
from pathlib import Path
import socket
import sys
import threading

import aiohttp
from aiohttp import TCPConnector
from aiohttp.abc import AbstractResolver
from shared.environment import child_environment

_LIMIT = 8
_DEADLINE = 4.0
_REAP_DEADLINE = 1.0
_active = {}
_lock = threading.Lock()
_tasks = set()
_worker = str(Path(__file__).with_name('dns_worker.py'))


def _owned(coroutine):
    task = asyncio.create_task(coroutine)
    _tasks.add(task)
    def finished(done):
        _tasks.discard(done)
        if not done.cancelled(): done.exception()
    task.add_done_callback(finished)
    return task


def _release(key, token):
    with _lock:
        if _active.get(key) is token:
            del _active[key]


async def _reap(process, key, token):
    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError:
            # Keep the finite slot reserved until actual exit, even if kill fails.
            pass
    waiter = _owned(process.wait())
    waiter.add_done_callback(lambda done: _release(key, token) if not done.cancelled() and done.exception() is None else None)
    try:
        await asyncio.wait_for(asyncio.shield(waiter), _REAP_DEADLINE)
    except (TimeoutError, asyncio.CancelledError):
        # The waiter retains its slot. Never launch a replacement orphan.
        pass


def _late_spawn(spawn, key, token):
    if spawn.cancelled() or spawn.exception() is not None:
        _release(key, token)
        return
    _owned(_reap(spawn.result(), key, token))


async def _job(host, port, family, key, token):
    spawn = _owned(asyncio.create_subprocess_exec(
        sys.executable, '-I', _worker, json.dumps([host, port, family]),
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, limit=32769, env=child_environment()))
    process = None
    try:
        async with asyncio.timeout(_DEADLINE):
            process = await asyncio.shield(spawn)
            raw = bytearray()
            while chunk := await process.stdout.read(8192):
                raw.extend(chunk)
                if len(raw) > 32768:
                    raise OSError('DNS response too large')
            if await process.wait() != 0:
                raise OSError('DNS unavailable')
            rows = json.loads(raw)
            if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
                raise ValueError()
            result = []
            for af, kind, proto, canon, address in rows:
                ip = ipaddress.ip_address(address[0])
                if af not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM:
                    raise ValueError()
                if (ip.version == 4) != (af == socket.AF_INET) or family not in (0, af):
                    raise ValueError()
                if address[1] != (port or 0):
                    raise ValueError()
                result.append((af, kind, proto, canon, tuple(address)))
            return result
    except (TimeoutError, ValueError, TypeError, KeyError, UnicodeError):
        raise OSError('DNS unavailable') from None
    finally:
        if process is not None:
            await _reap(process, key, token)
        else:
            # Timeout/cancellation may race OS process creation. Retain the slot
            # and collect exactly that spawn result; never abandon its child.
            spawn.add_done_callback(lambda done: _late_spawn(done, key, token))


async def getaddrinfo(host, port, family=socket.AF_UNSPEC):
    if not isinstance(host, str) or not 1 <= len(host) <= 253 or '\x00' in host:
        raise OSError('Invalid DNS target')
    if port is not None and (type(port) is not int or not 0 <= port <= 65535):
        raise OSError('Invalid DNS port')
    if family not in (socket.AF_UNSPEC, socket.AF_INET, socket.AF_INET6):
        raise OSError('Invalid DNS family')
    key = (host.lower().rstrip('.'), port, family)
    token = object()
    with _lock:
        if key in _active or len(_active) >= _LIMIT:
            raise OSError('DNS lookup busy')
        _active[key] = token
    job = _owned(_job(host, port, family, key, token))
    # A caller cancellation cannot detach ownership of the underlying child.
    return await asyncio.shield(job)


class Resolver(AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        rows = await getaddrinfo(host, port, family)
        return [dict(hostname=host, host=row[4][0], port=port,
                     family=row[0], proto=row[2], flags=socket.AI_NUMERICHOST)
                for row in rows]

    async def close(self):
        # Jobs belong to the finite process budget, not this session wrapper.
        pass


def connector(**kwargs):
    return TCPConnector(resolver=Resolver(), use_dns_cache=False, **kwargs)


def session(*args, **kwargs):
    if 'connector' not in kwargs:
        kwargs['connector'] = connector()
    return aiohttp.ClientSession(*args, **kwargs)
