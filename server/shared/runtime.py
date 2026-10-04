"""Subprocess boundary: never forward FRP logs, which can contain credentials."""
import asyncio
import json
from pathlib import Path
from shared.files import atomic_write


class FrpRuntime:
    def __init__(self, binary, config_path, *, prefix=(), verify=True):
        self.binary = str(binary)
        self.path = Path(config_path)
        self.prefix = list(prefix)
        self.verify = verify
        self.process = None
        self.config = None
        self.lock = asyncio.Lock()

    def status(self):
        return {'running': self.process is not None and self.process.returncode is None,
                'exit_code': None if self.process is None else self.process.returncode}

    async def _launch(self):
        # Discard arbitrary child output rather than trusting ad-hoc redaction.
        self.process = await asyncio.create_subprocess_exec(
            self.binary,*self.prefix,'-c',str(self.path),
            stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)

    async def start(self, config):
        async with self.lock:
            if self.status()['running']:
                raise RuntimeError('Process already running')
            atomic_write(self.path,json.dumps(config,separators=(',',':')).encode())
            if self.verify:
                check = await asyncio.create_subprocess_exec(
                    self.binary,*self.prefix,'verify','-c',str(self.path),
                    stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
                try:
                    result = await asyncio.wait_for(check.wait(),15)
                except BaseException:
                    if check.returncode is None:
                        check.kill()
                        await check.wait()
                    raise
                if result:
                    raise RuntimeError('FRP configuration rejected')
            self.config = config
            await self._launch()

    async def _stop(self):
        if self.status()['running']:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(),10)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()

    async def stop(self):
        async with self.lock:
            await self._stop()

    async def restart(self):
        async with self.lock:
            if self.config is None:
                raise RuntimeError('Process not configured')
            await self._stop()
            await self._launch()
