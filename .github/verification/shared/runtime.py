"""Subprocess boundary: optional safe diagnostics, never raw credential-bearing output."""
import asyncio
import json
from pathlib import Path
from shared.files import atomic_write
from shared.environment import child_environment
from shared.process_output import ProcessOutput


class FrpRuntime:
    def __init__(self, binary, config_path, *, prefix=(), verify=True, diagnostics=None):
        self.binary = str(binary)
        self.path = Path(config_path)
        self.prefix = list(prefix)
        self.verify = verify
        self.process = None
        self.config = None
        self.lock = asyncio.Lock()
        self.diagnostics=diagnostics
        self.output_tasks=[]
        self.reported_exit=None

    def status(self):
        running=self.process is not None and self.process.returncode is None
        code=None if self.process is None else self.process.returncode
        if self.diagnostics and self.process is not None:
            self.diagnostics.component('frp','running' if running else 'stopped',exit_code=code)
            if not running and self.reported_exit!=self.process.pid:
                self.reported_exit=self.process.pid
                self.diagnostics.event('process_exit',component='frp',level='WARNING',fields={'exit_code':code})
        return {'running':running,'exit_code':code}

    async def _spawn(self, *args):
        sink=asyncio.subprocess.PIPE if self.diagnostics else asyncio.subprocess.DEVNULL
        process=await asyncio.create_subprocess_exec(self.binary,*self.prefix,*args,
            stdout=sink,stderr=sink,env=child_environment())
        tasks=[]
        if self.diagnostics:
            for stream in (process.stdout,process.stderr):
                tasks.append(asyncio.create_task(ProcessOutput(self.diagnostics,'frp').drain(stream)))
        return process,tasks

    async def _drain(self,tasks):
        if not tasks: return
        try: await asyncio.wait_for(asyncio.gather(*tasks),2)
        except TimeoutError:
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)

    async def _launch(self):
        self.process,self.output_tasks=await self._spawn('-c',str(self.path))
        self.status()
        if self.diagnostics: self.diagnostics.event('process_start',component='frp')

    async def start(self, config):
        async with self.lock:
            if self.status()['running']:
                raise RuntimeError('Process already running')
            atomic_write(self.path,json.dumps(config,separators=(',',':')).encode())
            if self.verify:
                if self.diagnostics: self.diagnostics.event('process_verify',component='frp')
                check,tasks=await self._spawn('verify','-c',str(self.path))
                try:
                    result=await asyncio.wait_for(check.wait(),15)
                except BaseException:
                    if check.returncode is None:
                        check.kill()
                        await check.wait()
                    await self._drain(tasks)
                    raise
                await self._drain(tasks)
                if self.diagnostics:
                    self.diagnostics.event('process_exit',component='frp',
                        level='ERROR' if result else 'INFO',fields={'exit_code':result})
                if result:
                    raise RuntimeError('FRP configuration rejected')
            self.config=config
            await self._launch()

    async def _stop(self):
        if self.status()['running']:
            self.process.terminate()
            try: await asyncio.wait_for(self.process.wait(),10)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()
        await self._drain(self.output_tasks)
        self.output_tasks=[]
        self.status()

    async def stop(self):
        async with self.lock: await self._stop()

    async def restart(self):
        async with self.lock:
            if self.config is None: raise RuntimeError('Process not configured')
            if self.diagnostics: self.diagnostics.event('process_restart',component='frp')
            await self._stop()
            await self._launch()
