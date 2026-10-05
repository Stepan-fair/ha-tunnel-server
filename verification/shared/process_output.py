"""Continuously drain bounded child pipes; emit only reviewed diagnostic reason codes."""
from collections import deque
import asyncio

PATTERNS = ((b'address already in use','address_in_use'),(b'permission denied','permission_denied'),
            (b'no space left on device','disk_full'),(b'connection refused','connection_refused'),
            (b'no such file or directory','file_missing'),(b'certificate verify failed','certificate_error'),
            (b'i/o timeout','timed_out'))


class ProcessOutput:
    def __init__(self, diagnostics, component):
        self.diagnostics,self.component=diagnostics,component
        self.tail=deque(maxlen=16)
        self.suppressed=0

    def _line(self, line):
        # No arbitrary substring is copied. Even a secret embedded in a recognized
        # message yields only our fixed reason code.
        lowered=line.lower()
        reason=next((r for p,r in PATTERNS if p in lowered),'output_suppressed')
        self.tail.append(reason)
        if reason=='output_suppressed': self.suppressed+=1
        else: self.diagnostics.event('process_output',component=self.component,level='ERROR',fields={'reason':reason})

    async def drain(self, stream):
        pending=bytearray()
        discarding=False
        while True:
            chunk=await stream.read(4096)
            if not chunk: break
            for part in chunk.splitlines(keepends=True):
                if not discarding:
                    pending.extend(part)
                    if len(pending)>4096: pending.clear(); discarding=True
                if part.endswith((b'\n',b'\r')):
                    if not discarding: self._line(bytes(pending))
                    else: self.suppressed+=1
                    pending.clear(); discarding=False
            await asyncio.sleep(0)
        if pending: self._line(bytes(pending))
        if discarding: self.suppressed+=1
        if self.suppressed:
            self.diagnostics.event('process_output',component=self.component,
                fields={'reason':'output_suppressed','suppressed':min(self.suppressed,2**63-1)})
