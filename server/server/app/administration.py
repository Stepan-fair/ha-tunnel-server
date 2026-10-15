"""One fail-closed administrative boundary; nesting belongs to the exact asyncio Task."""
import asyncio
from contextlib import asynccontextmanager


class Administration:
    def __init__(self):
        self.owner=None
        self.operation=None
        self.depth=0

    @staticmethod
    def _task():
        try: return asyncio.current_task()
        except RuntimeError: return None

    @property
    def busy(self): return self.owner is not None

    def ensure_mutation_allowed(self):
        if self.busy and self.owner is not self._task():
            from server.app.store import ConflictError
            raise ConflictError('Административная операция выполняется. Повторите позже.')

    @asynccontextmanager
    async def exclusive(self,operation):
        self.ensure_mutation_allowed()
        task=self._task()
        if task is None: raise RuntimeError('Administrative operation requires an asyncio Task')
        if not self.busy: self.owner,self.operation=task,operation
        self.depth+=1
        try: yield self
        finally:
            self.depth-=1
            if not self.depth: self.owner=self.operation=None
