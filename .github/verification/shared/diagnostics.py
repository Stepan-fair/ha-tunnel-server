"""Bounded diagnostic records: arbitrary messages, requests and secrets never enter sinks."""
from collections import deque
from datetime import datetime, timezone
import errno
import json
import logging.handlers
import math
from pathlib import Path
import re
import secrets
import sys
import threading
import time
import traceback

CODES = frozenset(('startup','startup_error','phase','running','shutdown','unclean_start',
    'storage_error','cleanup_error','discovery_error','service_error','process_exit',
    'process_output','process_start','process_verify','process_restart','http_error',
    'logging_unavailable','clock_error','component_state','migration','invalid_event'))
COMPONENTS = frozenset(('server','setup','storage','privileges','clock','frp','gateway',
    'npm','http','relay','mqtt','telemetry','pki'))
LEVELS = frozenset(('INFO','WARNING','ERROR','CRITICAL'))
REASONS = frozenset(('address_in_use','permission_denied','disk_full','file_missing',
    'connection_refused','timed_out','invalid_configuration','configuration_rejected',
    'certificate_error','database_error','output_suppressed','authentication_failed',
    'unexpected_exit','unavailable','interrupted','invalid_time'))
NUMBERS = frozenset(('exit_code','signal','errno','sqlite_errorcode','status','count',
    'suppressed','repeat','free_bytes','port','line'))
PHASES = frozenset(('prepare_privileges','load_options','discovery','validate_options','resolve_npm',
    'prepare_pki','open_database','check_clock','start_listeners','start_frp','start_telemetry',
    'start_gateway','operational','cleanup'))
STATES = frozenset(('running','stopped','error','unknown','healthy','unhealthy'))
CURSOR = re.compile(r'[a-f0-9]{32}')


class RaisingRotation(logging.handlers.RotatingFileHandler):
    def handleError(self, record):
        # The caller emits a safe fallback instead of logging's raw handler traceback.
        raise OSError('Diagnostic storage unavailable')


def _fields(fields):
    result = {}
    for name, value in (fields or {}).items():
        if name in NUMBERS and type(value) is int and -(2**63) <= value < 2**63:
            result[name] = value
        elif name == 'phase' and isinstance(value,str) and value in PHASES:
            result[name] = value
        elif name == 'reason' and isinstance(value,str) and value in REASONS:
            result[name] = value
        elif name == 'state' and isinstance(value,str) and value in STATES:
            result[name] = value
        elif name == 'method' and value in ('GET','HEAD','POST','PUT','DELETE','OPTIONS','PATCH'):
            result[name] = value
        elif name in ('client_id','operation_id','request_id','episode_id') and isinstance(value,str) and re.fullmatch('[a-f0-9]{16,64}',value):
            result[name] = value
        elif name == 'version' and isinstance(value,str) and re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',value):
            result[name] = value
        elif name == 'route' and value in ('/health','/v1/enroll','/v1/token','/v1/client/status',
                '/api/state','/api/setup','/api/diagnostics','/api/diagnostics/export',
                '/api/clients','/api/clients/{id}/access','/api/clients/{id}/billing',
                '/api/domain-migration/preview','/api/domain-migration/apply','unknown'):
            result[name] = value
    return result


def _reason(error):
    known={'Gateway process stopped':'unexpected_exit','Background service stopped':'unexpected_exit',
        'FRP configuration rejected':'configuration_rejected','Incomplete CA; restore saved identity':'certificate_error',
        'CA identity mismatch':'certificate_error','Leaf identity mismatch':'certificate_error'}
    if type(error) in (RuntimeError,ValueError) and len(error.args)==1 and isinstance(error.args[0],str) and error.args[0] in known:
        return known[error.args[0]]
    number = getattr(error,'errno',None) if isinstance(error,OSError) else None
    if number in (errno.EACCES,errno.EPERM): return 'permission_denied'
    if number == errno.ENOSPC: return 'disk_full'
    if number == errno.ENOENT: return 'file_missing'
    if number == errno.EADDRINUSE: return 'address_in_use'
    if number == errno.ECONNREFUSED: return 'connection_refused'
    if isinstance(error,TimeoutError): return 'timed_out'
    if type(error).__module__ == 'sqlite3': return 'database_error'
    if isinstance(error,(ValueError,TypeError,KeyError)): return 'invalid_configuration'
    return 'unavailable'


def safe_error(error):
    causes, seen = [], set()
    while error is not None and id(error) not in seen and len(causes)<8:
        seen.add(id(error))
        module = type(error).__module__
        name = type(error).__name__ if module in ('builtins','sqlite3','ssl','socket','json.decoder') else 'ApplicationError'
        frames = []
        for frame, line in traceback.walk_tb(error.__traceback__):
            # File basename and code location only: no full machine paths, source or locals.
            frames.append({'file':Path(frame.f_code.co_filename).name[:128],
                           'function':frame.f_code.co_name[:128], 'line':line})
        item = {'type':name, 'reason':_reason(error), 'frames':frames[-20:]}
        for key in ('errno','sqlite_errorcode'):
            value = getattr(error,key,None)
            if type(value) is int: item[key] = value
        if isinstance(error,ModuleNotFoundError) and isinstance(error.name,str) and re.fullmatch('[a-zA-Z0-9_.]{1,128}',error.name):
            item['module'] = error.name
        causes.append(item)
        error = error.__cause__ or (error.__context__ if not error.__suppress_context__ else None)
    return {'causes':causes}


class Diagnostics:
    def __init__(self, directory, *, max_bytes=2097152, file_count=5):
        if type(max_bytes) is not int or not 512 <= max_bytes <= 2097152 or type(file_count) is not int or not 1 <= file_count <= 5:
            raise ValueError('Invalid diagnostic bounds')
        self.directory = None
        self.max_bytes, self.file_count = max_bytes,file_count
        self.run_id = secrets.token_hex(8)
        self.sequence = 0
        self.handler = None
        self.last_failure = None
        self.primary_set = False
        self.previous_unclean = False
        self.components = {}
        self.memory = deque(maxlen=100)
        self.lock = threading.RLock()
        self.repeats = {}
        self.storage_failed = False
        self.active_phase = 'load_options'
        self.active_component = 'server'
        if directory is not None: self.attach(directory)
        self.event('startup',component='server')

    def _console(self, record):
        try:
            print(json.dumps(record,ensure_ascii=True,separators=(',',':')),flush=True)
        except (OSError,ValueError): pass

    def attach(self, directory):
        self.directory = Path(directory)
        try:
            if self.directory.is_symlink(): raise ValueError('Unsafe diagnostic directory')
            self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
            self.directory.chmod(0o700)
            for name in ('events.jsonl','failure.json','run.json'):
                if (self.directory/name).is_symlink(): raise ValueError('Unsafe diagnostic file')
            try:
                previous = json.loads((self.directory/'run.json').read_text())
                self.previous_unclean = previous.get('shutdown') is not True
            except (OSError,ValueError,AttributeError): pass
            try:
                self.last_failure = self._read_record(json.loads((self.directory/'failure.json').read_text()))
            except (OSError,ValueError): pass
            self.handler = RaisingRotation(self.directory/'events.jsonl',maxBytes=self.max_bytes,
                backupCount=self.file_count-1,encoding='utf-8')
            self.handler.setFormatter(logging.Formatter('%(message)s'))
            (self.directory/'events.jsonl').chmod(0o600)
            self._marker(False)
            if self.previous_unclean: self.event('unclean_start',component='server',level='WARNING')
        except (OSError,ValueError):
            self.handler = None
            self._storage_problem()

    def _storage_problem(self):
        if not self.storage_failed:
            self.storage_failed = True
            self._console({'code':'logging_unavailable','component':'storage','level':'ERROR',
                'run_id':self.run_id,'at':time.time()})

    def _save(self, name, value):
        if self.directory is None: return
        try:
            from shared.files import atomic_write
            atomic_write(self.directory/name,json.dumps(value,separators=(',',':')).encode())
        except (OSError,ValueError): self._storage_problem()

    def _marker(self, shutdown):
        self._save('run.json',{'run_id':self.run_id,'at':time.time(),'shutdown':shutdown})

    def _write(self, record):
        encoded = json.dumps(record,ensure_ascii=True,separators=(',',':'))
        if len(encoded.encode()) + 1 > min(8192,self.max_bytes):
            record = dict(record)
            if 'error' in record:
                record['error']={'causes':[dict(c,frames=[]) for c in record['error']['causes'][:2]]}
            encoded = json.dumps(record,ensure_ascii=True,separators=(',',':'))
        self.memory.append(record)
        self._console(record)
        if self.handler:
            try:
                self.handler.emit(logging.LogRecord('ha-tunnel',logging.INFO,'',0,encoded,(),None))
                self.handler.flush()
            except (OSError,ValueError):
                self._storage_problem()
        return record

    def event(self, code, *, component, level='INFO', fields=None, _error=None):
        with self.lock:
            if code not in CODES or component not in COMPONENTS: code,component='invalid_event','server'
            if level not in LEVELS: level='INFO'
            selected=_fields(fields)
            if code in ('process_output','http_error','discovery_error','storage_error','component_state'):
                key=(code,component,level,json.dumps(selected,sort_keys=True))
                now=time.monotonic()
                if key in self.repeats and now-self.repeats[key]<30: return None
                if len(self.repeats)>=128: self.repeats.clear()
                self.repeats[key]=now
            self.sequence+=1
            record={'id':self.run_id+format(self.sequence,'016x'),'run_id':self.run_id,
                'at':time.time(),'time':datetime.now(timezone.utc).isoformat(),
                'code':code,'component':component,'level':level,'fields':selected}
            if _error is not None: record['error']=_error
            return self._write(record)

    def phase(self, name, component='server'):
        if name in PHASES and component in COMPONENTS:
            self.active_phase,self.active_component=name,component
            self.event('phase',component=component,fields={'phase':name})

    def failure(self, code, error, *, component, fatal=True):
        record = self.event(code,component=component,level='CRITICAL' if fatal else 'ERROR',
            fields={'phase':self.active_phase},_error=safe_error(error))
        if fatal and not self.primary_set and record is not None:
            self.primary_set=True
            self.last_failure=record
            self._save('failure.json',record)

    def install_loop(self, loop):
        def failure(loop,context):
            error=context.get('exception')
            if isinstance(error,BaseException): self.failure('service_error',error,component='server')
            else: self.event('service_error',component='server',level='ERROR',fields={'reason':'unexpected_exit'})
        loop.set_exception_handler(failure)

    def observe(self, task, component):
        def completed(done):
            if done.cancelled(): return
            error=done.exception()
            if error is not None: self.failure('service_error',error,component=component)
            else: self.event('service_error',component=component,level='WARNING',fields={'reason':'unexpected_exit'})
        task.add_done_callback(completed)

    def component(self, name, state, *, exit_code=None):
        if name not in COMPONENTS or state not in STATES: return
        value={'state':state,'exit_code':exit_code if type(exit_code) is int else None}
        if self.components.get(name)!=value:
            self.components[name]=value
            self.event('component_state',component=name,fields=value)

    def shutdown(self):
        self.event('shutdown',component='server')
        self._marker(True)
        if self.handler: self.handler.close(); self.handler=None

    def snapshot(self):
        return {'run_id':self.run_id,'last_failure':self.last_failure,
                'previous_unclean':self.previous_unclean,'storage_available':self.handler is not None,
                'components':dict(self.components),'max_bytes':self.max_bytes,'file_count':self.file_count}

    @staticmethod
    def _read_record(row):
        if not isinstance(row,dict) or row.get('code') not in CODES or row.get('component') not in COMPONENTS or row.get('level') not in LEVELS:
            raise ValueError('Invalid diagnostic record')
        if not isinstance(row.get('id'),str) or not CURSOR.fullmatch(row['id']): raise ValueError()
        if type(row.get('at')) not in (int,float) or not math.isfinite(row['at']): raise ValueError()
        # Records are already sanitized at creation. Exact schema rejects injected fields.
        if set(row)-{'id','run_id','at','time','code','component','level','fields','error'}: raise ValueError()
        row=dict(row); row['fields']=_fields(row.get('fields'))
        return row

    def _records(self):
        if self.handler is None: return list(reversed(self.memory))
        records=[]
        for suffix in range(self.file_count-1,-1,-1):
            path=self.directory/('events.jsonl'+('.'+str(suffix) if suffix else ''))
            if path.is_symlink(): continue
            try:
                with path.open('rb') as stream:
                    remaining=self.max_bytes
                    while remaining>0:
                        raw=stream.readline(min(8193,remaining)); remaining-=len(raw)
                        if not raw: break
                        if len(raw)>8192 or not raw.endswith(b'\n'): continue
                        try: records.append(self._read_record(json.loads(raw)))
                        except (ValueError,TypeError): continue
            except OSError: continue
        return list(reversed(records))

    def page(self, *, before=None, limit=100, level=None, component=None, since=None, until=None):
        if type(limit) is not int or not 1<=limit<=1000: raise ValueError()
        if before is not None and (not isinstance(before,str) or not CURSOR.fullmatch(before)): raise ValueError()
        if level is not None and level not in LEVELS or component is not None and component not in COMPONENTS: raise ValueError()
        for value in (since,until):
            if value is not None and (type(value) not in (int,float) or not math.isfinite(value)): raise ValueError()
        if since is not None and until is not None and since>until: raise ValueError()
        rows=self._records()
        if before is not None:
            indices=[i for i,r in enumerate(rows) if r['id']==before]
            rows=rows[indices[0]+1:] if indices else []
        selected=[]
        for row in rows:
            if level and row['level']!=level or component and row['component']!=component: continue
            if since is not None and row['at']<since or until is not None and row['at']>until: continue
            selected.append(row)
            if len(selected)>limit: break
        return {'items':selected[:limit],'next_cursor':selected[limit-1]['id'] if len(selected)>limit else None}

    def export(self, **filters):
        # One bounded snapshot: rotation during download cannot duplicate or skip pages.
        self.page(limit=1,**filters)
        for row in reversed(self._records()):
            if filters.get('level') and row['level']!=filters['level']: continue
            if filters.get('component') and row['component']!=filters['component']: continue
            if filters.get('since') is not None and row['at']<filters['since']: continue
            if filters.get('until') is not None and row['at']>filters['until']: continue
            yield (json.dumps(row,ensure_ascii=True,separators=(',',':'))+'\n').encode()
