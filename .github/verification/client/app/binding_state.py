"""The sole authoritative Client state, preserving ambiguous operations."""
from dataclasses import dataclass
import json
from pathlib import Path
import re

from shared.files import atomic_write
from shared.protocol import Invitation
from shared.validation import origin,token

MAX_STATE_BYTES=65536


class StateProblem(ValueError):
    """Local state must be repaired without silently issuing a new identity."""


@dataclass
class BindingState:
    active: dict | None = None
    pending_operation: dict | None = None
    error: str | None = None


def credentials(value):
    from client.app.enrollment import validate_response
    if value is None: return None
    return validate_response(value,Invitation(origin(value['server_url']),''))


def pending(value):
    if value is None: return None
    required={'operation_id','secret','server_url','code','expected_client_id','binding_secret','stage','candidate','server_instance_id','generation'}
    if not isinstance(value,dict) or set(value)!=required: raise ValueError('Invalid pending structure')
    if not isinstance(value['operation_id'],str) or not re.fullmatch('[a-f0-9]{32}',value['operation_id']): raise ValueError()
    token(value['secret']); token(value['code']); origin(value['server_url'])
    if value['stage'] not in ('prepare','prepared','commit_unknown'): raise ValueError()
    if value['binding_secret'] is not None: token(value['binding_secret'])
    if value['expected_client_id'] is not None and not re.fullmatch('[a-f0-9]{32}',value['expected_client_id']): raise ValueError()
    candidate=credentials(value['candidate'])
    if candidate is not None:
        if candidate['secret']!=value['secret'] or candidate['server_url']!=value['server_url']: raise ValueError()
        if value['expected_client_id'] is not None and candidate['client_id']!=value['expected_client_id']: raise ValueError()
        if not isinstance(value['server_instance_id'],str) or not re.fullmatch('[a-f0-9]{32}',value['server_instance_id']): raise ValueError()
        if type(value['generation']) is not int or value['generation']<0: raise ValueError()
    elif value['stage']!='prepare': raise ValueError()
    return value


class StateFile:
    def __init__(self,directory):
        self.directory=Path(directory)
        self.path=self.directory/'credentials.json'

    def load(self):
        if not self.path.exists(): return BindingState()
        try:
            with self.path.open('rb') as stream: raw=stream.read(MAX_STATE_BYTES+1)
            if len(raw)>MAX_STATE_BYTES: raise ValueError()
            data=json.loads(raw)
            if not isinstance(data,dict): raise ValueError()
            if 'schema' not in data:
                state=BindingState(credentials(data))
                try: self.save(state)
                except OSError:
                    state.error='Не удалось сохранить обновлённый формат привязки. Прежние данные сохранены; проверьте локальное хранилище.'
                return state
            if type(data['schema']) is not int or data['schema']!=2 or set(data)!={'schema','active','pending_operation'}: raise ValueError()
            active=credentials(data['active'])
        except (ValueError,TypeError,KeyError,OSError) as exc:
            raise StateProblem('Локальные данные подключения повреждены или недоступны. Исходный файл сохранён; требуется восстановление данных.') from exc
        try: operation=pending(data['pending_operation'])
        except (ValueError,TypeError,KeyError):
            return BindingState(active,error='Незавершённая привязка повреждена. Новая выдача заблокирована; исходные данные сохранены.')
        return BindingState(active,operation)

    def save(self,state):
        if state.error: raise StateProblem(state.error)
        credentials(state.active); pending(state.pending_operation)
        raw=json.dumps({'schema':2,'active':state.active,'pending_operation':state.pending_operation},separators=(',',':')).encode()
        if len(raw)>MAX_STATE_BYTES: raise StateProblem('Локальные данные превышают допустимый размер.')
        atomic_write(self.path,raw)

    def materialize_ca(self,active):
        if active is not None: atomic_write(self.directory/'ca.pem',active['ca_pem'].encode())
