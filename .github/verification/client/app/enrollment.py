import json
import re
from urllib.parse import urlsplit

from aiohttp import ClientTimeout, encode_basic_auth
from shared.dns import session as ClientSession
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from shared.protocol import Invitation
from shared.validation import domain, origin, token
from client.app.ha_config import ConfigProblem

FIELDS={'protocol','client_id','secret','domain','server_url','tunnel_host','tunnel_port','ca_pem'}


class EnrollmentProblem(ConfigProblem):
    """Safe local enrollment message; the existing connection can keep running."""


async def read_json(response):
    raw=bytearray()
    async for chunk in response.content.iter_chunked(8192):
        raw.extend(chunk)
        if len(raw)>32768:
            raise ValueError('Server response too large')
    return json.loads(raw)


async def post_json(session,url,**kwargs):
    async with session.post(url,allow_redirects=False,**kwargs) as response:
        if response.status!=200:
            # Map a bounded, known error code to our own text; never echo a server body.
            if response.status in (400,409):
                try: problem=await read_json(response)
                except (ValueError, TypeError): problem=None
                messages={
                    'domain_bound':'Домен уже привязан к другому Home Assistant. Обычный код не переносит адрес. Используйте прежний Client или оформите перенос на Server.',
                    'binding_conflict':'Подготовка привязки изменилась или уже занята другой операцией. Дождитесь проверки состояния на Server.',
                    'wrong_connection':'Код относится к другому подключению. Прежняя привязка сохранена. Проверьте выбранный домен на Server.'}
                if isinstance(problem,dict) and problem.get('error') in messages:
                    raise EnrollmentProblem(messages[problem['error']])
                raise EnrollmentProblem('Код недействителен, уже использован или истёк. Получите новый код нужного подключения на Server.')
            raise ValueError('Сервер отклонил запрос. Проверьте срок действия кода и адрес сервера.')
        return await read_json(response)


def validate_response(data, invitation):
    if not isinstance(data,dict) or set(data)!=FIELDS or type(data['protocol']) is not int or data['protocol']!=1:
        raise ValueError('Unsupported enrollment response')
    host=urlsplit(invitation.server).hostname
    if (origin(data['server_url'])!=invitation.server or domain(data['tunnel_host'])!=host or
            type(data['tunnel_port']) is not int or not 1<=data['tunnel_port']<=65535):
        raise ValueError('Server identity mismatch')
    if not isinstance(data['client_id'],str) or not re.fullmatch('[a-f0-9]{32}',data['client_id']):
        raise ValueError('Invalid client identity')
    token(data['secret'])
    assigned=domain(data['domain'])
    if assigned.split('.')[1:]!=host.split('.')[1:] or assigned==host:
        raise ValueError('Unexpected client domain')
    pem=data['ca_pem']
    if not isinstance(pem,str) or len(pem)>8192 or 'PRIVATE' in pem:
        raise ValueError('Expected public CA only')
    try:
        certificates=x509.load_pem_x509_certificates(pem.encode())
        if len(certificates)!=1 or not certificates[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('Expected one CA certificate')
    except (x509.ExtensionNotFound,x509.DuplicateExtension,UnsupportedAlgorithm) as exc:
        raise ValueError('Invalid CA certificate') from exc
    return data


async def enroll(invitation, *, directory=None, expected_client_id=None, expected_server_url=None, binding_secret=None, before_commit=None):
    try: parsed=Invitation.parse(invitation)
    except ValueError: raise EnrollmentProblem('Некорректный код подключения.') from None
    if expected_server_url is not None and parsed.server!=expected_server_url:
        raise EnrollmentProblem('Код выдан другим Server.')
    if directory is None: raise EnrollmentProblem('Для безопасной выдачи требуется локальное хранилище Client.')
    return await BindingClient(directory).enroll(invitation,expected_client_id=expected_client_id,
        expected_server_url=expected_server_url,binding_secret=binding_secret,before_commit=before_commit)


def save_credentials(directory, data):
    from client.app.binding_state import StateFile,BindingState
    file=StateFile(directory)
    state=file.load()
    if state.error or state.pending_operation: raise ValueError('Unresolved binding operation')
    file.save(BindingState(data))
    file.materialize_ca(data)


def load_credentials(directory):
    from client.app.binding_state import StateFile
    return StateFile(directory).load().active

class BindingClient:
    """Persist intent and the complete candidate before committing remotely."""
    def __init__(self,directory):
        from client.app.binding_state import StateFile
        self.file=StateFile(directory)

    async def enroll(self,invitation,*,expected_client_id=None,expected_server_url=None,binding_secret=None,before_commit=None):
        import secrets
        from client.app.binding_state import StateProblem
        try: invitation=Invitation.parse(invitation)
        except ValueError: raise EnrollmentProblem('Некорректный код подключения.') from None
        if expected_server_url is not None and invitation.server!=expected_server_url:
            raise EnrollmentProblem('Код выдан другим Server. Используйте код текущего подключения.')
        state=self.file.load()
        if state.error or state.pending_operation: raise StateProblem(state.error or 'Незавершённая привязка требует восстановления.')
        async with ClientSession(timeout=ClientTimeout(total=30),trust_env=False) as session:
            async with session.get(invitation.server+'/health',allow_redirects=False) as response:
                if response.status!=200: raise ValueError('Server unavailable')
                health=await read_json(response)
            if not isinstance(health,dict) or health.get('protocol')!=1 or health.get('status')!='ok' or 'enrollment-v2' not in health.get('capabilities',[]):
                raise EnrollmentProblem('Для безопасной выдачи обновите Server до версии с enrollment-v2.')
        state.pending_operation=dict(operation_id=secrets.token_hex(16),secret=secrets.token_urlsafe(32),
            server_url=invitation.server,code=invitation.code,expected_client_id=expected_client_id,binding_secret=binding_secret,
            stage='prepare',candidate=None,server_instance_id=None,generation=None)
        self.file.save(state)
        return await self.recover(before_commit=before_commit)

    def _identity(self,result,operation):
        if (not isinstance(result,dict) or result.get('operation_id')!=operation['operation_id'] or
            result.get('client_id')!=operation['candidate']['client_id'] or result.get('domain')!=operation['candidate']['domain'] or
            result.get('generation')!=operation['generation'] or result.get('server_instance_id')!=operation['server_instance_id']):
            raise ValueError('Binding identity mismatch')

    async def recover(self,*,before_commit=None):
        from client.app.binding_state import StateProblem
        from client.app.status import validate_status,CredentialsRejected
        state=self.file.load()
        if state.error: raise StateProblem(state.error)
        op=state.pending_operation
        if op is None: return state.active
        async with ClientSession(timeout=ClientTimeout(total=30),trust_env=False) as session:
            if op['stage']=='prepare':
                payload={k:op[k] for k in ('operation_id','secret','code')}
                headers={}
                if op['expected_client_id'] is not None: payload['expected_client_id']=op['expected_client_id']
                if op['binding_secret'] is not None: headers['Authorization']=encode_basic_auth(op['expected_client_id'],op['binding_secret'])
                try:
                    result=await post_json(session,op['server_url']+'/v2/enroll/prepare',json=payload,headers=headers)
                except EnrollmentProblem:
                    # No commit has ever been sent from this durable stage.
                    state.pending_operation=None; self.file.save(state)
                    raise
                if result.get('state')!='prepared':
                    if result.get('state') in ('expired','cancelled','superseded'):
                        state.pending_operation=None; self.file.save(state)
                        raise EnrollmentProblem('Подготовка привязки отменена или истекла. Прежняя привязка сохранена.')
                    raise ValueError('Unexpected prepare state')
                candidate=validate_response(result['credentials'],Invitation(op['server_url'],op['code']))
                if candidate['secret']!=op['secret'] or result.get('client_id')!=candidate['client_id'] or result.get('domain')!=candidate['domain']:
                    raise ValueError('Unexpected candidate')
                if op['expected_client_id'] is not None:
                    if candidate['client_id']!=op['expected_client_id'] or (state.active and any(candidate[k]!=state.active[k] for k in ('domain','server_url','ca_pem'))):
                        raise EnrollmentProblem('Кандидат не соответствует прежнему подключению. Привязка сохранена.')
                op.update(candidate=candidate,server_instance_id=result.get('server_instance_id'),generation=result.get('generation'),stage='prepared')
                self.file.save(state)
            headers={'Authorization':encode_basic_auth(op['candidate']['client_id'],op['secret'])}
            payload={'operation_id':op['operation_id']}
            async with session.post(op['server_url']+'/v2/enroll/status',allow_redirects=False,json=payload,headers=headers) as response:
                if response.status==200:
                    result=await read_json(response)
                    self._identity(result,op)
                elif response.status==400:
                    # Replay retention elapsed. Only authenticated current identity can prove commit.
                    async with session.post(op['server_url']+'/v1/client/status',allow_redirects=False,
                        json={'capabilities':['access-v1','telemetry-v1']},headers=headers) as status:
                        if status.status in (401,403):
                            state.pending_operation=None
                            self.file.save(state)
                            raise CredentialsRejected('Binding superseded or uncommitted')
                        if status.status!=200: raise ValueError('Recovery status unavailable')
                        current=validate_status(await read_json(status),op['candidate']['client_id'])
                    result={**current,'operation_id':op['operation_id'],'state':'committed','current_state':current['access_state']}
                    self._identity(result,op)
                else: raise ValueError('Recovery status unavailable')
            if result['state']=='prepared':
                if before_commit is not None: await before_commit()
                from client.app.controller import verify_tunnel_tls
                await verify_tunnel_tls(op['candidate'])
                # The candidate CA must be writable without replacing the active runtime CA.
                from client.app.binding_state import atomic_write as durable_write
                durable_write(self.file.directory/'candidate-ca.pem',op['candidate']['ca_pem'].encode())
                op['stage']='commit_unknown'
                self.file.save(state)
                result=await post_json(session,op['server_url']+'/v2/enroll/commit',json=payload,headers=headers)
                self._identity(result,op)
            if result['state']!='committed':
                if result['state'] in ('expired','cancelled','superseded'):
                    state.pending_operation=None; self.file.save(state)
                    raise EnrollmentProblem('Привязка отменена или заменена. Прежние локальные данные сохранены.')
                raise ValueError('Unexpected commit state')
            # Keep the complete pending proof until both active and derived CA are durable.
            state.active=op['candidate']
            self.file.save(state)
            self.file.materialize_ca(state.active)
            state.pending_operation=None
            self.file.save(state)
            return state.active

    async def cancel(self):
        from client.app.binding_state import StateProblem
        state=self.file.load(); op=state.pending_operation
        if state.error: raise StateProblem(state.error)
        if op is None: return state.active
        if op['candidate'] is None:
            # Recover prepare first, so cancellation has a verified Client identity.
            raise StateProblem('Дождитесь ответа Server на подготовку привязки.')
        async with ClientSession(timeout=ClientTimeout(total=30),trust_env=False) as session:
            result=await post_json(session,op['server_url']+'/v2/enroll/cancel',json={'operation_id':op['operation_id']},
                headers={'Authorization':encode_basic_auth(op['candidate']['client_id'],op['secret'])})
        self._identity(result,op)
        if result['state']=='committed': return await self.recover()
        if result['state'] not in ('cancelled','expired','superseded'): raise ValueError('Cancellation not confirmed')
        state.pending_operation=None; self.file.save(state)
        return state.active
