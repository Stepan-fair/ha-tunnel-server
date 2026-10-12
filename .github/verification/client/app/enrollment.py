import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout, encode_basic_auth
from cryptography import x509
from shared.files import atomic_write
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
    certificates=x509.load_pem_x509_certificates(pem.encode())
    if len(certificates)!=1 or not certificates[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError('Expected one CA certificate')
    return data


async def enroll(invitation, *, expected_client_id=None, expected_server_url=None, binding_secret=None):
    try: invitation=Invitation.parse(invitation)
    except ValueError: raise EnrollmentProblem('Некорректный код подключения. Скопируйте его целиком из панели Server.') from None
    if expected_server_url is not None and invitation.server != expected_server_url:
        raise EnrollmentProblem('Код выдан другим Server. Используйте код текущего подключения или «Другое подключение».')
    payload={'code':invitation.code}
    if expected_client_id is not None: payload['expected_client_id']=expected_client_id
    headers={}
    if binding_secret is not None:
        if expected_client_id is None: raise ValueError('Missing binding identity')
        headers['Authorization']=encode_basic_auth(expected_client_id,token(binding_secret))
    async with ClientSession(timeout=ClientTimeout(total=30),trust_env=False) as session:
        data=await post_json(session,invitation.server+'/v1/enroll',json=payload,headers=headers)
    return validate_response(data,invitation)


def save_credentials(directory, data):
    directory=Path(directory)
    atomic_write(directory/'credentials.json',json.dumps(data,separators=(',',':')).encode())
    atomic_write(directory/'ca.pem',data['ca_pem'].encode())


def load_credentials(directory):
    path=Path(directory)/'credentials.json'
    if not path.exists():
        return None
    data=json.loads(path.read_bytes())
    return validate_response(data,Invitation(origin(data['server_url']),''))
