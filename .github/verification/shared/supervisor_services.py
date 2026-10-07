"""Optional Supervisor MQTT service without exposing credentials."""
from dataclasses import dataclass, field
import json
import re
from aiohttp import ClientSession, ClientTimeout


@dataclass(frozen=True)
class MqttService:
    host: str
    port: int
    username: str = field(repr=False)
    password: str = field(repr=False)
    ssl: bool = False


def parse_service(data):
    if not isinstance(data,dict): raise ValueError('Invalid MQTT service')
    host,port=data.get('host'),data.get('port')
    if not isinstance(host,str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,253}',host) or type(port) is not int or not 1<=port<=65535:
        raise ValueError('Invalid MQTT endpoint')
    for name in ('username','password'):
        if not isinstance(data.get(name),str) or not 1<=len(data[name])<=1024: raise ValueError('Invalid MQTT credential')
    if type(data.get('ssl',False)) is not bool: raise ValueError('Invalid MQTT TLS configuration')
    return MqttService(host,port,data['username'],data['password'],data.get('ssl',False))


async def mqtt_service(token):
    if not token: return None
    async with ClientSession(timeout=ClientTimeout(total=5),trust_env=False) as session:
        async with session.get('http://supervisor/services/mqtt',headers={'Authorization':'Bearer '+token},allow_redirects=False) as response:
            if response.status in (400,404): return None
            if response.status!=200: raise ValueError('MQTT service unavailable')
            raw=bytearray()
            async for chunk in response.content.iter_chunked(8192):
                raw.extend(chunk)
                if len(raw)>8192: raise ValueError('MQTT service response too large')
    payload=json.loads(raw)
    if not isinstance(payload,dict) or payload.get('result')!='ok': raise ValueError('MQTT service unavailable')
    return parse_service(payload.get('data'))
