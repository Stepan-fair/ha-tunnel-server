import asyncio
import os
from aiohttp import ClientSession, ClientTimeout, ClientError, ClientConnectionError, WSMsgType
from client.app.enrollment import read_json

CORE_ORIGIN='http://127.0.0.1:8123'
CORE_WEBSOCKET='ws://supervisor/core/websocket'


class CoreCommandError(ValueError):
    def __init__(self, code):
        self.code=code
        super().__init__('Home Assistant отклонил настройку HTTP. Проверьте доступ приложения к Core API.')


async def receive_core(ws):
    msg=await ws.receive()
    if msg.type in (WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.CLOSING,WSMsgType.ERROR):
        raise ClientConnectionError('Core WebSocket disconnected')
    if msg.type!=WSMsgType.TEXT:
        raise CoreCommandError('protocol')
    value=msg.json()
    if not isinstance(value,dict):
        raise CoreCommandError('protocol')
    return value


class Supervisor:
    async def http_command(self, kind, **data):
        credential=os.environ.get('SUPERVISOR_TOKEN')
        if not credential:
            raise ValueError('Нет доступа к Supervisor.')
        async with ClientSession(timeout=ClientTimeout(total=30),trust_env=False) as session:
            async with session.ws_connect(CORE_WEBSOCKET,
                    headers={'Authorization':'Bearer '+credential},max_msg_size=65536) as ws:
                async with asyncio.timeout(30):
                    if (await receive_core(ws)).get('type')!='auth_required':
                        raise CoreCommandError('protocol')
                    await ws.send_json({'type':'auth','access_token':credential})
                    if (await receive_core(ws)).get('type')!='auth_ok':
                        raise CoreCommandError('auth')
                    await ws.send_json({'id':1,'type':kind,**data})
                    result=await receive_core(ws)
                    if result.get('id')!=1 or result.get('type')!='result':
                        raise CoreCommandError('protocol')
                    if not result.get('success'):
                        raise CoreCommandError(result.get('error',{}).get('code'))
                    return result.get('result')

    async def get_http_config(self):
        try:
            return await self.http_command('http/config')
        except CoreCommandError as exc:
            if exc.code=='unknown_command':
                return None
            raise

    async def _post(self, route):
        credential=os.environ.get('SUPERVISOR_TOKEN')
        if not credential:
            raise ValueError('Нет доступа к Supervisor. Запустите приложение внутри HA OS.')
        async with ClientSession(timeout=ClientTimeout(total=180),trust_env=False) as session:
            async with session.post('http://supervisor/core/'+route,
                    headers={'Authorization':'Bearer '+credential},allow_redirects=False) as response:
                if response.status!=200:
                    return False
                data=await read_json(response)
                return isinstance(data,dict) and data.get('result')=='ok'

    async def check_config(self):
        return await self._post('check')

    async def restart_core(self):
        if not await self._post('restart'):
            raise ValueError('Supervisor не подтвердил перезапуск HA. Проверьте состояние в настройках системы.')

    async def wait_proxy_ready(self, timeout=180):
        deadline=asyncio.get_running_loop().time()+timeout
        async with ClientSession(timeout=ClientTimeout(total=5),trust_env=False) as session:
            while asyncio.get_running_loop().time()<deadline:
                try:
                    # The frontend is public but still passes through the forwarded
                    # middleware. Avoid protected API probes that count as failed logins.
                    async with session.get(CORE_ORIGIN+'/',allow_redirects=False,
                            headers={'X-Forwarded-For':'192.0.2.1','X-Forwarded-Proto':'https'}) as response:
                        if response.status==200:
                            return
                except (ClientError,TimeoutError):
                    pass
                await asyncio.sleep(2)
        raise TimeoutError('Home Assistant пока не принимает запросы через прокси. Публикация не запущена.')
