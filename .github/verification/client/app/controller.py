import asyncio
import base64
import secrets
import ssl
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout, ClientError, ClientConnectorCertificateError
from client.app.enrollment import enroll, load_credentials, save_credentials, read_json
from client.app.ha_config import ConfigProblem
from client.app.http_config import (preview_http, configure_http, check_http_ready,
                                    finish_http_trial, HTTPConfirmationRequired)
from client.app.runtime import client_config
from client.app.status import ClientStatusClient
from shared.telemetry import parse_telemetry,age_telemetry


def basic(username,password):
    return 'Basic '+base64.b64encode((username+':'+password).encode()).decode()


async def verify_tunnel_tls(credentials):
    context=ssl.create_default_context(cadata=credentials['ca_pem'])
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    _,writer=await asyncio.wait_for(asyncio.open_connection(
        credentials['tunnel_host'],credentials['tunnel_port'],ssl=context,
        server_hostname=credentials['tunnel_host'],ssl_handshake_timeout=5,
        happy_eyeballs_delay=0.25,interleave=1),timeout=7)
    writer.close()
    await asyncio.wait_for(writer.wait_closed(),timeout=3)


async def proxy_running(url,password,client_id):
    async with ClientSession(timeout=ClientTimeout(total=5),trust_env=False) as session:
        async with session.get(url,headers={'Authorization':basic('local',password)},allow_redirects=False) as response:
            if response.status!=200:
                return False
            data=await read_json(response)
            return any(p.get('name')=='ha' and p.get('status')=='running'
                       for p in data.get('http',[]))


class Controller:
    def __init__(self,directory,config_path,runtime,supervisor):
        self.directory=Path(directory)
        self.config_path=Path(config_path)
        self.runtime=runtime
        self.supervisor=supervisor
        self.credentials=load_credentials(self.directory)
        self.state='disconnected'
        self.message='Не подключён'
        self.lock=asyncio.Lock()
        self.dashboard_password=secrets.token_urlsafe(32)
        self.retry_at=0
        self.retry_delay=2
        self.pending_path=self.directory/'ha-config.pending'
        self.server_access=None
        self.telemetry=None
        self.status_received=None
        self.billing_stale=True
        self.mqtt=None

    def status(self):
        return {'state':self.state,'message':self.message,'configured':self.credentials is not None,
                'domain':self.credentials['domain'] if self.credentials else None,
                'busy':self.lock.locked(),'access':self.server_access,
                'billing_stale':self.billing_stale or self.status_received is None or asyncio.get_running_loop().time()-self.status_received>45,
                'telemetry':age_telemetry(self.telemetry,asyncio.get_running_loop().time()) if self.telemetry else None,
                'mqtt':self.mqtt.status() if self.mqtt else {'state':'not_configured'}}

    def set_state(self,state,message):
        self.state,self.message=state,message

    async def connect(self,invitation):
        if invitation and self.credentials and self.state=='revoked':
            return await self.rebind(invitation)
        async with self.lock:
            self.set_state('preparing','Подготовка Home Assistant')
            try:
                await self.runtime.stop()
                await preview_http(self.config_path,self.supervisor)
                if invitation:
                    if self.credentials:
                        raise ConfigProblem('Client уже подключён. Используйте «Заменить код» или «Другое подключение».')
                    self.credentials=await enroll(invitation)
                    save_credentials(self.directory,self.credentials)
                if not self.credentials:
                    raise ConfigProblem('Введите код подключения, выданный сервером.')
                await configure_http(self.config_path,self.supervisor,self.pending_path)
                await self.supervisor.wait_proxy_ready()
                if await self.launch(): self.set_state('connecting','Подключение к серверу')
            except HTTPConfirmationRequired as exc:
                self.set_state('confirm_http',str(exc))
            except ConfigProblem as exc:
                self.set_state('error',str(exc))
            except (ClientConnectorCertificateError,ssl.SSLError):
                self.set_state('certificate_error','Ошибка сертификата. Проверки доверия остаются включены.')
            except Exception:
                self.set_state('error','Подключение не завершено. Проверьте сервер, код и состояние HA; сохранённую привязку можно повторить.')

    async def resume(self):
        """Keep Ingress available on startup; never edit YAML or restart HA here."""
        async with self.lock:
            try:
                await check_http_ready(self.config_path,self.supervisor,self.pending_path)
                await self.supervisor.wait_proxy_ready(timeout=5)
                if await self.launch(): self.set_state('connecting','Подключение к серверу')
            except HTTPConfirmationRequired as exc:
                self.set_state('confirm_http',str(exc))
            except ConfigProblem as exc:
                self.set_state('error',str(exc))
            except (ClientError,TimeoutError,OSError):
                self.set_state('waiting_ha','Ожидание Home Assistant; проверка повторится автоматически.')
            except ValueError:
                self.set_state('offline','Нет подтверждения доступа от сервера; проверка повторится автоматически.')
            except Exception:
                self.set_state('error','Не удалось восстановить туннель. Нажмите «Повторить подготовку».')

    async def rebind(self, invitation):
        async with self.lock:
            try:
                if not self.credentials: raise ConfigProblem('Сначала подключите Client.')
                await check_http_ready(self.config_path,self.supervisor,self.pending_path)
                replacement=await enroll(invitation,expected_client_id=self.credentials['client_id'],expected_server_url=self.credentials['server_url'])
                if any(replacement[name]!=self.credentials[name] for name in ('client_id','domain','server_url')):
                    raise ConfigProblem('Используйте новый код для этого же подключения на сервере.')
                save_credentials(self.directory,replacement)
                self.credentials=replacement
                self.server_access=self.telemetry=self.status_received=None
                if await self.launch(): self.set_state('connecting','Код заменён; подключение к серверу')
            except ConfigProblem as exc: self.set_state('error',str(exc))
            except Exception: self.set_state('offline','Замена кода не завершена. Проверьте код и связь с сервером.')

    async def replace_connection(self, invitation, *, confirmed):
        async with self.lock:
            try:
                if confirmed is not True: raise ConfigProblem('Подтвердите замену текущего подключения.')
                if not invitation: raise ConfigProblem('Введите новый код подключения.')
                await check_http_ready(self.config_path,self.supervisor,self.pending_path)
                replacement=await enroll(invitation)
                save_credentials(self.directory,replacement)
                self.credentials=replacement
                self.server_access=self.telemetry=self.status_received=None
                if await self.launch(): self.set_state('connecting','Новое подключение сохранено; подключаемся к серверу')
            except ConfigProblem as exc: self.set_state('error',str(exc))
            except Exception: self.set_state('offline','Подключение не заменено или ещё не установлено. Проверьте код и связь с сервером.')

    async def poll_access(self):
        c=self.credentials
        self.billing_stale=True
        result=await ClientStatusClient(c['server_url']).fetch(c['client_id'],c['secret'])
        self.server_access=result
        self.billing_stale=False
        self.status_received=asyncio.get_running_loop().time()
        if result is None: return True
        self.telemetry=parse_telemetry(result['telemetry'],self.status_received) if result.get('telemetry') else None
        state=result['access_state']
        if state!='allowed':
            await self.runtime.stop()
            messages={'paused':'Доступ на паузе','expired':'Срок доступа истёк','revoked':'Доступ отозван на сервере',
                      'clock_error':'Сервер проверяет время; доступ временно закрыт','pending':'Ожидание разрешения сервера'}
            self.set_state(state,messages[state])
            return False
        return True

    async def launch(self, permission_checked=False):
        if not permission_checked and not await self.poll_access(): return False
        await self.runtime.stop()
        config=client_config(self.credentials,self.directory/'ca.pem')
        config['webServer']={'addr':'127.0.0.1','port':18992,'user':'local','password':self.dashboard_password}
        await self.runtime.start(config)
        return True

    async def monitor_once(self):
        if self.lock.locked() or not self.credentials or self.state in ('error','disconnected'):
            return
        if self.state=='waiting_ha':
            await self.resume()
            return
        if self.state=='confirm_http':
            async with self.lock:
                try:
                    if await finish_http_trial(self.supervisor,self.pending_path):
                        if await self.launch(): self.set_state('connecting','Подключение к серверу')
                except ConfigProblem as exc:
                    self.set_state('error',str(exc))
                except (ClientError,TimeoutError,OSError):
                    pass
                except Exception:
                    self.set_state('error','Не удалось завершить настройку HTTP или запустить туннель. Проверьте HA и повторите подготовку.')
            return
        c=self.credentials
        try:
            await verify_tunnel_tls(c)
            if not await self.poll_access(): return
            if self.server_access is not None:
                if not self.runtime.status()['running']:
                    await self.launch(permission_checked=True)
                    self.set_state('connecting','Повторное подключение к серверу')
                    return
                if await proxy_running('http://127.0.0.1:18992/api/status',self.dashboard_password,c['client_id']):
                    self.set_state('connected','Туннель опубликован')
                else: self.set_state('connecting','Туннель ещё не подтвердил публикацию')
                return
            async with ClientSession(timeout=ClientTimeout(total=10),trust_env=False) as session:
                async with session.post(c['server_url']+'/v1/token',allow_redirects=False,
                        data={'grant_type':'client_credentials'},
                        headers={'Authorization':basic(c['client_id'],c['secret'])}) as response:
                    if response.status==401:
                        await self.runtime.stop()
                        self.set_state('revoked','Доступ отозван на сервере')
                        return
                    if response.status!=200:
                        raise ValueError()
                    # Never persist or expose the access token obtained for this probe.
                    await read_json(response)
            if not self.runtime.status()['running']:
                now=asyncio.get_running_loop().time()
                if now>=self.retry_at:
                    self.retry_at=now+self.retry_delay
                    self.retry_delay=min(120,self.retry_delay*2)
                    await self.launch()
                self.set_state('connecting','Повторное подключение к серверу')
                return
            if await proxy_running('http://127.0.0.1:18992/api/status',self.dashboard_password,c['client_id']):
                self.retry_delay=2
                self.set_state('connected','Подключён')
            else:
                self.set_state('connecting','Туннель ещё не подтвердил публикацию')
        except (ClientConnectorCertificateError,ssl.SSLError):
            await self.runtime.stop()
            self.set_state('certificate_error','Ошибка сертификата API или туннеля. Проверки доверия остаются включены.')
        except (ClientError,TimeoutError,ValueError,RuntimeError,OSError):
            self.set_state('offline','Нет связи с сервером')

    async def monitor(self):
        while True:
            await self.monitor_once()
            await asyncio.sleep(15)
