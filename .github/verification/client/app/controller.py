import asyncio
import base64
import secrets
import ssl
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout, ClientError, ClientConnectorCertificateError
from client.app.enrollment import enroll, read_json, EnrollmentProblem, BindingClient
from client.app.ha_config import ConfigProblem
from client.app.http_config import (preview_http, configure_http, check_http_ready,
                                    finish_http_trial, HTTPConfirmationRequired)
from client.app.runtime import client_config
from client.app.supervisor import CoreCommandError
from client.app.status import ClientStatusClient, CredentialsRejected
from client.app.binding_state import StateFile,StateProblem
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
        self.state_file=StateFile(self.directory)
        self.local_error=None
        self.ha_wait_state=None
        self.binding_recovery=False
        self.binding_can_cancel=False
        try:
            local=self.state_file.load()
            self.credentials=local.active
            self.local_error=local.error
            self.binding_recovery=bool(local.error or local.pending_operation)
            self.binding_can_cancel=bool(local.pending_operation and local.pending_operation['candidate'])
        except StateProblem as exc:
            self.credentials=None
            self.local_error=str(exc)
            self.binding_recovery=True
        self.state='disconnected'
        self.message='Не подключён'
        if self.local_error:
            self.state='state_error'
            self.message=self.local_error
        self.lock=asyncio.Lock()
        self.dashboard_password=secrets.token_urlsafe(32)
        self.retry_at=0
        self.retry_delay=2
        self.pending_path=self.directory/'ha-config.pending'
        self.server_access=None
        self.telemetry=None
        self.status_received=None
        self.contact_received=None
        self.billing_stale=True
        self.mqtt=None
        self.status_client=None
        self.status_origin=None
        self.operation_error=None

    async def close(self):
        if self.status_client is not None:
            await self.status_client.close()
            self.status_client=None
            self.status_origin=None

    def status(self):
        return {'state':self.state,'message':self.message,'configured':self.credentials is not None,
                'operation_error':self.operation_error,'binding_recovery':self.binding_recovery,
                'binding_can_cancel':self.binding_can_cancel,'binding_message':self.local_error or ('Проверяем незавершённую привязку. Новая выдача временно заблокирована.' if self.binding_recovery else None),
                'domain':self.credentials['domain'] if self.credentials else None,
                'busy':self.lock.locked(),'access':self.server_access,
                'billing_stale':self.billing_stale or self.status_received is None or asyncio.get_running_loop().time()-self.status_received>45,
                'telemetry':age_telemetry(self.telemetry,asyncio.get_running_loop().time()) if self.telemetry else None,
                'mqtt':self.mqtt.status() if self.mqtt else {'state':'not_configured'}}

    def set_state(self,state,message):
        self.state,self.message=state,message

    async def _reload_binding(self):
        try:
            was_recovering=self.binding_recovery
            local=self.state_file.load()
            if local.active!=self.credentials:
                await self.runtime.stop()
                await self.close()
                self.credentials=local.active
                self.server_access=self.telemetry=self.status_received=None
                self.contact_received=None
                self.billing_stale=True
            self.local_error=local.error
            self.binding_recovery=bool(local.error or local.pending_operation)
            self.binding_can_cancel=bool(local.pending_operation and local.pending_operation['candidate'])
            if was_recovering and not self.binding_recovery and self.credentials:
                self.set_state('waiting_ha','Привязка проверена; восстанавливаем подключение.')
        except StateProblem as exc:
            self.local_error=str(exc)
            self.binding_recovery=True
            self.binding_can_cancel=False

    async def _ready(self):
        await check_http_ready(self.config_path,self.supervisor,self.pending_path)
        await self.supervisor.wait_proxy_ready(timeout=5)
        self.ha_wait_state=None

    async def _initial_ready(self):
        await configure_http(self.config_path,self.supervisor,self.pending_path)
        await self.supervisor.wait_proxy_ready()
        self.ha_wait_state=None

    def _binding_error(self,exc):
        if isinstance(exc,HTTPConfirmationRequired):
            self.ha_wait_state='confirm_http'
            self.set_state('confirm_http',str(exc))
        elif isinstance(exc,(StateProblem,)):
            self.local_error=str(exc)
            self.set_state('state_error',str(exc))
        elif isinstance(exc,(EnrollmentProblem,ConfigProblem,CoreCommandError)):
            self.operation_error=str(exc)
            if not self.credentials or not self.runtime.status()['running']: self.set_state('configuration_error',str(exc))
        elif isinstance(exc,CredentialsRejected):
            self.set_state('credentials_rejected','Привязка заменена или доступ отклонён Server.')
        elif isinstance(exc,(ClientConnectorCertificateError,ssl.SSLError)):
            self.operation_error='Ошибка сертификата. Проверки доверия остаются включены.'
            if not self.credentials: self.set_state('certificate_error',self.operation_error)
        else:
            self.operation_error='Ожидание HA или Server. Незавершённая привязка будет проверена автоматически.'
            if not self.credentials: self.set_state('binding_recovery' if self.binding_recovery else 'offline',self.operation_error)

    async def _enroll(self,invitation,*,same_connection=False,initial=False):
        if self.local_error or self.binding_recovery:
            raise EnrollmentProblem(self.local_error or 'Дождитесь восстановления незавершённой привязки.')
        expected={}
        if same_connection:
            if not self.credentials: raise ConfigProblem('Сначала подключите Client.')
            expected=dict(expected_client_id=self.credentials['client_id'],expected_server_url=self.credentials['server_url'],binding_secret=self.credentials['secret'])
        if initial: await preview_http(self.config_path,self.supervisor)
        else: await self._ready()
        try:
            await enroll(invitation,directory=self.directory,before_commit=self._initial_ready if initial else self._ready,**expected)
        finally:
            # A write can fail after rename. Reload the sole authority, never guess whether it changed.
            await self._reload_binding()
        if await self.launch(): self.set_state('connecting','Подключение сохранено; подключаемся к серверу')

    async def connect(self,invitation):
        async with self.lock:
            self.operation_error=None
            if invitation and self.credentials:
                self.operation_error='Client уже подключён. Используйте «Заменить код» или «Другое подключение».'
                return
            try:
                if invitation: await self._enroll(invitation,initial=True)
                elif self.binding_recovery: await self._recover_binding()
                elif self.credentials:
                    await self.runtime.stop()
                    await self._initial_ready()
                    if await self.launch(): self.set_state('connecting','Подключение к серверу')
                else: raise ConfigProblem('Введите код подключения, выданный сервером.')
            except Exception as exc: self._binding_error(exc)

    async def resume(self):
        """Startup checks existing configuration; no automatic edits or Core restart."""
        async with self.lock:
            if self.local_error and not self.credentials:
                self.set_state('state_error',self.local_error)
                return
            try:
                await self._ready()
                if await self.launch(): self.set_state('connecting','Подключение к серверу')
            except HTTPConfirmationRequired as exc:
                self.ha_wait_state='confirm_http'
                self.set_state('confirm_http',str(exc))
            except (ConfigProblem,CoreCommandError) as exc:
                self.ha_wait_state='configuration_error'
                self.set_state('configuration_error',str(exc))
            except CredentialsRejected:
                await self.runtime.stop()
                self.set_state('credentials_rejected','Привязка заменена или доступ отклонён Server.')
            except (ClientConnectorCertificateError,ssl.SSLError):
                await self.runtime.stop()
                self.set_state('certificate_error','Ошибка сертификата. Проверки доверия остаются включены.')
            except StateProblem as exc: self.set_state('state_error',str(exc))
            except Exception:
                self.ha_wait_state='waiting_ha'
                self.set_state('waiting_ha','Ожидание HA или Server; проверка повторится автоматически.')
            if self.ha_wait_state and self.credentials:
                await self._monitor_connection(status_only=True)

    async def rebind(self,invitation):
        async with self.lock:
            self.operation_error=None
            try: await self._enroll(invitation,same_connection=True)
            except Exception as exc: self._binding_error(exc)

    async def replace_connection(self,invitation,*,confirmed):
        async with self.lock:
            self.operation_error=None
            try:
                if confirmed is not True: raise ConfigProblem('Подтвердите замену текущего подключения.')
                if not invitation: raise ConfigProblem('Введите новый код подключения.')
                await self._enroll(invitation)
            except Exception as exc: self._binding_error(exc)

    async def _recover_binding(self):
        try:
            await BindingClient(self.directory).recover(before_commit=self._ready)
        finally: await self._reload_binding()
        if self.credentials and not self.binding_recovery:
            if await self.launch(): self.set_state('connecting','Привязка восстановлена; подключаемся к серверу')

    async def cancel_binding(self):
        async with self.lock:
            try:
                await BindingClient(self.directory).cancel()
                self.operation_error='Состояние привязки проверено на Server.'
            except Exception as exc: self._binding_error(exc)
            finally: await self._reload_binding()
            if not self.binding_recovery and not self.credentials: self.set_state('disconnected','Введите код подключения.')

    async def poll_access(self):
        c=self.credentials
        self.billing_stale=True
        if self.status_origin!=c['server_url']:
            await self.close()
            self.status_client=ClientStatusClient(c['server_url'])
            self.status_origin=c['server_url']
        result=await self.status_client.fetch(c['client_id'],c['secret'])
        self.server_access=result
        self.billing_stale=False
        self.status_received=asyncio.get_running_loop().time()
        if result is None: return True
        self.contact_received=self.status_received
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
        self.state_file.materialize_ca(self.credentials)
        await self.runtime.stop()
        config=client_config(self.credentials,self.directory/'ca.pem')
        config['webServer']={'addr':'127.0.0.1','port':18992,'user':'local','password':self.dashboard_password}
        await self.runtime.start(config)
        return True

    async def monitor_once(self):
        if self.lock.locked(): return
        if self.binding_recovery and not self.local_error:
            async with self.lock:
                try: await self._recover_binding()
                except Exception as exc: self._binding_error(exc)
            if self.state=='confirm_http': return
        if not self.credentials or self.state=='disconnected':
            return
        # Server policy may change the visible state; keep the HA launch gate
        # separately so pause/start or API errors cannot bypass local readiness.
        if self.ha_wait_state=='confirm_http' or self.state=='confirm_http':
            self.ha_wait_state='confirm_http'
            async with self.lock:
                await self._monitor_connection(status_only=True)
                try:
                    if await finish_http_trial(self.supervisor,self.pending_path):
                        self.ha_wait_state=None
                        self.set_state('waiting_ha','Настройка HTTP подтверждена; подключаемся к серверу.')
                        if await self.launch(): self.set_state('connecting','Подключение к серверу')
                except (ConfigProblem,CoreCommandError) as exc:
                    self.ha_wait_state='configuration_error'
                    self.set_state('configuration_error',str(exc))
                except (ClientError,TimeoutError,OSError):
                    pass
                except Exception:
                    self.set_state('waiting_ha','Ожидание HA или Server; проверка повторится автоматически.')
            return
        if self.ha_wait_state=='configuration_error' or self.state=='configuration_error':
            self.ha_wait_state='configuration_error'
            async with self.lock:
                await self._monitor_connection(status_only=True)
            return
        if self.ha_wait_state=='waiting_ha' or self.state=='waiting_ha':
            await self.resume()
            return
        async with self.lock:
            await self._monitor_connection()

    async def _monitor_connection(self, *, status_only=False):
        c=self.credentials
        try:
            if not await self.poll_access(): return
            if status_only: return
            await verify_tunnel_tls(c)
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
                        self.contact_received=asyncio.get_running_loop().time()
                        await self.runtime.stop()
                        self.set_state('revoked','Доступ отозван на сервере')
                        return
                    if response.status!=200:
                        raise ValueError()
                    # Never persist or expose the access token obtained for this probe.
                    await read_json(response)
                    self.contact_received=asyncio.get_running_loop().time()
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
        except CredentialsRejected:
            self.contact_received=asyncio.get_running_loop().time()
            await self.runtime.stop()
            self.set_state('credentials_rejected','Привязка заменена или доступ отклонён Server. Проверьте подключение на Server.')
        except (ClientConnectorCertificateError,ssl.SSLError):
            await self.runtime.stop()
            self.set_state('certificate_error','Ошибка сертификата API или туннеля. Проверки доверия остаются включены.')
        except (ClientError,TimeoutError,ValueError,RuntimeError,OSError):
            if not status_only:
                self.set_state('offline','Нет связи с сервером')

    async def monitor(self):
        while True:
            await self.monitor_once()
            await asyncio.sleep(15+secrets.randbelow(4000)/1000)
