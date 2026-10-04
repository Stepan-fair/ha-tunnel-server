"""Use the HA HTTP trial API; use YAML only when that API is absent."""
import asyncio
import ipaddress
import json
from pathlib import Path

from aiohttp import ClientError
from client.app.ha_config import ConfigProblem, configure_ha, prepare_patch
from shared.files import atomic_write

META={'created_at','error','error_message'}


class HTTPConfirmationRequired(ConfigProblem):
    def __init__(self):
        super().__init__('В течение 5 минут откройте Настройки → Система → Сеть и подтвердите новую настройку HTTP. Затем туннель подключится автоматически. Без подтверждения HA вернёт прежние настройки.')


def plain(config):
    if not isinstance(config,dict):
        raise ConfigProblem('Home Assistant не вернул настройки HTTP.')
    return {k:v for k,v in config.items() if k not in META}


def desired(config):
    result=plain(config)
    if result.get('server_port')!=8123 or result.get('ssl_certificate') or result.get('ssl_key'):
        raise ConfigProblem('Автонастройка поддерживает локальный HTTP на порту 8123; TLS/порт не изменены.')
    proxies=result.get('trusted_proxies',[])
    if not isinstance(proxies,list) or not isinstance(result.get('use_x_forwarded_for',False),bool):
        raise ConfigProblem('Некорректные настройки доверенных прокси.')
    try:
        networks=[ipaddress.ip_network(p,strict=False) for p in proxies if isinstance(p,str)]
        if len(networks)!=len(proxies) or any(p.prefixlen==0 for p in networks):
            raise ValueError()
    except ValueError:
        raise ConfigProblem('Небезопасный список доверенных прокси; настройки не изменены.') from None
    result['trusted_proxies']=list(proxies)
    if ipaddress.ip_network('127.0.0.1/32') not in networks:
        result['trusted_proxies'].append('127.0.0.1/32')
    result['use_x_forwarded_for']=True
    return result


def active(state):
    kind=state.get('active_config_type')
    if kind not in ('stable','pending'):
        raise ConfigProblem('Сначала подтвердите действующие настройки HTTP в Настройки → Система → Сеть.')
    return state[kind]


async def preview_http(path,supervisor):
    state=await supervisor.get_http_config()
    if state is None:
        return prepare_patch(path)
    desired(active(state))
    return state


async def check_http_ready(path,supervisor,pending_path):
    state=await supervisor.get_http_config()
    if state is None:
        ready=not prepare_patch(path).changed and not Path(pending_path).exists()
    else:
        current=active(state)
        marker=Path(pending_path).with_suffix('.http-api.json')
        if marker.exists():
            if await finish_http_trial(supervisor,pending_path):
                return
            raise HTTPConfirmationRequired()
        ready=(state.get('pending') is None and plain(current)==desired(current)
               and not marker.exists())
    if not ready:
        raise ConfigProblem('Настройки HTTP ещё не применены. Нажмите «Повторить подготовку».')


async def configure_http(path,supervisor,pending_path,timeout=240):
    state=await supervisor.get_http_config()
    if state is None:
        return await configure_ha(path,supervisor,pending_path)
    marker=Path(pending_path).with_suffix('.http-api.json')
    intent=json.loads(marker.read_bytes()) if marker.exists() else None
    if state.get('pending') is not None:
        if (intent is None or plain(state['pending'])!=intent or state['pending'].get('error')):
            raise ConfigProblem('В HA есть другая неподтверждённая настройка HTTP. Завершите её в настройках сети.')
        target=intent
    else:
        current=active(state)
        target=desired(current)
        if target==plain(current):
            await supervisor.wait_proxy_ready(timeout=10)
            if intent is not None:
                if intent!=target:
                    raise ConfigProblem('Настройки HTTP изменились извне; автоматическое подтверждение отменено.')
                marker.unlink()
            Path(pending_path).unlink(missing_ok=True)
            return False
        atomic_write(marker,json.dumps(target,sort_keys=True).encode())
        if await supervisor.get_http_config()!=state:
            raise ConfigProblem('Настройки HTTP изменились во время подготовки; повторите после завершения другой настройки.')
        # Configure triggers HA's own restart and five-minute automatic rollback.
        try:
            await supervisor.http_command('http/config/configure',config=target)
        except (ClientError,TimeoutError,OSError):
            # The restart may close the socket after the write but before its
            # reply arrives. Reconcile our persisted intent instead of resending.
            pass
    deadline=asyncio.get_running_loop().time()+timeout
    while True:
        try:
            after=await supervisor.get_http_config()
            if after is None:
                raise ConfigProblem('API настройки HTTP исчез; подтверждение отменено.')
            pending=after.get('pending')
            if pending is None:
                if plain(active(after))!=target:
                    raise ConfigProblem('Home Assistant вернул прежние настройки HTTP. Подготовку можно повторить.')
                await supervisor.wait_proxy_ready(timeout=5)
                break
            if plain(pending)!=target or pending.get('error'):
                raise ConfigProblem('Настройки HTTP изменились или были отклонены; подтверждение отменено.')
            if after.get('active_config_type')!='pending':
                raise TimeoutError()
            await supervisor.wait_proxy_ready(timeout=5)
            # Re-read after the connectivity probe; never confirm someone else's edit.
            fresh=await supervisor.get_http_config()
            if (fresh is None or fresh.get('active_config_type')!='pending' or
                    fresh.get('pending')!=pending):
                raise ConfigProblem('Настройки HTTP изменились во время проверки; подтверждение отменено.')
            # HA's promote API has no expected revision. Calling it automatically
            # could confirm another administrator's concurrent pending edit.
            # Only HA's explicit, user-reviewed confirmation completes the trial.
            raise HTTPConfirmationRequired()
        except (ClientError,TimeoutError,OSError):
            if asyncio.get_running_loop().time()>=deadline:
                raise TimeoutError('Новая настройка HTTP не подтверждена; HA автоматически вернёт прежнюю.') from None
            await asyncio.sleep(min(2,max(0,deadline-asyncio.get_running_loop().time())))
    marker.unlink(missing_ok=True)
    Path(pending_path).unlink(missing_ok=True)
    return True


async def finish_http_trial(supervisor,pending_path):
    marker=Path(pending_path).with_suffix('.http-api.json')
    if not marker.exists():
        raise ConfigProblem('Сведения о подготовке HTTP отсутствуют. Повторите подготовку.')
    target=json.loads(marker.read_bytes())
    state=await supervisor.get_http_config()
    if state is None:
        raise ConfigProblem('API настройки HTTP недоступен.')
    pending=state.get('pending')
    if pending is not None:
        if plain(pending)!=target or pending.get('error'):
            raise ConfigProblem('HA отменил или изменил настройку HTTP. Проверьте настройки сети перед повторной подготовкой.')
        return False
    if plain(active(state))!=target:
        raise ConfigProblem('HA вернул прежнюю настройку HTTP. Повторите подготовку.')
    await supervisor.wait_proxy_ready(timeout=5)
    marker.unlink()
    Path(pending_path).unlink(missing_ok=True)
    return True
