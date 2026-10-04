"""Opt-in, bounded public diagnostics; no inference of ISP static addressing."""
import asyncio
import ipaddress
import json
import socket
from urllib.parse import urlsplit
import aiohttp
from shared.validation import origin


async def public_addresses(host):
    rows=await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo,host,443,socket.AF_INET,socket.SOCK_STREAM),5)
    ips=sorted({row[4][0] for row in rows})
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips): raise ValueError('Nonpublic DNS address')
    return ips


class PinnedResolver(aiohttp.abc.AbstractResolver):
    def __init__(self,host,ips): self.host=host; self.ips=ips
    async def resolve(self,host,port=0,family=socket.AF_INET):
        if host!=self.host or port!=443: raise ValueError('Unexpected diagnostic target')
        return [{'hostname':host,'host':ip,'port':port,'family':socket.AF_INET,'proto':0,'flags':0} for ip in self.ips]
    async def close(self): pass


async def get_json(url,ips):
    parsed=urlsplit(url); host=parsed.hostname
    if url!='https://api.ipify.org?format=json':
        if parsed.path!='/health' or parsed.query or parsed.fragment: raise ValueError('Unexpected target')
        origin(url[:-len('/health')])
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips): raise ValueError('Nonpublic target')
    connector=aiohttp.TCPConnector(resolver=PinnedResolver(host,ips),use_dns_cache=False)
    async with aiohttp.ClientSession(connector=connector,timeout=aiohttp.ClientTimeout(total=5)) as session:
        async with session.get(url,allow_redirects=False) as response:
            if response.status!=200: raise ValueError('Unexpected response')
            data=bytearray()
            async for chunk in response.content.iter_chunked(8192):
                data.extend(chunk)
                if len(data)>65536: raise ValueError('Diagnostic reply too large')
            result=json.loads(data)
            if not isinstance(result,dict): raise ValueError('Invalid reply')
            return result


def item(status,message,**evidence): return {'status':status,'message':message,**evidence}


async def check_network(config,wan_ip,static_confirmed):
    server=origin(config.get('server_url',''))
    host=urlsplit(server).hostname
    try: ipaddress.ip_address(host)
    except ValueError: pass
    else: raise ValueError('DNS hostname required')
    if type(static_confirmed) is not bool: raise ValueError('Invalid static confirmation')
    wan=None
    if wan_ip:
        if not isinstance(wan_ip,str) or len(wan_ip)>45: raise ValueError('Invalid WAN address')
        wan=ipaddress.ip_address(wan_ip)
        if wan.version!=4: raise ValueError('IPv4 WAN required')
    result={'wan':item('unknown','Введите IPv4 из раздела Интернет / WAN вашего роутера.'),
            'static':item('ok' if static_confirmed else 'unknown',
                'Постоянный IP подтверждён вами у провайдера; автоматическое измерение не проводилось.' if static_confirmed else
                'Уточните у провайдера, закреплён ли внешний IP за вами.'),
            'external':item('unknown','Проверка внешнего адреса пропущена.'),
            'dns':item('unknown','DNS не проверен.'),'tls':item('unknown','HTTPS не проверен.')}
    if wan:
        if not wan.is_global:
            shared=wan in ipaddress.ip_network('100.64.0.0/10')
            result['wan']=item('problem','WAN находится в общей сети провайдера (возможен CGNAT).' if shared else
                'WAN не публичный. Возможен второй роутер или NAT провайдера; входящий доступ пока не подтверждён.',ip=str(wan))
        else: result['wan']=item('ok','WAN-адрес публичный. Доступность входящих портов проверяется отдельно.',ip=str(wan))
    if not config.get('skip_external',False):
        try:
            ips=await public_addresses('api.ipify.org')
            echo=await get_json('https://api.ipify.org?format=json',ips)
            external=ipaddress.ip_address(echo['ip'])
            if external.version!=4 or not external.is_global: raise ValueError()
            result['external']=item('ok','Внешний IPv4 определён. Это не проверка входящего доступа или постоянства.',ip=str(external))
            if wan and wan.is_global and wan!=external:
                result['wan']=item('unknown','WAN и внешний адрес различаются. Проверьте другой выход в Интернет или NAT.',ip=str(wan))
        except Exception: result['external']=item('unknown','Сервис внешнего адреса недоступен. Тип WAN по этой ошибке не определяется.')
    try:
        ips=await public_addresses(host)
        result['dns']=item('ok','Адрес регистрации разрешается в публичный IPv4.',addresses=ips)
    except ValueError:
        result['dns']=item('problem','DNS ведёт на непубличный адрес; запрос HTTPS не выполнялся.')
        return result
    except Exception:
        result['dns']=item('unknown','Не удалось проверить DNS. Проверьте запись у DNS-провайдера.')
        return result
    try:
        health=await get_json(server+'/health',ips)
        if health.get('status')!='ok' or health.get('protocol')!=1: raise ValueError()
        result['tls']=item('ok','Сертификат проверен, HTTPS API Server отвечает.')
    except aiohttp.ClientSSLError:
        result['tls']=item('problem','Не удалось подтвердить сертификат HTTPS. Проверьте домен и сертификат NPM.')
    except Exception:
        result['tls']=item('unknown','HTTPS API не ответил ожидаемым образом. Возможны настройки NPM или отсутствие NAT loopback; проверьте с внешней сети.')
    return result
