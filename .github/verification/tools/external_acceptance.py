"""Anonymous, bounded public-route acceptance. Never print target identities."""
import asyncio
import json
import os
import re
import time
from urllib.parse import urljoin, urlsplit

import aiohttp
from shared.dns import connector

DEADLINE = 15
BODY_LIMIT = 2 * 1024 * 1024
FRAME_LIMIT = 8192


class Rejected(ValueError):
    pass


def origin(value):
    if not isinstance(value,str) or len(value)>512 or re.search(r'[\s\\\x00-\x1f\x7f]',value):
        raise ValueError('Invalid target configuration')
    parsed=urlsplit(value)
    if (parsed.scheme!='https' or not parsed.hostname or parsed.username is not None or
            parsed.password is not None or parsed.path not in ('','/') or parsed.query or parsed.fragment):
        raise ValueError('Invalid target configuration')
    port=parsed.port
    if port is not None and not 1<=port<=65535: raise ValueError('Invalid target configuration')
    value.encode('ascii')
    return 'https://'+parsed.netloc.lower()


def parse_targets(raw):
    if not isinstance(raw,str) or len(raw)>8192: raise ValueError('Invalid target configuration')
    targets=json.loads(raw)
    if not isinstance(targets,list) or not 1<=len(targets)<=8: raise ValueError('Invalid target configuration')
    targets=[origin(item) for item in targets]
    if len(set(targets))!=len(targets): raise ValueError('Invalid target configuration')
    return targets


async def check(target,index,*,connector_factory=connector):
    result=dict(index=index,https=False,wss=False,protocol=None,elapsed_ms=0,error=None)
    started=time.monotonic()
    try:
        target=origin(target)
        trace=aiohttp.TraceConfig()
        async def reject_redirect(session,context,params):
            params.response.close()
            raise Rejected('redirect')
        trace.on_request_redirect.append(reject_redirect)
        async with asyncio.timeout(DEADLINE), aiohttp.ClientSession(
                connector=connector_factory(),timeout=aiohttp.ClientTimeout(total=DEADLINE),
                trust_env=False,cookie_jar=aiohttp.DummyCookieJar(),auto_decompress=False,
                trace_configs=[trace]) as session:
            url=target+'/'
            for attempt in range(3):
                async with session.get(url,allow_redirects=False,headers={'Accept-Encoding':'identity'}) as response:
                    if response.status in (301,302,303,307,308):
                        location=response.headers.get('Location','')
                        if not location or re.search(r'[\s\\\x00-\x1f\x7f]',location): raise Rejected('redirect')
                        destination=urlsplit(urljoin(url,location))
                        if (attempt==2 or destination.username is not None or destination.password is not None or
                                destination.scheme!='https' or destination.netloc.lower()!=urlsplit(target).netloc or
                                destination.fragment): raise Rejected('redirect')
                        url=destination.geturl()
                        continue
                    if response.status!=200 or response.content_type!='text/html': raise Rejected('http')
                    body=bytearray()
                    async for chunk in response.content.iter_chunked(8192):
                        body.extend(chunk)
                        if len(body)>BODY_LIMIT: raise Rejected('size')
                    if b'<home-assistant' not in body.lower(): raise Rejected('shell')
                    result['https']=True
                    break
            async with session.ws_connect(target+'/api/websocket',max_msg_size=FRAME_LIMIT,
                    autoping=False,heartbeat=None) as websocket:
                message=await websocket.receive()
                if message.type!=aiohttp.WSMsgType.TEXT or len(message.data.encode())>FRAME_LIMIT:
                    raise Rejected('websocket')
                data=json.loads(message.data)
                if not isinstance(data,dict) or data.get('type')!='auth_required': raise Rejected('protocol')
                result.update(wss=True,protocol='auth_required')
    except Rejected as exc:
        result['error']=str(exc)
    except aiohttp.ClientSSLError:
        result['error']='tls'
    except TimeoutError:
        result['error']='timeout'
    except (ValueError,UnicodeError,TypeError):
        result['error']='protocol'
    except Exception:
        result['error']='network'
    result['elapsed_ms']=round((time.monotonic()-started)*1000)
    return result


async def main():
    try:
        targets=parse_targets(os.environ.pop('HA_TUNNEL_ACCEPTANCE_ORIGINS',''))
    except Exception:
        print(json.dumps({'error':'configuration'}))
        return 1
    results=[await check(target,index) for index,target in enumerate(targets,1)]
    print(json.dumps({'results':results},separators=(',',':')))
    return int(any(item['error'] is not None for item in results))


if __name__=='__main__':
    raise SystemExit(asyncio.run(main()))
