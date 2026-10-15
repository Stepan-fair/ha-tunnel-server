"""Narrow fixed Supervisor Core API. No arbitrary URLs, services or WS commands."""
import asyncio
import inspect
import json
import re
import secrets
from contextlib import asynccontextmanager

from aiohttp import ClientTimeout, ClientWSTimeout, DummyCookieJar, TraceConfig, WSMsgType
from shared.dns import session as ClientSession
from shared.notification_state import SERVICE, unique_pairs

CORE_API = 'http://supervisor/core/api'
CORE_WS = 'ws://supervisor/core/websocket'
FRAME_LIMIT = 256 * 1024


def payload(ident, title, message):
    if not isinstance(ident,str) or not re.fullmatch('ha_tunnel_[a-zA-Z0-9_]{1,160}',ident): raise ValueError('Invalid own notification ID')
    if not isinstance(title,str) or len(title)>128 or not isinstance(message,str) or len(message)>2048: raise ValueError('Invalid notification text')
    return dict(title=title,message=message)


async def bounded(response, limit):
    raw=bytearray()
    async for chunk in response.content.iter_chunked(8192):
        raw.extend(chunk)
        if len(raw)>limit: raise ValueError('Core response too large')
    return bytes(raw)


def decode(raw):
    try: return json.loads(raw,object_pairs_hook=unique_pairs)
    except (ValueError,RecursionError,OverflowError) as exc: raise ValueError('Invalid Core response') from exc


class HaNotifications:
    def __init__(self, token):
        self.token=token
        self.allowed=set()
        self.prefix='ha_tunnel_'
        self.session=None
        self.ws_session=None
        self.ready=asyncio.Event()
        self.observer_session=None

    async def _http(self):
        if not self.token: raise ValueError('Core access unavailable')
        if self.session is None or self.session.closed:
            self.session=ClientSession(timeout=ClientTimeout(total=5),trust_env=False,cookie_jar=DummyCookieJar())
        return self.session

    async def close(self):
        if self.session is not None:
            await self.session.close(); self.session=None
        if self.ws_session is not None:
            await self.ws_session.close(); self.ws_session=None

    @asynccontextmanager
    async def _websocket_session(self):
        if self.ws_session is None or self.ws_session.closed:
            trace=TraceConfig()
            async def reject_redirect(session, context, params):
                params.response.close()
                raise ValueError('Core redirects forbidden')
            trace.on_request_redirect.append(reject_redirect)
            # Connection reuse is local; DNS child ownership survives this session.
            self.ws_session=ClientSession(timeout=ClientTimeout(total=5),trust_env=False,
                cookie_jar=DummyCookieJar(),trace_configs=[trace])
        yield self.ws_session

    async def _request(self, method, path, data=None, limit=FRAME_LIMIT):
        session=await self._http()
        async with session.request(method,CORE_API+path,json=data,allow_redirects=False,
                headers={'Authorization':'Bearer '+self.token}) as response:
            if not 200<=response.status<300: raise ValueError('Core delivery unavailable')
            return decode(await bounded(response,limit))

    async def services(self):
        result=await self._request('GET','/services',limit=2*1024*1024)
        if not isinstance(result,list): raise ValueError('Invalid Core catalog')
        found=set()
        for item in result:
            if not isinstance(item,dict): raise ValueError('Invalid Core catalog')
            if item.get('domain')!='notify': continue
            services=item.get('services')
            if not isinstance(services,dict): raise ValueError('Invalid Core catalog')
            for name in services:
                service='notify.'+name
                if SERVICE.fullmatch(service): found.add(service)
                if len(found)>512: raise ValueError('Mobile catalog too large')
        self.allowed=found
        return sorted(found)

    async def create(self, id, title, message):
        data=payload(id,title,message); data['notification_id']=id
        await self._request('POST','/services/persistent_notification/create',data)

    async def dismiss(self, id):
        payload(id,'','')
        await self._request('POST','/services/persistent_notification/dismiss',{'notification_id':id})

    async def mobile(self, service, tag, title, message):
        if not isinstance(service,str) or not SERVICE.fullmatch(service) or service not in self.allowed: raise ValueError('Mobile service unavailable')
        data=payload(tag,title,message); data['data']={'tag':tag}
        await self._request('POST','/services/notify/'+service.split('.',1)[1],data)

    async def observe(self, callback):
        if not self.token: raise ValueError('Core access unavailable')
        self.ready.clear()
        session_id=secrets.token_hex(16)
        self.observer_session=session_id
        async with self._websocket_session() as session:
            ws=await asyncio.wait_for(session.ws_connect(CORE_WS,max_msg_size=FRAME_LIMIT,
                heartbeat=30,timeout=ClientWSTimeout(ws_receive=None,ws_close=5)),5)
            async def receive():
                frame=await ws.receive()
                if frame.type!=WSMsgType.TEXT: raise ValueError('Core observer disconnected')
                result=decode(frame.data)
                if not isinstance(result,dict): raise ValueError('Invalid Core frame')
                return result
            try:
                if (await asyncio.wait_for(receive(),5)).get('type')!='auth_required': raise ValueError('Core authentication unavailable')
                await asyncio.wait_for(ws.send_json({'type':'auth','access_token':self.token}),5)
                if (await asyncio.wait_for(receive(),5)).get('type')!='auth_ok': raise ValueError('Core authentication rejected')
                await asyncio.wait_for(ws.send_json({'id':1,'type':'persistent_notification/subscribe'}),5)
                result=await asyncio.wait_for(receive(),5)
                if result.get('id')!=1 or result.get('type')!='result' or result.get('success') is not True: raise ValueError('Core subscription rejected')
                first=True
                while True:
                    result=await asyncio.wait_for(receive(),5) if first else await receive()
                    event=result.get('event')
                    if result.get('id')!=1 or result.get('type')!='event' or not isinstance(event,dict): raise ValueError('Invalid Core event')
                    kind=event.get('type'); cards=event.get('notifications')
                    if kind not in ('current','added','updated','removed') or not isinstance(cards,dict) or first and kind!='current': raise ValueError('Invalid Core event')
                    own={}
                    for ident,card in cards.items():
                        if not ident.startswith(self.prefix): continue
                        if (not isinstance(card,dict) or card.get('notification_id')!=ident or
                            not isinstance(card.get('created_at'),str) or len(card['created_at'])>128): raise ValueError('Invalid Core card')
                        payload(ident,card.get('title'),card.get('message'))
                        own[ident]=card
                    answer=callback(dict(session=session_id,type=kind,notifications=own))
                    if inspect.isawaitable(answer): await answer
                    if first: self.ready.set(); first=False
            finally:
                if self.observer_session==session_id: self.ready.clear()
                await asyncio.wait_for(ws.close(),5)
