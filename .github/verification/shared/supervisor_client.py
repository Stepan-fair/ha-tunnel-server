"""Bounded access to fixed, narrowly scoped Supervisor endpoints."""
import re
from shared.dns import connector
import json
import aiohttp


class SupervisorClient:
    def __init__(self,token): self.token=token

    async def get(self,path): return await self._request('GET',path)
    async def post(self,path,payload): return await self._request('POST',path,payload)

    async def _request(self,method,path,payload=None):
        allowed=(path in ('/addons/self/info','/supervisor/info','/addons','/host/info') or
                 re.fullmatch(r'/addons/[a-z0-9_]+/info',path)) if method=='GET' else path=='/addons/self/options'
        if not allowed or not self.token: raise ValueError('Supervisor endpoint unavailable')
        try:
            async with aiohttp.ClientSession(connector=connector(),timeout=aiohttp.ClientTimeout(total=5),trust_env=False) as session:
                async with session.request(method,'http://supervisor'+path,
                        headers={'Authorization':'Bearer '+self.token},json=payload,allow_redirects=False) as response:
                    if response.status!=200: raise ValueError()
                    raw=bytearray()
                    async for chunk in response.content.iter_chunked(8192):
                        raw.extend(chunk)
                        if len(raw)>65536: raise ValueError()
                    body=json.loads(raw)
                    if body.get('result')!='ok' or not isinstance(body.get('data'),dict): raise ValueError()
                    return body['data']
        except Exception: raise ValueError('Supervisor request failed') from None
