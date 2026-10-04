"""Bounded access to fixed, narrowly scoped Supervisor endpoints."""
import re
import json
import aiohttp


class SupervisorClient:
    def __init__(self,token): self.token=token

    async def get(self,path): return await self._request('GET',path)
    async def post(self,path,payload): return await self._request('POST',path,payload)

    async def _request(self,method,path,payload=None):
        allowed=(path in ('/addons/self/info','/supervisor/info','/addons') or
                 re.fullmatch(r'/addons/[a-z0-9_]+/info',path)) if method=='GET' else path=='/addons/self/options'
        if not allowed or not self.token: raise ValueError('Supervisor endpoint unavailable')
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.request(method,'http://supervisor'+path,
                        headers={'Authorization':'Bearer '+self.token},json=payload,allow_redirects=False) as response:
                    if response.status!=200: raise ValueError()
                    raw=await response.content.read(65537)
                    if len(raw)>65536: raise ValueError()
                    body=json.loads(raw)
                    if body.get('result')!='ok' or not isinstance(body.get('data'),dict): raise ValueError()
                    return body['data']
        except Exception: raise ValueError('Supervisor request failed') from None
