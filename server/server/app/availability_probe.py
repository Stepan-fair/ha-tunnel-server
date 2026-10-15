"""Bounded probes of the local shared path, without weakening endpoint policy or TLS."""
import asyncio
import socket
import time
from urllib.parse import urlsplit
from aiohttp import ClientSession, ClientTimeout, TCPConnector, ClientError
from aiohttp.abc import AbstractResolver

class NpmResolver(AbstractResolver):
    def __init__(self,host,addresses): self.host,self.addresses=host,tuple(addresses)
    async def resolve(self,host,port=0,family=socket.AF_INET):
        if host!=self.host: raise OSError('Unexpected probe hostname')
        return [dict(hostname=host,host=address,port=port,family=socket.AF_INET,proto=0,flags=0) for address in self.addresses]
    async def close(self): pass

class ServiceProbe:
    def __init__(self,runtime,gateway,server_url,addresses,diagnostics=None,*,generation=None):
        self.runtime,self.gateway=runtime,gateway
        self.url=server_url.rstrip('/')+'/health'
        self.host=urlsplit(server_url).hostname
        self.address_source=addresses
        self.generation=generation or (lambda:0)
        self.diagnostics=diagnostics
        self.last=None
        self.at=0

    @property
    def addresses(self):
        return tuple(self.address_source() if callable(self.address_source) else self.address_source)

    async def __call__(self):
        result=dict(frp=bool(self.runtime.status()['running']),gateway=self.gateway.returncode is None,npm=False)
        if result['frp']:
            try:
                reader,writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',7000),.5)
                writer.close()
                await writer.wait_closed()
            except (OSError,TimeoutError): result['frp']=False
        # Every checkpoint verifies local processes. HTTPS is cached for at most 5s.
        addresses=self.addresses
        generation=self.generation()
        if addresses!=getattr(self,'last_addresses',None) or generation!=getattr(self,'last_generation',None):
            self.last=None
            self.last_addresses=addresses
            self.last_generation=generation
        if not addresses:
            self.last=False
        elif self.last is None or time.monotonic()-self.at>=5:
            connector=TCPConnector(resolver=NpmResolver(self.host,addresses))
            try:
                async with ClientSession(connector=connector,timeout=ClientTimeout(total=2),trust_env=False,auto_decompress=False) as session:
                    async with session.get(self.url,allow_redirects=False) as response:
                        body=bytearray()
                        async for chunk in response.content.iter_chunked(1024):
                            body.extend(chunk)
                            if len(body)>1024: raise ValueError('Health response too large')
                        import json
                        data=json.loads(body) if len(body)<=1024 else {}
                        self.last=response.status==200 and data.get('status')=='ok' and data.get('protocol')==1
            except (ClientError,OSError,TimeoutError,ValueError,AttributeError):
                self.last=False
            self.at=time.monotonic()
        # Revocation during HTTPS must not publish a cached healthy result.
        result['npm']=self.last is True and bool(addresses) and self.addresses==addresses
        if result['gateway']:
            try:
                async with ClientSession(timeout=ClientTimeout(total=.5),trust_env=False) as session:
                    async with session.get('http://127.0.0.1:8080/',allow_redirects=False) as response:
                        result['gateway']=response.status==403
            except (ClientError,OSError,TimeoutError): result['gateway']=False
        result['npm']=result['npm'] and self.addresses==addresses and bool(addresses) and self.generation()==generation
        if self.diagnostics:
            for component,healthy in result.items(): self.diagnostics.component(component,'healthy' if healthy else 'unhealthy')
        return result
