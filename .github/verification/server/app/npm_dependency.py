"""Supervisor-owned NPM identity and short-lived, exact-address proof."""
import asyncio
from dataclasses import dataclass
import ipaddress
import socket
import time

NPM_SLUG='a0d7b954_nginxproxymanager'
NPM_HOST='a0d7b954-nginxproxymanager'
PROOF_TTL=30
LOCAL_NETWORKS=tuple(ipaddress.ip_network(value) for value in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))

class DependencyUnavailable(ValueError):
    """Expected dependency may recover without editing saved options."""
    def __init__(self,reason):
        self.reason=reason
        super().__init__(reason)

class InvalidNpmCandidate(ValueError):
    """Saved/candidate identity is not the supported NPM app."""

@dataclass(frozen=True)
class VerifiedNpmSnapshot:
    hostname: str
    addresses: tuple[str,...]
    verified_at: float

    def fresh(self):
        return 0<=time.monotonic()-self.verified_at<PROOF_TTL

async def resolve_npm(host):
    rows=await asyncio.get_running_loop().getaddrinfo(host,None,family=socket.AF_INET,type=socket.SOCK_STREAM)
    return [row[4][0] for row in rows]

def _address(value):
    try:
        if not isinstance(value,str): raise ValueError()
        address=ipaddress.ip_address(value)
        if (address.version!=4 or not any(address in network for network in LOCAL_NETWORKS) or address.is_unspecified or
                address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved):
            raise ValueError()
        return str(address)
    except (ValueError,TypeError): raise DependencyUnavailable('unsafe_address') from None

class NpmDependency:
    def __init__(self,supervisor,resolve=None):
        self.supervisor=supervisor
        self.resolve=resolve or resolve_npm

    async def validate_candidate(self,options):
        return await self.snapshot(options)

    async def snapshot(self,options):
        # Reject a foreign configured host even while Supervisor is absent.
        if options.get('npm_host')!=NPM_HOST:
            raise InvalidNpmCandidate('NPM hostname does not identify the supported app')
        started=time.monotonic()
        try:
            async with asyncio.timeout(5):
                info=await self.supervisor.get('/addons/'+NPM_SLUG+'/info')
        except Exception: raise DependencyUnavailable('supervisor_unavailable') from None
        if (info.get('slug')!=NPM_SLUG or info.get('hostname')!=NPM_HOST or
                info.get('repository')!='a0d7b954' or info.get('host_network') is not False):
            raise InvalidNpmCandidate('Supervisor NPM identity does not match')
        if info.get('state')!='started': raise DependencyUnavailable('npm_stopped')
        address=_address(info.get('ip_address'))
        try:
            async with asyncio.timeout(5):
                addresses=tuple(sorted({_address(value) for value in await self.resolve(NPM_HOST)}))
        except Exception: raise DependencyUnavailable('dns_unavailable') from None
        if addresses!=(address,): raise DependencyUnavailable('dns_owner_mismatch')
        snapshot=VerifiedNpmSnapshot(NPM_HOST,addresses,started)
        if not snapshot.fresh(): raise DependencyUnavailable('proof_expired')
        return snapshot

class NpmRuntime:
    """One published snapshot; only administrative exclusive may open trust.

    Expiry/revocation is synchronous, close-only safety, including during restore.
    Captured snapshot identity prevents an old expiry from closing a new generation.
    """
    def __init__(self,dependency,options,store,gateway,diagnostics=None):
        self.dependency,self.options,self.store,self.gateway=dependency,options,store,gateway
        self.diagnostics=diagnostics
        self.current=None
        self.reason='waiting_dependency'
        self.detail='waiting_dependency'
        self.local_health=lambda:None
        self.epoch=0
        self.progress=time.monotonic()

    @property
    def addresses(self):
        snap=self.current
        return snap.addresses if snap is not None and snap.fresh() and self.gateway.running else ()

    def status(self):
        ready=bool(self.addresses)
        healthy=self.local_health() if ready else False
        return {'state':'ready' if ready else ('waiting_dependency' if self.reason=='ready' else self.reason),
                'reason':self.detail,'local_ready':ready,
                'local_health':'healthy' if healthy is True else 'unhealthy' if healthy is False else 'unknown',
                'external':'unknown'}

    def revoke(self,reason='waiting_dependency',detail=None):
        self.current=None
        self.epoch+=1
        self.reason=reason
        self.detail=detail or reason
        self.gateway.revoke()
        if self.diagnostics: self.diagnostics.component('npm','unknown')

    def expire(self,expected=None):
        snap=self.current
        if expected is not None and snap is not expected: return
        if snap is not None and not snap.fresh(): self.revoke('proof_expired')

    async def refresh(self):
        self.expire()
        if self.store.administration.busy or self.store.migrating:
            self.progress=time.monotonic()
            return False
        try:
            async with self.store.administration.exclusive('npm_dependency'):
                snap=await self.dependency.snapshot(self.options)
                if self.store.migrating: self.revoke(); return False
                if self.current is None or self.current.addresses!=snap.addresses or not self.gateway.running:
                    self.revoke()
                    epoch=self.epoch
                    await self.gateway.start(snap)
                    if self.epoch!=epoch or self.store.migrating or not snap.fresh():
                        self.revoke(); return False
                if not snap.fresh(): self.revoke('proof_expired'); return False
                self.current=snap
                self.reason='ready'
                self.detail='verified'
                if self.diagnostics: self.diagnostics.component('npm','healthy')
                return True
        except asyncio.CancelledError:
            self.revoke()
            raise
        except Exception as error:
            self.revoke('invalid_candidate' if isinstance(error,InvalidNpmCandidate) else 'waiting_dependency',
                        error.reason if isinstance(error,DependencyUnavailable) else 'invalid_candidate' if isinstance(error,InvalidNpmCandidate) else 'gateway_unavailable')
            return False
        finally:
            self.progress=time.monotonic()

    async def run(self):
        import secrets
        delay=2
        while True:
            healthy=await self.refresh()
            delay=5 if healthy else min(20,delay*2)
            await asyncio.sleep(delay+secrets.randbelow(1000)/1000)

    async def guard(self):
        while True:
            self.expire()
            await asyncio.sleep(.5)
