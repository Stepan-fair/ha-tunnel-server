"""TLS-verified, bounded status polling independent of tunnel permission."""
import json
from aiohttp import ClientSession, ClientTimeout, TCPConnector, DummyCookieJar, encode_basic_auth
from shared.validation import origin
from shared.telemetry import parse_telemetry
from shared.billing_status import validate_billing


def validate_status(data, client_id):
    if not isinstance(data, dict) or data.get('client_id') != client_id or data.get('access_state') not in ('allowed','paused','expired','revoked','clock_error','pending'):
        raise ValueError('Invalid access status')
    for name in ('revision','generation'):
        if type(data.get(name)) is not int or data[name]<0: raise ValueError('Invalid access revision')
    if any(name in data for name in ('secret','secret_hash','status_secret_hash','code','code_hash','code_ciphertext','invitation')):
        raise ValueError('Unexpected private fields')
    if 'billing' in data: validate_billing(data['billing'])
    if 'telemetry' in data: parse_telemetry(data['telemetry'],0)
    return data


async def bounded_json(response):
    if response.status != 200: raise ValueError('Status temporarily unavailable')
    raw=bytearray()
    async for chunk in response.content.iter_chunked(8192):
        raw.extend(chunk)
        if len(raw)>8192: raise ValueError('Status too large')
    return json.loads(raw)


class ClientStatusClient:
    def __init__(self, server_url):
        self.server_url=origin(server_url)
        self.session=None

    async def close(self):
        if self.session is not None:
            await self.session.close()
            self.session=None

    async def fetch(self, client_id, secret):
        if self.session is None or self.session.closed:
            # Polling is every 15 seconds. Keep the verified connection longer
            # than that, with a small bounded pool and no ambient cookies/auth.
            self.session=ClientSession(timeout=ClientTimeout(total=10), trust_env=False,
                connector=TCPConnector(limit=2,limit_per_host=2,keepalive_timeout=45),
                cookie_jar=DummyCookieJar())
        async with self.session.get(self.server_url+'/health', allow_redirects=False) as response:
            health=await bounded_json(response)
        if not isinstance(health,dict) or health.get('protocol')!=1 or health.get('status')!='ok': raise ValueError('Invalid server health')
        if 'capabilities' not in health: return None
        if not isinstance(health['capabilities'],list) or 'access-v1' not in health['capabilities']: raise ValueError('Unsupported access capability')
        async with self.session.post(self.server_url+'/v1/client/status', allow_redirects=False,
                headers={'Authorization':encode_basic_auth(client_id,secret)},
                json={'capabilities':['access-v1','telemetry-v1']}) as response:
            return validate_status(await bounded_json(response),client_id)
