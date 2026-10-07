import pytest
from server.app import network_checks as checks


@pytest.fixture
def network(monkeypatch):
    async def addresses(host): return ['8.8.8.8']
    async def get(url,ips): return {'ip':'8.8.8.8'} if 'ipify' in url else {'status':'ok','protocol':1}
    monkeypatch.setattr(checks,'public_addresses',addresses)
    monkeypatch.setattr(checks,'get_json',get)


async def test_echo_does_not_prove_wan_or_static(network):
    result=await checks.check_network({'server_url':'https://tunnel.example.org'},None,False)
    assert result['external']['status']=='ok'
    assert result['wan']['status']==result['static']['status']=='unknown'


@pytest.mark.parametrize('ip',['100.64.1.2','192.168.1.2','10.0.0.1','127.0.0.1'])
async def test_nonpublic_wan_problem(network,ip):
    result=await checks.check_network({'server_url':'https://tunnel.example.org'},ip,False)
    assert result['wan']['status']=='problem'
    assert 'CGNAT' not in result['wan']['message'] or ip.startswith('100.64')


async def test_timeout_unknown_and_skip_echo(monkeypatch,network):
    calls=[]
    async def fail(url,ips): calls.append(url); raise TimeoutError()
    monkeypatch.setattr(checks,'get_json',fail)
    result=await checks.check_network({'server_url':'https://tunnel.example.org','skip_external':True},None,False)
    assert result['external']['status']==result['tls']['status']=='unknown'
    assert all('ipify' not in url for url in calls)


async def test_dns_and_tls_are_separate(monkeypatch,network):
    import aiohttp
    async def fail(url,ips): raise aiohttp.ClientSSLError(None,OSError())
    monkeypatch.setattr(checks,'get_json',fail)
    result=await checks.check_network({'server_url':'https://tunnel.example.org'},'8.8.8.8',True)
    assert result['dns']['status']=='ok' and result['tls']['status']=='problem'
    assert result['static']['status']=='ok' and 'провайдер' in result['static']['message']


@pytest.mark.parametrize('url',['http://localhost','https://127.0.0.1','https://tunnel.example.org@localhost','https://tunnel.example.org/path'])
async def test_rejects_unsafe_origin(network,url):
    with pytest.raises(ValueError): await checks.check_network({'server_url':url},None,False)


async def test_private_dns_never_contacted(monkeypatch,network):
    async def addresses(host): raise ValueError('Nonpublic address')
    async def forbidden(url,ips): raise AssertionError('Must not fetch unsafe DNS')
    monkeypatch.setattr(checks,'public_addresses',addresses)
    monkeypatch.setattr(checks,'get_json',forbidden)
    result=await checks.check_network({'server_url':'https://tunnel.example.org','skip_external':True},None,False)
    assert result['dns']['status']=='problem'


async def test_dns_actual_address_validation(monkeypatch):
    import socket
    monkeypatch.setattr(socket,'getaddrinfo',lambda *args:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.168.1.1',443))])
    with pytest.raises(ValueError,match='Nonpublic'): await checks.public_addresses('tunnel.example.org')


@pytest.mark.parametrize('status,chunks',[(302,[b'{}']),(200,[b'x'*65536,b'x']),(200,[b'not json'])])
async def test_http_rejects_redirect_large_or_malformed(monkeypatch,status,chunks):
    class Content:
        async def iter_chunked(self,size):
            for chunk in chunks: yield chunk
    class Response:
        content=Content()
        async def __aenter__(self): return self
        async def __aexit__(self,*args): pass
    response=Response(); response.status=status
    class Session:
        def __init__(self,connector,timeout):
            assert timeout.total==5; self.connector=connector
        async def __aenter__(self): return self
        async def __aexit__(self,*args): await self.connector.close()
        def get(self,url,**kwargs):
            assert kwargs.get('allow_redirects') is False
            assert kwargs.get('ssl') is not False
            return response
    monkeypatch.setattr(checks.aiohttp,'ClientSession',Session)
    with pytest.raises(ValueError): await checks.get_json('https://tunnel.example.org/health',['8.8.8.8'])


async def test_resolver_pins_checked_addresses():
    resolver=checks.PinnedResolver('tunnel.example.org',['8.8.8.8'])
    assert (await resolver.resolve('tunnel.example.org',443))[0]['host']=='8.8.8.8'
    with pytest.raises(ValueError): await resolver.resolve('other.example.org',443)
