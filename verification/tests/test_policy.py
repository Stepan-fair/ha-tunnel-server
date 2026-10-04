import importlib
import time
from pathlib import Path
import pytest
from server.app.store import Store


@pytest.fixture
def setup(tmp_path):
    assert Path('server/app/policy.py').exists(), 'Authorization policy not implemented'
    from server.app.identity import Authority
    from server.app.policy import authorize
    store = Store(tmp_path / 's.db', 'example.com')
    now = int(time.time())
    a = store.redeem(store.issue('a', now).code, now)
    b = store.redeem(store.issue('b', now).code, now)
    authority = Authority(tmp_path / 'identity.key', 'http://127.0.0.1:19000')
    return store, authority, authorize, a, b


def test_identity_bound_on_login_and_work_connections(setup):
    store, authority, authorize, a, b = setup
    jwt = authority.issue(a.client_id)
    assert authorize('Login', {'user':a.client_id,'privilege_key':jwt}, store, authority)['reject'] is False
    assert authorize('Login', {'user':b.client_id,'privilege_key':jwt}, store, authority)['reject'] is True
    for op in ['Ping', 'NewWorkConn']:
        assert authorize(op, {'user':{'user':b.client_id},'privilege_key':jwt}, store, authority)['reject'] is True
        assert authorize(op, {'user':{'user':a.client_id},'privilege_key':jwt}, store, authority)['reject'] is False


def test_allowed_proxy_and_revocation(setup):
    store, authority, authorize, a, b = setup
    content = {'user':{'user':a.client_id}, 'proxy_type':'http',
               'proxy_name':a.client_id+'.ha', 'custom_domains':[a.domain]}
    assert not authorize('NewProxy',content,store,authority)['reject']
    store.revoke(a.client_id)
    assert authorize('NewProxy',content,store,authority)['reject']
    assert authorize('Login',{'user':a.client_id,'privilege_key':authority.issue(a.client_id)},store,authority)['reject']


def test_bandwidth_limit_controlled_only_by_server(setup):
    store,authority,authorize,a,b=setup
    content={'user':{'user':a.client_id},'proxy_type':'http',
             'proxy_name':a.client_id+'.ha','custom_domains':[a.domain],
             'bandwidth_limit':'999MB','bandwidth_limit_mode':'client'}
    result=authorize('NewProxy',content,store,authority,bandwidth_limit_mb=3)
    assert result['content']['bandwidth_limit']=='3MB'
    assert result['content']['bandwidth_limit_mode']=='server'
    for invalid in (0,-1,1001,True,'3'):
        with pytest.raises(ValueError):
            authorize('NewProxy',content,store,authority,bandwidth_limit_mb=invalid)


@pytest.mark.parametrize('override', [
    {'proxy_type':'tcp'}, {'proxy_type':'udp'}, {'proxy_type':'stcp'},
    {'custom_domains':['b.example.com']}, {'custom_domains':['A.example.com']},
    {'custom_domains':['a.example.com','b.example.com']}, {'custom_domains':[]},
    {'group':'shared'}, {'group_key':'x'}, {'subdomain':'b'}, {'remote_port':22},
    {'locations':['/']}, {'host_header_rewrite':'b'}, {'headers':{'Host':'b'}},
    {'proxy_name':'other.ha'}, {'unknown_security_field':True},
])
def test_rejects_proxy_escalations(setup, override):
    store, authority, authorize, a, b = setup
    content = {'user':{'user':a.client_id},'proxy_type':'http',
               'proxy_name':a.client_id+'.ha','custom_domains':[a.domain],**override}
    assert authorize('NewProxy',content,store,authority)['reject']


def test_bad_signatures_and_expiration(setup):
    store, authority, authorize, a, b = setup
    import jwt
    fake = jwt.encode({'sub':a.client_id}, 'wrong'*8, algorithm='HS256')
    for token in ['garbage', fake, authority.issue(a.client_id, now=int(time.time())-7200)]:
        assert authorize('Login',{'user':a.client_id,'privilege_key':token},store,authority)['reject']


def test_malformed_and_unknown_operations_fail_closed(setup):
    store, authority, authorize, a, b = setup
    for content in [None, [], {}, {'user':None}, {'user':{'user':a.client_id},'privilege_key':[]}]:
        assert authorize('Login',content,store,authority)['reject']
    assert authorize('Surprise',{'user':a.client_id},store,authority)['reject']
