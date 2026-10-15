"""Real proc-format files exercise the acceptance classifier without FRP/Linux."""
import json
import os
from types import SimpleNamespace

import pytest


EPOCH_A='a'*32
EPOCH_B='b'*32
NONCE_A='1'*64
NONCE_B='2'*64


def proc_snapshot(tmp_path,monkeypatch,rows):
    from tests.frp_socket_evidence import established_sockets
    process=tmp_path/'321'; (process/'fd').mkdir(parents=True,exist_ok=True)
    (process/'net').mkdir(exist_ok=True)
    links={}
    lines=['sl local_address rem_address st tx_queue rx tr tm retr uid timeout inode']
    for index,(inode,remote_port,state,owned) in enumerate(rows):
        if owned:
            fd=process/'fd'/str(index); fd.touch(); links[fd]=f'socket:[{inode}]'
        lines.append(f'{index}: 0100007F:1B58 0100007F:{remote_port:04X} {state} 0:0 0:0 0 0 0 {inode}')
    (process/'net'/'tcp').write_text('\n'.join(lines))
    def readlink(path):
        if path not in links: raise FileNotFoundError()
        return links[path]
    monkeypatch.setattr(os,'readlink',readlink)
    return established_sockets(321,7000,proc_root=tmp_path)


def test_pending_rejected_and_work_transports_are_not_login_controls(tmp_path,monkeypatch):
    from tests.frp_socket_evidence import ControlEvidence
    sockets=proc_snapshot(tmp_path,monkeypatch,[
        (10,40001,'01',True),(11,40002,'01',True),(12,40003,'01',True),
        (13,40004,'01',True),(14,40005,'08',True),(15,40006,'01',False)])
    evidence=ControlEvidence()
    evidence.accept('127.0.0.1:40001',EPOCH_A,NONCE_A,sockets)
    evidence.activate(EPOCH_A)
    assert evidence.sample(EPOCH_A,NONCE_A,sockets)=={
        'raw_all':4,'accepted':1,'unclassified':3,'current_present':True,'current_activated':True}
    assert evidence.ready(EPOCH_A,NONCE_A,sockets)
    assert evidence.require_current(EPOCH_A,NONCE_A,sockets)==1


def test_superseded_accepted_socket_is_still_counted_as_duplicate(tmp_path,monkeypatch):
    from tests.frp_socket_evidence import ControlEvidence
    sockets=proc_snapshot(tmp_path,monkeypatch,[(10,40001,'01',True),(11,40002,'01',True)])
    evidence=ControlEvidence()
    evidence.accept('127.0.0.1:40001',EPOCH_A,NONCE_A,sockets); evidence.activate(EPOCH_A)
    evidence.accept('127.0.0.1:40002',EPOCH_B,NONCE_B,sockets); evidence.activate(EPOCH_B)
    assert evidence.sample(EPOCH_B,NONCE_B,sockets)['accepted']==2
    assert not evidence.ready(EPOCH_B,NONCE_B,sockets)
    with pytest.raises(AssertionError): evidence.require_current(EPOCH_B,NONCE_B,sockets)
    current={item for item in sockets if item.inode==11}
    assert evidence.require_current(EPOCH_B,NONCE_B,current)==1
    assert len(evidence.history)==2  # Closed/superseded identities are never discarded.


@pytest.mark.parametrize('condition',['only-old','no-activation','wrong-epoch','wrong-nonce',
                                    'reused-port','reused-inode','superseded-epoch'])
def test_one_socket_without_exact_current_activation_is_not_positive(tmp_path,monkeypatch,condition):
    from tests.frp_socket_evidence import ControlEvidence
    sockets=proc_snapshot(tmp_path,monkeypatch,[(10,40001,'01',True),(11,40002,'01',True)])
    evidence=ControlEvidence()
    evidence.accept('127.0.0.1:40001',EPOCH_A,NONCE_A,sockets); evidence.activate(EPOCH_A)
    evidence.accept('127.0.0.1:40002',EPOCH_B,NONCE_B,sockets)
    if condition!='no-activation': evidence.activate(EPOCH_B)
    current={item for item in sockets if item.inode==(10 if condition=='only-old' else 11)}
    epoch=EPOCH_A if condition=='wrong-epoch' else EPOCH_B
    nonce=NONCE_A if condition=='wrong-nonce' else NONCE_B
    if condition=='reused-port':
        current=proc_snapshot(tmp_path,monkeypatch,[(99,40002,'01',True)])
    if condition=='reused-inode':
        current=proc_snapshot(tmp_path,monkeypatch,[(11,40003,'01',True)])
    if condition=='superseded-epoch':
        current={item for item in sockets if item.inode==10}
        epoch,nonce=EPOCH_A,NONCE_A
    assert not evidence.ready(epoch,nonce,current)
    with pytest.raises(AssertionError): evidence.require_current(epoch,nonce,current)


@pytest.mark.parametrize('address',['','127.0.0.1','127.0.0.1:0','127.0.0.1:65536',
    '127.0.0.1:40099','::1:40001','example.org:40001',None])
def test_unmapped_or_malformed_login_address_fails_closed(tmp_path,monkeypatch,address):
    from tests.frp_socket_evidence import ControlEvidence
    sockets=proc_snapshot(tmp_path,monkeypatch,[(10,40001,'01',True)])
    evidence=ControlEvidence()
    with pytest.raises(ValueError): evidence.accept(address,EPOCH_A,NONCE_A,sockets)
    assert not evidence.history


def test_unknown_activation_and_history_overflow_fail_closed(tmp_path,monkeypatch):
    from tests.frp_socket_evidence import ControlEvidence
    sockets=proc_snapshot(tmp_path,monkeypatch,[(10,40001,'01',True),(11,40002,'01',True)])
    evidence=ControlEvidence(max_logins=1)
    with pytest.raises(ValueError): evidence.activate(EPOCH_A)
    evidence.accept('127.0.0.1:40001',EPOCH_A,NONCE_A,sockets)
    assert evidence.latest(NONCE_A).epoch==EPOCH_A
    assert evidence.latest(NONCE_B) is None
    with pytest.raises(ValueError): evidence.accept('127.0.0.1:40002',EPOCH_B,NONCE_B,sockets)
    assert len(evidence.history)==1


def test_expiring_before_expected_login_allows_old_retry_to_capture_reservation():
    from server.app.admission import Admission
    now=[1000.0]
    admission=Admission(clock=lambda:now[0])
    assert admission.login('client',0,'',NONCE_A)
    now[0]+=16
    assert admission.login('client',0,'',NONCE_A)
    assert admission.login('client',0,'',NONCE_B) is None


def test_expiry_at_expected_login_preserves_eight_handoffs_and_rejects_old_retries():
    from server.app.admission import Admission
    from tests.frp_socket_evidence import ReservationClock
    clock=ReservationClock(lambda:1000.0)
    admission=Admission(clock=clock)
    previous=[]
    for index in range(8):
        nonce=f'{index:064x}'
        if previous: clock.arm(lambda:nonce)
        for old in previous[:-1]:
            clock.before_login(old)
            assert admission.login('client',0,'',old) is None
        if previous:
            # Even a reconnect by the incumbent cannot extend its reservation.
            clock.before_login(previous[-1])
            assert admission.login('client',0,'',previous[-1])
        clock.before_login(nonce)
        assert admission.login('client',0,'',nonce)
        assert clock()==1000.0+16*index
        clock.before_login(nonce)
        assert clock()==1000.0+16*index  # Expiry injection is one-shot.
        for old in previous:
            clock.before_login(old)
            assert admission.login('client',0,'',old) is None
        previous.append(nonce)


@pytest.mark.parametrize('candidate',[{}, {'metadatas':{}}, {'metadatas':{'keep':'value'}}])
async def test_old_login_during_real_runtime_verify_reaches_policy(tmp_path,monkeypatch,candidate):
    from client.app.runtime import ClientRuntime
    from server.app.admission import Admission
    from server.app.identity import Authority
    from server.app.policy import authorize
    from server.app.store import Store
    from tests.frp_socket_evidence import ReservationClock,runtime_process_nonce
    clock=ReservationClock(lambda:1000.0)
    store=Store(tmp_path/'db','example.org',clock=lambda:2000)
    client=store.redeem(store.issue('alpha',1000).code,1001)
    store.admission=Admission(clock=clock)
    authority=Authority(tmp_path/'key','http://127.0.0.1:19000')
    policy_results=[]
    def login(nonce):
        clock.before_login(nonce)
        result=authorize('Login',{'user':client.client_id,'privilege_key':authority.issue(client.client_id),
            'metas':{'ha_tunnel_process':nonce}},store,authority)
        policy_results.append(result['reject'])
        return result
    first=login(NONCE_A)
    assert not first['reject']
    runtime=ClientRuntime('unused-frpc',tmp_path/'runtime.json')
    clock.arm(lambda:runtime_process_nonce(runtime.path))
    assert runtime_process_nonce(runtime.path) is None
    phases=[]
    check=SimpleNamespace(returncode=None)
    check.kill=lambda:setattr(check,'returncode',-1)
    async def verified():
        if check.returncode is not None: return check.returncode
        # Real start has atomically written candidate, but real _launch has not
        # written the process nonce yet. Insert the native retry at this await.
        assert json.loads(runtime.path.read_text())==candidate
        assert not login(NONCE_A)['reject']
        assert clock()==1000.0 and clock.expected_nonce is not None
        assert policy_results==[False,False]
        phases.append('verify-wait')
        check.returncode=0
        return 0
    check.wait=verified
    async def spawn(*args):
        if args[0]=='verify':
            phases.append('verify-spawn')
            return check,[]
        assert args==('-c',str(runtime.path))
        assert phases==['verify-spawn','verify-wait']
        # ClientRuntime._launch must generate this nonce, not the test double.
        new_nonce=runtime_process_nonce(runtime.path)
        assert len(new_nonce)==64 and new_nonce!=NONCE_A
        assert not login(NONCE_A)['reject']
        assert clock()==1000.0 and clock.expected_nonce is not None
        new=login(new_nonce)
        assert not new['reject'] and clock()==1016.0
        assert clock.expected_nonce is None
        assert new['content']['metas']['ha_tunnel_session']!=first['content']['metas']['ha_tunnel_session']
        assert not login(new_nonce)['reject'] and clock()==1016.0
        assert login(NONCE_A)['reject'] and clock()==1016.0
        phases.append('launch-spawn')
        return SimpleNamespace(returncode=None,pid=123),[]
    monkeypatch.setattr(runtime,'_spawn',spawn)
    await runtime.start(candidate)  # Actual start/_launch/atomic writes/wait order.
    assert phases==['verify-spawn','verify-wait','launch-spawn']
    assert policy_results==[False,False,False,False,False,True]
    assert store.admission.counts()=={'owners':1,'reservations':1,'active':0}


@pytest.mark.parametrize('raw',['{','[]','{"metadatas":null}'])
def test_nonce_provider_does_not_suppress_malformed_config(tmp_path,raw):
    from tests.frp_socket_evidence import runtime_process_nonce
    path=tmp_path/'runtime.json'; path.write_text(raw)
    with pytest.raises((ValueError,TypeError,AttributeError)):
        runtime_process_nonce(path)
