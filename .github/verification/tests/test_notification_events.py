import copy
import pytest


def snapshot(**changes):
    result = dict(client_id='a'*32, domain='alpha.example.org', access_state='allowed',
                  deadline=2000000, revision=1, generation=1, server_instance_id='b'*32,
                  billing=dict(mode='monthly', price_kopecks=100, balance_kopecks=0,
                    paid_from=1000, paid_until=2000000, funds_until=2000000,
                    projection_kind='current', projection_limited=False,
                    pause_reason=None, timezone='UTC', updated_at=1000000))
    result.update(changes)
    return result


def assess(s, now=1000000, reliable=True, flags=None):
    from shared.notifications import assess_access
    return assess_access(s, now=now, reliable_time=reliable, warning_days=3, enabled=flags)


def test_paid_zero_and_negative_balance_are_low_not_stopped():
    for balance in (0,-100):
        s=snapshot(); s['billing']['balance_kopecks']=balance
        assert assess(s).kind=='funds_low'
    s['billing']['balance_kopecks']=100
    assert assess(s) is None


def test_coverage_threshold_selects_highest_enabled_reason():
    s=snapshot(); s['billing']['funds_until']=s['billing']['paid_until']=1100000
    assert assess(s).kind=='access_ending'
    assert assess(s,flags={'access_ending':False}).kind=='funds_low'
    s['billing']['funds_until']=3000000
    assert assess(s).kind=='funds_low'
    s['billing']['balance_kopecks']=100
    assert assess(s) is None


@pytest.mark.parametrize('reason,state', [('manual','paused'),('revoked','revoked'),
    ('pending','pending'),('clock_error','clock_error')])
def test_nonfinancial_exclusions(reason,state):
    s=snapshot(access_state=state); s['billing']['pause_reason']=reason
    assert assess(s) is None


def test_free_legacy_and_fresh_server_evidence():
    s=snapshot(); s['billing'].update(price_kopecks=0,funds_until=None,projection_kind='unlimited')
    assert assess(s) is None
    s=snapshot(access_state='expired',deadline=900000)
    s['billing'].update(mode='legacy',projection_kind='legacy',paid_from=None,paid_until=None,funds_until=None)
    assert assess(s).kind=='access_stopped'
    assert assess(s,reliable=False) is None
    s['fresh']=False
    assert assess(s) is None
    s=snapshot(access_state='expired'); s['billing'].update(pause_reason='insufficient_funds',paid_until=900000,funds_until=None,projection_kind='insufficient')
    assert assess(s).kind=='access_stopped'
    assert assess(s,flags={'access_stopped':False}) is None


def test_untrusted_domain_and_invalid_billing_never_form_payload():
    with pytest.raises(ValueError): assess(snapshot(domain='{{ secret }}'))
    s=snapshot(); s['billing']['balance_kopecks']='secret'
    with pytest.raises(ValueError): assess(s)
    s=snapshot(); before=copy.deepcopy(s); alert=assess(s)
    assert s==before and '100' not in alert.message


def test_state_durable_ack_settings_revision_and_replay(tmp_path):
    from shared.notification_state import NotificationState, SettingsConflict
    p=tmp_path/'notifications.json'; st=NotificationState(p,'server')
    initial=st.view(); desired={'title':'HA Tunnel','message':'alpha.example.org','kind':'funds_low','mobile_key':'low:1'}
    ident=st.observe('account','financial','one',desired)
    assert p.exists() and st.view()['revision']==initial['revision']
    assert not st.acknowledge(ident)  # No observed version proof.
    st.bind_card(ident,st.records[ident]['version'],'created-one')
    assert st.acknowledge(ident,version=st.records[ident]['version'],created_at='created-one')
    restored=NotificationState(p,'server')
    assert restored.records[ident]['acknowledged']
    settings=initial['settings']; settings['warning_days']=7
    rev=st.configure(settings,0,'save-one')['revision']
    assert rev==1
    assert st.configure(settings,0,'save-one')['revision']==1
    with pytest.raises(SettingsConflict): st.configure(settings,0,'save-two')
    st.observe('account','financial','two',desired)
    assert not st.acknowledge(ident,version='old',created_at='created-one')
    assert st.view()['revision']==1


@pytest.mark.parametrize('raw',[b'{',b'{"schema":1,"schema":1}',b'['*2000,b'x'*(1024*1024+1)],ids=['invalid','duplicate','deep','oversize'])
def test_corruption_preserves_exact_original_and_stops_only_notifications(tmp_path,raw):
    from shared.notification_state import NotificationState, NotificationUnavailable
    p=tmp_path/'notifications.json'; p.write_bytes(raw)
    st=NotificationState(p,'client')
    assert st.view()['diagnostic']=='storage_error'
    with pytest.raises(NotificationUnavailable): st.observe('account','financial','one',None)
    assert p.read_bytes()==raw


@pytest.mark.parametrize('changes',[{'warning_days':0},{'warning_days':31},{'warning_days':True},
    {'mobile_targets':['notify.telegram']},{'enabled':'yes'}])
def test_settings_reject_invalid_values(tmp_path,changes):
    from shared.notification_state import NotificationState
    st=NotificationState(tmp_path/'n.json','client'); settings=st.view()['settings']; settings.update(changes)
    with pytest.raises(ValueError): st.configure(settings,0,'command')


def test_portable_restore_rotates_only_delivery_namespace_and_queues_own_cleanup(tmp_path):
    from shared.notification_state import NotificationState
    st=NotificationState(tmp_path/'n.json','server'); settings=st.view()['settings']; settings['mobile_targets']=['notify.mobile_app_test']
    st.configure(settings,0,'phone')
    ident=st.observe('server/account','financial','one',{'title':'HA Tunnel','message':'Synthetic','kind':'funds_low','mobile_key':'one'})
    old=st.data['namespace']; st.reset_namespace()
    restored=NotificationState(tmp_path/'n.json','server')
    assert restored.data['namespace']!=old and restored.view()['settings']['mobile_targets']==[]
    assert ident in restored.data['cleanup'] and not restored.records
    assert restored.identifier('server/account','financial')!=ident


def test_notification_read_is_bounded_even_without_stat(tmp_path,monkeypatch):
    from shared.notification_state import NotificationState,MAX_BYTES
    from pathlib import Path
    import io
    path=tmp_path/'n.json'; reads=[]; original=Path.open
    class Stream(io.BytesIO):
        def read(self,size=-1): reads.append(size); return super().read(size)
    def opened(self,*args,**kw):
        return Stream(b'x'*(MAX_BYTES+500)) if self==path else original(self,*args,**kw)
    monkeypatch.setattr(Path,'open',opened)
    st=NotificationState(path,'client')
    assert reads==[MAX_BYTES+1] and st.view()['diagnostic']=='storage_error'


def test_malformed_episode_context_preserves_original(tmp_path):
    from shared.notification_state import NotificationState,encoded
    p=tmp_path/'n.json'; state=NotificationState(p,'server')
    ident=state.observe('account','financial','one',None)
    state.data['records'][ident]['context']={'stopped':'false'}
    raw=encoded(state.data); p.write_bytes(raw)
    restored=NotificationState(p,'server')
    assert restored.diagnostic=='storage_error' and p.read_bytes()==raw
