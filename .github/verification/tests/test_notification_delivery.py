import asyncio
import json
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer


@pytest.fixture
async def core(monkeypatch):
    from shared import ha_notifications as module
    class Core:
        def __init__(self):
            self.cards={}; self.clients=set(); self.calls=[]; self.serial=0; self.mobile=[]
            self.catalog=[{'domain':'notify','services':{'mobile_app_test':{'name':'Test'},'telegram':{}}}]
            self.catalog_status=200; self.split=False; self.create_status=200; self.redirect=None
            self.before_create=None; self.before_current=None; self.send_reply=None; self.service_unavailable=False
        async def event(self,kind,cards):
            for ws in tuple(self.clients):
                await ws.send_json({'id':1,'type':'event','event':{'type':kind,'notifications':cards}})
        async def services(self,r):
            assert r.headers['Authorization']=='Bearer synthetic-token'
            raw=json.dumps(self.catalog).encode()
            if self.split:
                response=web.StreamResponse(status=self.catalog_status); await response.prepare(r)
                await response.write(raw[:7]); await asyncio.sleep(.01); await response.write(raw[7:]); await response.write_eof(); return response
            return web.Response(body=raw,status=self.catalog_status)
        async def send(self,r):
            assert r.headers['Authorization']=='Bearer synthetic-token'
            data=await r.json(); self.calls.append((r.path,data))
            if self.redirect: raise web.HTTPFound(self.redirect)
            if self.service_unavailable: return web.json_response({},status=503)
            if self.send_reply is not None: return web.Response(body=self.send_reply)
            if r.match_info['domain']=='persistent_notification':
                ident=data['notification_id']
                if r.match_info['service']=='create':
                    if self.before_create: await self.before_create()
                    self.serial+=1; card={**data,'created_at':f'2026-10-15T10:00:{self.serial:06d}+00:00'}
                    kind='updated' if ident in self.cards else 'added'; self.cards[ident]=card
                    await self.event(kind,{ident:card})
                    return web.json_response([],status=self.create_status)
                card=self.cards.pop(ident,None)
                if card: await self.event('removed',{ident:card})
            else: self.mobile.append(data)
            return web.json_response([])
        async def ws(self,r):
            if self.redirect: raise web.HTTPFound(self.redirect)
            ws=web.WebSocketResponse(); await ws.prepare(r)
            await ws.send_json({'type':'auth_required'})
            auth=await ws.receive_json(); assert auth=={'type':'auth','access_token':'synthetic-token'}
            await ws.send_json({'type':'auth_ok'})
            sub=await ws.receive_json(); assert sub=={'id':1,'type':'persistent_notification/subscribe'}
            await ws.send_json({'id':1,'type':'result','success':True,'result':None})
            self.clients.add(ws)
            if self.before_current: await self.before_current()
            await ws.send_json({'id':1,'type':'event','event':{'type':'current','notifications':dict(self.cards)}})
            try:
                async for _ in ws: pass
            finally: self.clients.discard(ws)
            return ws
        async def dismiss(self,ident):
            card=self.cards.pop(ident); await self.event('removed',{ident:card})
    instance=Core(); app=web.Application()
    app.add_routes([web.get('/api/services',instance.services),web.post('/api/services/{domain}/{service}',instance.send),web.get('/websocket',instance.ws)])
    async with TestServer(app) as server:
        monkeypatch.setattr(module,'CORE_API',str(server.make_url('/api')))
        monkeypatch.setattr(module,'CORE_WS',str(server.make_url('/websocket')).replace('http:','ws:'))
        yield instance
    for ws in tuple(instance.clients): await ws.close()


async def test_adapter_fixed_calls_split_catalog_and_real_observer(core):
    from shared.ha_notifications import HaNotifications
    ha=HaNotifications('synthetic-token'); core.split=True
    assert await ha.services()==['notify.mobile_app_test']
    events=[]; task=asyncio.create_task(ha.observe(lambda e: events.append(e)))
    try:
        await asyncio.wait_for(ha.ready.wait(),1)
        await ha.create('ha_tunnel_test','HA Tunnel','Synthetic')
        await ha.mobile('notify.mobile_app_test','ha_tunnel_test','HA Tunnel','Synthetic')
        await ha.dismiss('ha_tunnel_test'); await asyncio.sleep(.03)
        assert [e['type'] for e in events]==['current','added','removed']
        assert core.mobile==[{'title':'HA Tunnel','message':'Synthetic','data':{'tag':'ha_tunnel_test'}}]
    finally: task.cancel(); await asyncio.gather(task,return_exceptions=True); await ha.close()


async def test_adapter_rejects_arbitrary_service_and_bounded_catalog(core):
    from shared.ha_notifications import HaNotifications
    ha=HaNotifications('synthetic-token')
    try:
        for service in ('notify.telegram','notify.mobile_app_unknown','notify.mobile_app_a/../../restart'):
            with pytest.raises(ValueError): await ha.mobile(service,'ha_tunnel_test','title','message')
        core.catalog=[{'domain':'notify','services':{'mobile_app_'+str(i):{} for i in range(513)}}]
        with pytest.raises(ValueError): await ha.services()
        core.catalog=['x'*(2*1024*1024)]
        with pytest.raises(ValueError): await ha.services()
        with pytest.raises(ValueError): await ha.create('ha_tunnel_test','x'*129,'test')
        with pytest.raises(ValueError): await ha.create('ha_tunnel_test','test','x'*2049)
        assert not core.calls
    finally: await ha.close()


async def test_rest_and_ws_redirect_never_reach_target(core):
    from shared.ha_notifications import HaNotifications
    hits=[]
    async def target(r): hits.append(dict(r.headers)); return web.Response()
    app=web.Application(); app.router.add_route('*','/{tail:.*}',target)
    async with TestServer(app) as server:
        core.redirect=str(server.make_url('/target')); ha=HaNotifications('synthetic-token')
        try:
            with pytest.raises(ValueError): await ha.create('ha_tunnel_test','Test','Synthetic')
            with pytest.raises(ValueError): await ha.observe(lambda e:None)
            assert hits==[]
        finally: await ha.close()


async def test_bad_ws_frame_fails_closed_and_quiet_observer_stays(core):
    from shared.ha_notifications import HaNotifications
    ha=HaNotifications('synthetic-token'); events=[]
    task=asyncio.create_task(ha.observe(lambda e:events.append(e)))
    try:
        await asyncio.wait_for(ha.ready.wait(),1)
        await asyncio.sleep(.02); assert not task.done()
        for ws in tuple(core.clients): await ws.send_str('{')
        with pytest.raises(ValueError): await task
        assert len(events)==1
    finally: task.cancel(); await asyncio.gather(task,return_exceptions=True); await ha.close()


async def test_send_response_and_ws_frame_limits(core):
    from shared.ha_notifications import HaNotifications,FRAME_LIMIT
    ha=HaNotifications('synthetic-token')
    task=asyncio.create_task(ha.observe(lambda e:None))
    try:
        await asyncio.wait_for(ha.ready.wait(),1)
        core.send_reply=b'"'+b'x'*FRAME_LIMIT+b'"'
        with pytest.raises(ValueError): await ha.create('ha_tunnel_test','Test','Synthetic')
        for ws in tuple(core.clients): await ws.send_str('"'+'x'*FRAME_LIMIT+'"')
        with pytest.raises(ValueError): await asyncio.wait_for(task,2)
    finally: task.cancel(); await asyncio.gather(task,return_exceptions=True); await ha.close()


async def test_old_baseline_events_during_create_cannot_ack_current_version(core,tmp_path):
    rows=[current()]; worker=make_worker(tmp_path,core,rows)
    try:
        await worker.tick(); await asyncio.sleep(.02)
        ident=next(iter(core.cards)); old=dict(core.cards[ident])
        rows[0]['billing']['balance_kopecks']=100; worker.refresh()
        rows[0]['billing']['balance_kopecks']=0
        async def delayed_old():
            await core.event('added',{ident:old}); await core.event('removed',{ident:old})
            await asyncio.sleep(.02)
            assert not worker.state.records[ident]['acknowledged']
            assert worker.state.records[ident]['created_at'] is None
        core.before_create=delayed_old
        await worker.tick(); await asyncio.sleep(.02)
        assert core.cards[ident]['created_at']!=old['created_at']
        await core.dismiss(ident); await asyncio.sleep(.02)
        assert worker.state.records[ident]['acknowledged']
    finally: await worker.close()


async def test_slow_create_has_one_operation_budget_and_no_false_ack(core,tmp_path):
    import time
    rows=[current()]; worker=make_worker(tmp_path,core,rows)
    entered=asyncio.Event(); release=asyncio.Event()
    async def slow_create(): entered.set(); await release.wait()
    core.before_create=slow_create
    started=time.monotonic(); tick=asyncio.create_task(worker.tick())
    try:
        await asyncio.wait_for(entered.wait(),1)
        await asyncio.wait_for(tick,6)
        assert time.monotonic()-started<6
        record=worker.state.records[worker.state.identifier(rows[0]['binding_key'],'financial')]
        assert not record['ha_delivered'] and not record['acknowledged']
    finally:
        release.set(); await asyncio.gather(tick,return_exceptions=True); await worker.close()


def make_worker(tmp_path, core, snapshots, *, mono=None, role='server'):
    from shared.ha_notifications import HaNotifications
    from shared.notification_state import NotificationState
    from shared.notifications import NotificationWorker
    from tests.test_notification_events import snapshot
    state=NotificationState(tmp_path/'notifications.json',role)
    ha=HaNotifications('synthetic-token')
    worker=NotificationWorker(state,ha,lambda:snapshots,monotonic=mono or __import__('time').monotonic)
    return worker


def current(**changes):
    from tests.test_notification_events import snapshot
    return {**snapshot(), 'binding_key':'server/account', 'fresh':True,
            'reliable_time':True,'observed_now':1000000,'contact':True,**changes}


async def test_worker_durable_same_id_manual_dismiss_and_new_identical_episode(core,tmp_path):
    rows=[current()]; worker=make_worker(tmp_path,core,rows)
    try:
        await worker.tick(); await asyncio.sleep(.02)
        ident=next(iter(core.cards)); first=dict(core.cards[ident]); version=worker.state.records[ident]['version']
        assert worker.state.path.exists()
        await core.dismiss(ident); await asyncio.sleep(.02)
        assert worker.state.records[ident]['acknowledged']
        await worker.tick(); assert not core.cards
        # Resolve and re-enter the same visible low funds message.
        rows[0]['billing']['balance_kopecks']=100
        await worker.tick()
        rows[0]['billing']['balance_kopecks']=0
        old_session=worker.adapter.observer_session
        await worker.tick(); await asyncio.sleep(.02)
        assert ident in core.cards and worker.state.records[ident]['version']!=version
        assert core.cards[ident]['message']==first['message']
        worker.on_event({'session':old_session,'type':'removed','notifications':{ident:first}})
        await core.event('added',{ident:first}); await core.event('removed',{ident:first}); await asyncio.sleep(.02)
        assert not worker.state.records[ident]['acknowledged']
        await core.dismiss(ident); await asyncio.sleep(.02)
        assert worker.state.records[ident]['acknowledged']
    finally: await worker.close()


async def test_core_restart_rehydrates_without_mobile_replay_and_ack_survives_restart(core,tmp_path):
    from shared.notification_state import NotificationState
    rows=[current()]; worker=make_worker(tmp_path,core,rows)
    settings=worker.state.view()['settings']; settings['mobile_targets']=['notify.mobile_app_test']
    worker.state.configure(settings,0,'mobile')
    try:
        await worker.tick(); await asyncio.sleep(.02)
        ident=next(iter(core.cards)); assert len(core.mobile)==1
        await worker.close(); core.cards.clear()
        worker=make_worker(tmp_path,core,rows)
        await worker.tick(); await asyncio.sleep(.02)
        assert ident in core.cards and len(core.mobile)==1
        await core.dismiss(ident); await asyncio.sleep(.02)
        await worker.close(); worker=make_worker(tmp_path,core,rows)
        await worker.tick(); assert not core.cards and len(core.mobile)==1
    finally: await worker.close()


async def test_delivery_failure_retries_same_card_and_refresh_drops_obsolete_expiry(core,tmp_path):
    rows=[current(access_state='expired')]
    rows[0]['billing'].update(pause_reason='insufficient_funds',paid_until=900000,funds_until=None,projection_kind='insufficient')
    worker=make_worker(tmp_path,core,rows); core.create_status=503
    try:
        await worker.tick(); ident=next(iter(core.cards))
        assert not worker.state.records[ident]['ha_delivered']
        core.create_status=200
        rows[0]=current()
        await worker.tick(); await asyncio.sleep(.02)
        assert 'восстановлен' in core.cards[ident]['message'] and 'не хватит' in core.cards[ident]['message']
        assert 'закончился' not in core.cards[ident]['message']
        count=len(core.calls)
        rows[0]['generation']=99
        await worker.tick(); assert len(core.calls)==count
    finally: await worker.close()


async def test_service_catalog_failure_does_not_block_ha_or_discard_settings(core,tmp_path):
    worker=make_worker(tmp_path,core,[current()]); settings=worker.state.view()['settings']
    settings['mobile_targets']=['notify.mobile_app_test']; worker.state.configure(settings,0,'phone')
    core.catalog_status=503
    try:
        await worker.tick()
        assert core.cards and not core.mobile
        assert worker.view()['settings']['mobile_targets']==['notify.mobile_app_test']
        assert worker.view()['diagnostic']
    finally: await worker.close()


async def test_connection_monotonic_threshold_and_one_recovery_after_sent_warning(core,tmp_path):
    now=[0]; rows=[current(contact=False)]; worker=make_worker(tmp_path,core,rows,mono=lambda:now[0])
    settings=worker.state.view()['settings']; settings.update(connection=True,funds_low=False)
    worker.state.configure(settings,0,'connection')
    try:
        await worker.tick(); now[0]=599; await worker.tick(); assert not core.cards
        now[0]=600; await worker.tick(); assert len(core.cards)==1
        ident=next(iter(core.cards)); assert '10 минут' in core.cards[ident]['message']
        rows[0]['contact']=True; await worker.tick()
        assert 'восстановлена' in core.cards[ident]['message']
        count=len(core.calls); now[0]=900; await worker.tick(); assert len(core.calls)==count
        rows[0]['rejected']=True; await worker.tick(); assert not core.cards
    finally: await worker.close()


async def test_recovery_only_flags_and_disabled_history(core,tmp_path):
    rows=[current()]; worker=make_worker(tmp_path,core,rows)
    settings=worker.state.view()['settings']; settings.update(funds_low=False,access_ending=False,access_stopped=False)
    worker.state.configure(settings,0,'only-recovery')
    try:
        await worker.tick(); assert not core.cards
        rows[0]['access_state']='expired'; rows[0]['billing'].update(pause_reason='insufficient_funds',paid_until=900000,funds_until=None,projection_kind='insufficient')
        await worker.tick(); assert not core.cards
        rows[0]=current(); await worker.tick(); assert 'восстановлен' in next(iter(core.cards.values()))['message']
        settings['enabled']=False; worker.state.configure(settings,1,'off'); await worker.tick(); assert not core.cards
        settings['enabled']=True; worker.state.configure(settings,2,'on'); await worker.tick(); assert not core.cards
    finally: await worker.close()


async def test_stale_client_never_sends_queued_money_or_creates_expiry(core,tmp_path):
    rows=[current(fresh=False)]; worker=make_worker(tmp_path,core,rows)
    try:
        await worker.tick(); assert not core.cards
        rows[0]['fresh']=True; core.create_status=503; await worker.tick()
        rows[0]['fresh']=False; core.cards.clear(); core.create_status=200
        await worker.tick(); assert not core.cards
        rows[0]['rejected']=True; await worker.tick()
        assert all(r['desired'] is None for r in worker.state.records.values())
    finally: await worker.close()


async def test_crash_before_mobile_durable_ack_retries_same_tag(core,tmp_path,monkeypatch):
    import shared.notification_state as module
    rows=[current()]; worker=make_worker(tmp_path,core,rows)
    settings=worker.state.view()['settings']; settings['mobile_targets']=['notify.mobile_app_test']
    worker.state.configure(settings,0,'mobile')
    real=module.atomic_write
    def crash(path,raw,*a,**kw):
        value=json.loads(raw)
        if any(r['mobile'] for r in value['records'].values()): raise OSError('synthetic durable ACK failure')
        return real(path,raw,*a,**kw)
    monkeypatch.setattr(module,'atomic_write',crash)
    try:
        await worker.tick(); assert len(core.mobile)==1
        assert not any(r['mobile'] for r in json.loads(worker.state.path.read_bytes())['records'].values())
        await worker.close(); monkeypatch.setattr(module,'atomic_write',real)
        worker=make_worker(tmp_path,core,rows); await worker.tick()
        assert len(core.mobile)==2 and core.mobile[0]['data']['tag']==core.mobile[1]['data']['tag']
        await worker.close(); worker=make_worker(tmp_path,core,rows); await worker.tick()
        assert len(core.mobile)==2
    finally: await worker.close()


async def test_durable_before_send_and_original_preserved_on_write_failure(core,tmp_path,monkeypatch):
    import shared.notification_state as module
    worker=make_worker(tmp_path,core,[current()]); before=None
    def fail(*a,**kw): raise OSError('synthetic write failure')
    monkeypatch.setattr(module,'atomic_write',fail)
    try:
        await worker.tick(); assert not core.calls and not worker.state.path.exists()
        assert worker.view()['diagnostic']=='write_error'
    finally: await worker.close()


async def test_112_clients_bounded_pending_and_eventual_delivery_with_eight_recipients(core,tmp_path):
    from shared.notification_state import encoded
    rows=[current(binding_key=f'server/account-{i}',domain=f'host{i}.example.org',client_id=f'{i:032x}') for i in range(112)]
    worker=make_worker(tmp_path,core,rows)
    targets=['notify.mobile_app_'+str(i) for i in range(8)]
    core.catalog=[{'domain':'notify','services':{s.split('.')[1]:{} for s in targets}}]
    settings=worker.state.view()['settings']; settings['mobile_targets']=targets
    worker.state.configure(settings,0,'eight')
    try:
        worker.refresh(); pending=worker.pending()
        assert len(pending)<=256 and len(encoded(pending))<=1024*1024
        assert not any(r['ha_delivered'] or r['mobile'] for r in worker.state.records.values())
        for _ in range(8):
            await worker.tick()
            assert len(worker.pending())<=256 and worker.state.path.stat().st_size<=1024*1024
            if len(core.mobile)==896: break
        assert len(core.cards)==112 and len(core.mobile)==896
        assert len(worker.state.records)==224
        rows[:]=[current(binding_key='server/new',domain='new.example.org')]
        for _ in range(3): await worker.tick()
        assert len(core.cards)==1 and len(worker.state.records)==2
        assert next(iter(core.cards.values()))['message'].startswith('Для new.example.org')
    finally: await worker.close()


async def test_combined_recovery_updates_do_not_repeat_mobile_recovery(core,tmp_path):
    rows=[current(access_state='expired')]; rows[0]['billing'].update(pause_reason='insufficient_funds',paid_until=900000,funds_until=None,projection_kind='insufficient')
    worker=make_worker(tmp_path,core,rows); settings=worker.state.view()['settings']; settings['mobile_targets']=['notify.mobile_app_test']
    worker.state.configure(settings,0,'phone')
    try:
        await worker.tick(); rows[0]=current(); await worker.tick(); assert len(core.mobile)==2
        rows[0]['billing']['funds_until']=rows[0]['billing']['paid_until']=1100000
        await worker.tick(); assert len(core.mobile)==2
        assert 'скоро' in next(iter(core.cards.values()))['message']
        assert 'восстановлен' in next(iter(core.cards.values()))['message']
    finally: await worker.close()


async def test_cancellation_and_quiescence_leave_tunnel_independent(core,tmp_path):
    worker=make_worker(tmp_path,core,[current()]); await worker.start(); await asyncio.sleep(.03)
    await asyncio.wait_for(worker.close(),1)
    assert worker.task is None and worker.observer is None and not core.clients
    before=len(core.calls); worker=make_worker(tmp_path,core,[current()]); worker.gate=lambda:False
    await worker.tick(); assert len(core.calls)==before
    await worker.close()


async def test_unknown_identical_current_is_not_new_episode_proof(core,tmp_path):
    rows=[current()]; worker=make_worker(tmp_path,core,rows)
    try:
        worker.refresh(); ident=next(k for k,v in worker.state.records.items() if v['family']=='financial')
        desired=worker.state.records[ident]['desired']; old={'notification_id':ident,'created_at':'old-before-subscription',**{k:desired[k] for k in ('title','message')}}
        core.cards[ident]=old
        await worker._observe()
        await core.event('removed',{ident:old}); await asyncio.sleep(.02)
        assert not worker.state.records[ident]['acknowledged']
        await worker.tick(); await core.dismiss(ident); await asyncio.sleep(.02)
        assert worker.state.records[ident]['acknowledged']
    finally: await worker.close()


async def test_ws_retry_reuses_one_bounded_underlying_dns_job(monkeypatch):
    import socket
    import threading
    from shared.ha_notifications import HaNotifications
    from shared import ha_notifications as module
    real=socket.getaddrinfo; release=threading.Event(); calls=[]
    def lookup(host,*args,**kwargs):
        if host=='notification-dns.invalid':
            calls.append(host); release.wait(3)
            raise OSError('synthetic resolver unavailable')
        return real(host,*args,**kwargs)
    monkeypatch.setattr(socket,'getaddrinfo',lookup)
    monkeypatch.setattr(module,'CORE_WS','ws://notification-dns.invalid/websocket')
    ha=HaNotifications('synthetic-token')
    try:
        for _ in range(5):
            with pytest.raises(TimeoutError): await asyncio.wait_for(ha.observe(lambda e:None),.03)
        assert len(calls)==1
        await asyncio.wait_for(ha.close(),.3)
    finally: release.set(); await ha.close(); await asyncio.sleep(.03)


async def test_enabling_ha_delivers_current_state_and_cleanup_cannot_claim_connection_warning(core,tmp_path):
    now=[0]; rows=[current(contact=False)]; worker=make_worker(tmp_path,core,rows,mono=lambda:now[0])
    settings=worker.state.view()['settings']; settings.update(ha=False,connection=True)
    worker.state.configure(settings,0,'no-channels')
    try:
        await worker.tick(); now[0]=600; await worker.tick(); assert not core.cards
        rows[0]['contact']=True; await worker.tick()
        assert not any(r['desired'] and r['desired']['kind']=='connection_recovered' for r in worker.state.records.values())
        settings['ha']=True; worker.state.configure(settings,1,'ha-on'); await worker.tick()
        assert len(core.cards)==1 and 'не хватит' in next(iter(core.cards.values()))['message']
    finally: await worker.close()


async def test_portable_cleanup_dismisses_only_old_own_namespace(core,tmp_path):
    worker=make_worker(tmp_path,core,[current()])
    try:
        await worker.tick(); old=set(core.cards)
        core.cards['foreign']={'notification_id':'foreign','title':'Other','message':'Untouched','created_at':'foreign-version'}
        await worker.close(); worker.state.reset_namespace()
        worker=make_worker(tmp_path,core,[]); await worker.tick()
        assert set(core.cards)=={'foreign'} and not worker.state.data['cleanup']
        assert old.isdisjoint(core.cards)
    finally: await worker.close()


async def test_healthy_observer_survives_http_operation_timeout_window(core):
    from shared.ha_notifications import HaNotifications
    ha=HaNotifications('synthetic-token'); task=asyncio.create_task(ha.observe(lambda e:None))
    try:
        await asyncio.wait_for(ha.ready.wait(),1); session=ha.observer_session
        await asyncio.sleep(5.1)
        assert not task.done() and ha.observer_session==session and len(core.clients)==1
    finally: task.cancel(); await asyncio.gather(task,return_exceptions=True); await ha.close()


async def test_metadata_capacity_defers_new_accounts_but_drains_and_prunes_deleted(core,tmp_path,monkeypatch):
    import shared.notification_state as storage
    monkeypatch.setattr(storage,'MAX_BYTES',12000)
    rows=[current(binding_key=f'server/{i}',domain=f'host{i}.example.org') for i in range(30)]
    worker=make_worker(tmp_path,core,rows)
    try:
        await worker.tick()
        assert 0<len(core.cards)<30
        assert worker.state.path.stat().st_size<=12000
        rows[:]=[current(binding_key='server/new',domain='new.example.org')]
        for _ in range(3): await worker.tick()
        assert len(core.cards)==1
        assert next(iter(core.cards.values()))['message'].startswith('Для new.example.org')
        assert len(worker.state.records)==2
    finally: await worker.close()


async def test_confirmed_clock_error_clears_old_money_card_and_admin_gate_keeps_manual_ack(core,tmp_path):
    rows=[current()]; worker=make_worker(tmp_path,core,rows)
    try:
        await worker.tick(); ident=next(iter(core.cards))
        worker.gate=lambda:False
        await core.dismiss(ident); await asyncio.sleep(.02)
        assert worker.state.records[ident]['acknowledged']
        worker.gate=lambda:True
        rows[0]['billing']['paid_until']=rows[0]['billing']['funds_until']=1100000
        await worker.tick(); assert core.cards
        rows[0].update(access_state='clock_error',reliable_time=False)
        rows[0]['billing']['pause_reason']='clock_error'
        await worker.tick(); assert not core.cards
    finally: await worker.close()


@pytest.mark.parametrize('pending',['queued','partial','partial-mobile','core-down'])
async def test_global_disable_durably_cancels_test_on_both_channels(core,tmp_path,pending):
    worker=make_worker(tmp_path,core,[])
    settings=worker.state.view()['settings']; settings['mobile_targets']=['notify.mobile_app_test']
    worker.state.configure(settings,0,'targets'); worker.state.request_test(1,'explicit')
    ident=worker.state.identifier('__test__','connection')
    if pending=='partial':
        worker.refresh(); await worker._deliver(ident,worker.state.records[ident]['version'],'ha')
        assert len(core.cards)==1 and not core.mobile
    elif pending=='partial-mobile':
        worker.refresh(); await worker.discover()
        await worker._deliver(ident,worker.state.records[ident]['version'],'notify.mobile_app_test')
        assert not core.cards and len(core.mobile)==1
    elif pending=='core-down':
        core.service_unavailable=True; await worker.tick(); assert not core.cards and not core.mobile
    settings['enabled']=False; worker.state.configure(settings,1,'disable')
    delivered=len(core.mobile)
    await worker.close(); core.service_unavailable=False
    worker=make_worker(tmp_path,core,[])
    try:
        await worker.tick(); assert not core.cards and len(core.mobile)==delivered
        settings['enabled']=True; worker.state.configure(settings,2,'enable')
        worker.state.request_test(1,'explicit')  # A lost old response cannot requeue cancellation.
        await worker.tick(); assert not core.cards and len(core.mobile)==delivered
        worker.state.request_test(3,'new-explicit'); await worker.tick()
        assert len(core.cards)==1 and len(core.mobile)==delivered+1
    finally: await worker.close()


async def test_disable_during_current_barrier_is_rechecked_before_test_create(core,tmp_path):
    worker=make_worker(tmp_path,core,[]); worker.state.request_test(0,'explicit'); subscriptions=0
    async def before_current():
        nonlocal subscriptions
        subscriptions+=1
        if subscriptions==2:
            settings=worker.state.view()['settings']; settings['enabled']=False
            worker.state.configure(settings,0,'disable')
    core.before_current=before_current
    try:
        await worker.tick(); assert subscriptions>=2
        assert not core.cards and not core.mobile
    finally: await worker.close()
