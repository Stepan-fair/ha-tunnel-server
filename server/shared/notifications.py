"""Read-only event assessment and optional delivery, independent of tunnel health."""
from dataclasses import dataclass
from datetime import datetime, timezone
import math
import asyncio
import copy
from contextlib import asynccontextmanager
import secrets
import time
from pathlib import Path

from shared.billing_status import validate_billing
from shared.validation import domain
from shared.notification_state import NotificationUnavailable, digest, encoded


def notification_asset():
    """Canonical form source, copied with shared modules into either role image."""
    return Path(__file__).with_name('notification_settings.js').read_bytes()


@dataclass(frozen=True)
class Alert:
    kind: str
    message: str
    coverage: float | None


def assess_access(snapshot, *, now, reliable_time, warning_days, enabled=None):
    """Only callers with a fresh authenticated Server snapshot may supply reliable_time."""
    host=domain(snapshot['domain'])
    if type(warning_days) is not int or not 1<=warning_days<=30: raise ValueError('Invalid warning days')
    if type(now) not in (int,float) or not math.isfinite(now): raise ValueError('Invalid time')
    billing=validate_billing(snapshot['billing'])
    if not reliable_time or snapshot.get('fresh') is False: return None
    state=snapshot['access_state']
    if state in ('pending','revoked','clock_error','paused') or billing['pause_reason'] in ('manual','revoked','pending','clock_error'): return None
    monthly=billing['mode']=='monthly'
    if monthly and billing['price_kopecks']==0: return None
    coverage=billing['funds_until'] if monthly else snapshot.get('deadline')
    if coverage is not None:
        if type(coverage) not in (int,float) or not math.isfinite(coverage): raise ValueError('Invalid coverage')
        date=datetime.fromtimestamp(coverage,timezone.utc).strftime('%d.%m.%Y %H:%M UTC')
    else: date=None
    flags=enabled or {}
    # Raw status can cross paid_until before the independent billing timer has
    # reconciled renewal. Enough funds means pending renewal, not confirmed stop.
    stopped=state=='expired' and ((billing['pause_reason']=='insufficient_funds' and
        billing['balance_kopecks']<billing['price_kopecks']) if monthly else coverage is not None and coverage<=now)
    if stopped:
        return Alert('access_stopped',f'Для {host} доступ закончился из-за оплаты или срока.',coverage) if flags.get('access_stopped',True) else None
    if state!='allowed': return None
    if coverage is not None and 0<coverage-now<=warning_days*86400 and flags.get('access_ending',True):
        return Alert('access_ending',f'Для {host} доступ скоро закончится. Подтверждённый срок: {date}.',coverage)
    if monthly and billing['balance_kopecks']<billing['price_kopecks'] and flags.get('funds_low',True):
        paid=billing['paid_until']
        until=datetime.fromtimestamp(paid,timezone.utc).strftime('%d.%m.%Y %H:%M UTC') if paid is not None else None
        return Alert('funds_low',f'Для {host} не хватит средств на следующее продление.'+(f' Текущий доступ оплачен до {until}.' if until else ''),coverage)
    return None


@asynccontextmanager
async def unguarded(): yield


@asynccontextmanager
async def settings_lock(lock):
    # A request may wait for one operation, never an entire delivery batch.
    await asyncio.wait_for(lock.acquire(),5)
    try: yield
    finally: lock.release()


class NotificationWorker:
    def __init__(self, state, adapter, snapshots, clock=None, *, monotonic=time.monotonic,
                 gate=lambda:True):
        self.state,self.adapter,self.snapshots,self.clock=state,adapter,snapshots,clock
        self.monotonic,self.gate=monotonic,gate
        self.adapter.prefix='ha_tunnel_'+state.role+'_'+state.data['namespace']+'_'
        self.task=None; self.observer=None; self.closed=False
        self.lock=asyncio.Lock(); self.pass_lock=asyncio.Lock()
        self.diagnostic=None; self.catalog=[]; self.catalog_ok=False; self.catalog_at=None
        self.contacts={}; self.eligible=set(); self.seen_cards={}; self.expected={}; self.baseline={}
        self.cursor=state.data['cursor']

    def view(self):
        result=self.state.view()
        result.update(services=list(self.catalog),catalog_available=self.catalog_ok,
                      diagnostic=result['diagnostic'] or self.diagnostic)
        return result

    def _financial(self, row, settings):
        key=row['binding_key']; ident=self.state.identifier(key,'financial')
        previous=self.state.records.get(ident,{})
        context=copy.deepcopy(previous.get('context',{}))
        if row.get('rejected') or not settings['enabled']:
            self.state.observe(key,'financial','clear',None,context={}); self.eligible.add(ident); return
        if row.get('fresh') and row.get('access_state') in ('clock_error','paused','revoked','pending'):
            validate_billing(row['billing']); domain(row['domain'])
            context=context if row['access_state']=='clock_error' else {}
            if row.get('source_key'): context['source_key']=row['source_key']
            self.state.observe(key,'financial','clear',None,context=context); self.eligible.add(ident); return
        if not row.get('fresh') or not row.get('reliable_time'): return
        if row.get('source_key'): context['source_key']=row['source_key']
        self.eligible.add(ident)
        now=row['observed_now']
        factual=assess_access(row,now=now,reliable_time=True,warning_days=settings['warning_days'])
        selected=assess_access(row,now=now,reliable_time=True,warning_days=settings['warning_days'],enabled=settings)
        stopped=factual is not None and factual.kind=='access_stopped'
        if stopped:
            if not context.get('stopped'): context['stop']=secrets.token_hex(16)
            context.update(stopped=True,recovered=None)
        elif row['access_state']=='allowed':
            if context.get('stopped'): context['recovered']=context.get('stop')
            context['stopped']=False
        else:
            context={}
        recovery=context.get('recovered') if settings['access_recovered'] else None
        desired=None
        if selected or recovery:
            kind=selected.kind if selected else 'access_recovered'
            coverage=selected.coverage if selected else None
            marker=digest([kind,coverage,context.get('stop') if stopped else None,recovery])[:32]
            # Returning to an identical warning after a confirmed resolution starts a new episode.
            if context.get('marker')!=marker:
                context.update(marker=marker,episode=secrets.token_hex(16))
            message=selected.message if selected else ''
            if recovery: message=f"Для {domain(row['domain'])} доступ восстановлен."+(' '+message if message else '')
            desired=dict(title='HA Tunnel · Доступ',message=message,kind=kind,
                         mobile_key=('recovery:'+recovery) if recovery else context['episode'])
        else: context.pop('marker',None); context.pop('episode',None)
        self.state.observe(key,'financial',context.get('episode','clear'),desired,context=context)

    def _connection(self, row, settings):
        key=row['binding_key']; ident=self.state.identifier(key,'connection')
        self.eligible.add(ident)
        previous=self.state.records.get(ident,{})
        context=copy.deepcopy(previous.get('context',{})); now=self.monotonic()
        receipt=row.get('contact_at')
        valid=type(receipt) in (int,float) and math.isfinite(receipt) and receipt<=now
        last=self.contacts.setdefault(key,receipt if valid else now)
        if valid: self.contacts[key]=last=max(last,receipt)
        elif 'contact_at' not in row and row.get('contact'): self.contacts[key]=last=now
        if row.get('rejected') or not settings['enabled'] or not settings['connection']:
            self.contacts[key]=now
            self.state.observe(key,'connection','clear',None,context={}); return
        desired=None
        # Compare the deadline directly: subtracting fractional monotonic values
        # can round (last + 600) - last below 600 at the exact boundary.
        if now>=last+600:
            if context.get('phase')!='lost': context=dict(phase='lost',episode=secrets.token_hex(16),sent=False)
            desired=dict(title='HA Tunnel · Связь',message=f"Для {domain(row['domain'])} нет подтверждённого обмена 10 минут. Это не проверка работоспособности HA.",kind='connection_lost',mobile_key=context['episode'])
        elif row.get('contact') and context.get('phase')=='lost':
            context['phase']='recovered' if context.get('sent') else 'clear'
        if context.get('phase')=='recovered':
            desired=dict(title='HA Tunnel · Связь',message=f"Для {domain(row['domain'])} связь восстановлена.",kind='connection_recovered',mobile_key=context['episode']+':recovered')
        self.state.observe(key,'connection',context.get('episode','clear')+('recovered' if context.get('phase')=='recovered' else ''),desired,context=context)

    def refresh(self, only_binding=None):
        self.eligible=set()
        if self.closed or not self.gate(): return False
        rows=self.snapshots()
        if rows is None: return False
        settings=self.state.data['settings']; live=set(); resolved=[]
        for row in rows:
            if row.get('source_key') and not row.get('verified_identity'):
                known=next((r for r in self.state.records.values() if r['family']=='financial' and r['context'].get('source_key')==row['source_key']),None)
                if known: row={**row,'binding_key':known['binding']}
            live.add(row['binding_key'])
            resolved.append(row)
        # Retire disappeared accounts first, so new-account admission cannot
        # prevent cleanup from freeing a saturated durable metadata budget.
        for ident,record in tuple(self.state.records.items()):
            if only_binding is not None and record['binding']!=only_binding: continue
            if record['binding']=='__test__':
                if not settings['enabled'] and record['desired'] is not None: self.state.cancel_test()
                self.eligible.add(ident); continue
            if record['binding'] not in live:
                self.state.observe(record['binding'],record['family'],'retired',None,context={},retired=True)
                self.eligible.add(ident)
        for row in resolved:
            if only_binding is not None and row['binding_key']!=only_binding: continue
            try:
                self._financial(row,settings)
                self._connection(row,settings)
            except NotificationUnavailable:
                if self.state.diagnostic!='capacity': raise
                self.diagnostic='capacity'
                for family in ('financial','connection'):
                    self.eligible.discard(self.state.identifier(row['binding_key'],family))
        self.contacts={k:v for k,v in self.contacts.items() if k in live}
        self.state.forget_retired()
        return True

    def on_event(self,event):
        if self.closed or event['session']!=self.adapter.observer_session: return
        kind=event['type']; cards=event['notifications']
        if kind=='current':
            self.baseline={k:v['created_at'] for k,v in cards.items()}
            self.seen_cards={}
            for ident,record in tuple(self.state.records.items()):
                if record['binding']=='__test__' and record['context'].get('complete'): continue
                card=cards.get(ident)
                if card and record['created_at']==card['created_at']:
                    self.seen_cards[ident]=(record['version'],card['created_at'])
                elif record['desired'] is not None and not record['acknowledged']:
                    self.state.update(ident,record['version'],ha_delivered=False)
            return
        for ident,card in cards.items():
            record=self.state.records.get(ident)
            if record is None: continue
            if kind in ('added','updated'):
                expected=self.expected.get(ident)
                if (expected==(event['session'],record['version']) and card['created_at']!=self.baseline.get(ident)
                    and record['desired'] is not None and card['title']==record['desired']['title'] and card['message']==record['desired']['message']):
                    self.state.update(ident,record['version'],created_at=card['created_at'])
                    self.seen_cards[ident]=(record['version'],card['created_at'])
                    self.expected.pop(ident,None)
            elif kind=='removed':
                proof=self.seen_cards.get(ident)
                if proof and proof==(record['version'],card['created_at']):
                    self.state.acknowledge(ident,version=proof[0],created_at=proof[1])

    async def _observe(self, *, restart=False):
        if restart and self.observer is not None:
            self.observer.cancel(); await asyncio.gather(self.observer,return_exceptions=True); self.observer=None
        if self.observer is None or self.observer.done():
            if self.observer is not None: await asyncio.gather(self.observer,return_exceptions=True)
            self.expected={}; self.seen_cards={}; self.adapter.ready.clear()
            self.observer=asyncio.create_task(self.adapter.observe(self.on_event),name='notification-observer')
            waiter=asyncio.create_task(self.adapter.ready.wait())
            try:
                done,_=await asyncio.wait((waiter,self.observer),timeout=5,return_when=asyncio.FIRST_COMPLETED)
                if self.observer in done: self.observer.result()
                if not self.adapter.ready.is_set(): raise ValueError('Core subscription unavailable')
            finally: waiter.cancel(); await asyncio.gather(waiter,return_exceptions=True)

    def pending(self):
        settings=self.state.data['settings']; jobs=[(i,'cleanup','cleanup') for i in self.state.data['cleanup'][:128]]; size=len(encoded(jobs))
        records=list(self.state.records.items())
        if not records: return jobs
        start=self.cursor%len(records)
        for offset in range(len(records)):
            ident,record=records[(start+offset)%len(records)]
            if ident not in self.eligible: continue
            desired=record['desired']
            testing=record['binding']=='__test__'
            if testing and record['context'].get('complete') and desired is not None: continue
            channels=[]
            if not record['ha_delivered'] or (not settings['ha'] and record['created_at'] is not None):
                if not (desired is not None and record['acknowledged'] and settings['ha']): channels.append('ha')
            if settings['enabled'] and desired is not None and not record['acknowledged']:
                targets=record['context']['targets'] if testing else settings['mobile_targets']
                channels += [t for t in targets if t in settings['mobile_targets'] and record['mobile'].get(t)!=desired['mobile_key']]
            for channel in channels:
                job=(ident,record['version'],channel)
                cost=len(encoded([job,desired]))
                if len(jobs)>=256 or size+cost>1024*1024:
                    self.cursor=(start+offset)%len(records); return jobs
                jobs.append(job); size+=cost
        self.cursor=(start+1)%len(records)
        return jobs

    async def discover(self):
        try:
            self.catalog=await self.adapter.services(); self.catalog_ok=True; self.catalog_at=self.monotonic()
        except Exception:
            self.catalog_ok=False; self.diagnostic='mobile_catalog_unavailable'
        return list(self.catalog)

    def _sent(self, ident, version, channel):
        record=self.state.records.get(ident)
        if record is None or record['version']!=version: return
        changes={}
        if channel=='ha': changes['ha_delivered']=True
        elif record['desired']:
            mobile=dict(record['mobile']); mobile[channel]=record['desired']['mobile_key']; changes['mobile']=mobile
        if (record['desired'] and record['desired']['kind']=='connection_lost'
                and (channel!='ha' or self.state.data['settings']['ha'])):
            changes['context']={**record['context'],'sent':True}
        self.state.update(ident,version,**changes)
        record=self.state.records[ident]
        if record['binding']=='__test__' and record['desired'] is not None:
            context=record['context']; settings=self.state.data['settings']
            targets=[t for t in context['targets'] if t in settings['mobile_targets']]
            if (not context['ha'] or record['ha_delivered']) and all(record['mobile'].get(t)==record['desired']['mobile_key'] for t in targets):
                self.state.update(ident,version,context={**context,'complete':True})

    async def _deliver(self,ident,version,channel):
        namespace=self.state.data['namespace']
        if channel=='cleanup':
            if not self.closed and self.gate() and ident in self.state.data['cleanup']:
                await self.adapter.dismiss(ident)
                if not self.closed and self.gate() and namespace==self.state.data['namespace']: self.state.cleaned(ident)
            return
        original=self.state.records.get(ident)
        if original is None or not self.refresh(original['binding']) or ident not in self.eligible: return
        record=self.state.records.get(ident)
        if record is None or record['version']!=version: return
        settings=self.state.data['settings']; desired=record['desired']
        if channel=='ha':
            if desired is None or not settings['enabled'] or not settings['ha']:
                self.seen_cards.pop(ident,None); self.expected.pop(ident,None)
                await self.adapter.dismiss(ident)
                self.state.update(ident,version,created_at=None)
            elif not record['acknowledged']:
                # A fresh subscription CURRENT is an ordering barrier. An unknown old
                # identical card can never prove a version created after this barrier.
                await self._observe(restart=True)
                if not self.refresh(record['binding']) or ident not in self.eligible: return
                record=self.state.records.get(ident)
                if record is None or record['version']!=version or record['acknowledged']: return
                settings=self.state.data['settings']; desired=record['desired']
                if not settings['enabled'] or not settings['ha'] or desired is None: return
                self.expected[ident]=(self.adapter.observer_session,version)
                try: await self.adapter.create(ident,desired['title'],desired['message'])
                except BaseException:
                    self.expected.pop(ident,None); raise
            else: return
        else:
            if not settings['enabled'] or channel not in settings['mobile_targets'] or desired is None or record['acknowledged']: return
            if record['mobile'].get(channel)==desired['mobile_key']: return
            await self.adapter.mobile(channel,ident,desired['title'],desired['message'])
        if not self.closed and self.gate() and namespace==self.state.data['namespace']:
            self._sent(ident,version,channel)

    async def tick(self):
        async with self.pass_lock:
            if self.closed or not self.gate(): return
            self.diagnostic=None
            try:
                async with self.lock:
                    if not self.refresh(): return
                    try: await self._observe()
                    except Exception: self.diagnostic='core_unavailable'
                    if self.state.data['settings']['mobile_targets'] and (not self.catalog_ok or self.catalog_at is None or self.monotonic()-self.catalog_at>=300):
                        await self.discover()
                    jobs=self.pending()
                for ident,version,channel in jobs:
                    if self.closed or not self.gate(): return
                    try:
                        async with self.lock:
                            # One budget covers barrier + send, rather than
                            # accumulating separate phase timeouts per job.
                            async with asyncio.timeout(5):
                                await self._deliver(ident,version,channel)
                    except NotificationUnavailable: raise
                    except Exception: self.diagnostic='delivery_unavailable'
                async with self.lock:
                    self.state.forget_retired()
                    self.state.checkpoint_cursor(self.cursor)
            except Exception:
                self.diagnostic=self.state.diagnostic or 'notification_unavailable'

    async def start(self):
        if self.task is None or self.task.done():
            self.closed=False; self.task=asyncio.create_task(self.run(),name='notifications')

    async def run(self):
        delay=5
        while True:
            await self.tick()
            delay=min(300,delay*2) if self.diagnostic else 5
            await asyncio.sleep(delay+secrets.randbelow(1000)/1000)

    async def close(self):
        self.closed=True
        for task in (self.task,self.observer):
            if task is not None: task.cancel()
        await asyncio.gather(*(t for t in (self.task,self.observer) if t is not None),return_exceptions=True)
        self.task=self.observer=None
        await self.adapter.close()


def record_server_contact(store, client_id):
    """Optional in-memory evidence, only after authenticated current-owner input."""
    try:
        contacts=getattr(store,'notification_contacts',None)
        if contacts is None: contacts=store.notification_contacts={}
        if len(contacts)>=4096 and client_id not in contacts:
            live={r['client_id'] for r in store.list_clients()}
            for cid in list(contacts):
                if cid not in live: contacts.pop(cid,None)
        if len(contacts)<4096 or client_id in contacts: contacts[client_id]=time.monotonic()
    except Exception:
        # Optional observation must not fail an otherwise accepted tunnel call.
        return


def server_snapshots(store):
    """Read current raw snapshots; assessment must tolerate pending renewal."""
    if store.migrating or store.administration.busy or not getattr(store,'billing_available',lambda:True)(): return None
    now=store.now(); reliable=getattr(store.clock,'reliable',True)
    rows=store.list_clients(); instance=store.get_metadata('instance_id')
    contacts=getattr(store,'notification_contacts',{})
    live={r['client_id'] for r in rows}
    for cid in list(contacts):
        if cid not in live: contacts.pop(cid,None)
    for row in rows:
        last=contacts.get(row['client_id'])
        contact=last is not None and 0<=time.monotonic()-last<=45
        row['billing']['updated_at']=now
        row.update(binding_key=instance+'/'+row['client_id'],fresh=True,reliable_time=reliable,
                   observed_now=now,contact=contact,contact_at=last,
                   rejected=row['access_state']=='revoked')
    return rows


def client_snapshots(controller, *, monotonic=time.monotonic):
    credentials=controller.credentials
    if credentials is None: return []
    access=controller.server_access or {}
    received=controller.status_received; age=monotonic()-received if received is not None else None
    contact_received=getattr(controller,'contact_received',None)
    contact_age=monotonic()-contact_received if contact_received is not None else None
    fresh=not controller.billing_stale and age is not None and 0<=age<=45
    billing=access.get('billing')
    # The Server provides updated_at. Advancing local wall time never ages a
    # cached paid period into expiry, including while status polling is offline.
    reliable=fresh and billing is not None and access.get('access_state')!='clock_error'
    instance=access.get('server_instance_id') or credentials['server_url']
    if not isinstance(instance,str) or len(instance)>512: raise ValueError('Invalid server identity')
    source_key=digest([credentials['server_url'],credentials['client_id'],credentials.get('ca_pem')])
    return [{**access,'domain':credentials['domain'],'binding_key':instance+'/'+credentials['client_id'],
             'source_key':source_key,'verified_identity':bool(access.get('server_instance_id')),
             'fresh':fresh,'reliable_time':reliable,'observed_now':billing['updated_at'] if billing else 0,
             'contact':contact_age is not None and 0<=contact_age<=45,'contact_at':contact_received,
             'rejected':controller.state in ('credentials_rejected','revoked')}]


def add_notification_routes(app, worker, csrf_key, *, administration=None, ensure_allowed=lambda:None):
    """Install only on an existing Ingress/CSRF/admin protected local app."""
    from aiohttp import web
    from shared.http import csrf_for
    from shared.notification_state import validate_settings, SettingsConflict

    async def view(request):
        if worker is None: raise web.HTTPServiceUnavailable()
        # Discovery only updates the bounded service catalog. It does not alter
        # the journal; local settings remain readable while delivery is pending.
        await worker.discover()
        return web.json_response({**worker.view(),'csrf':csrf_for(csrf_key,request.headers['X-Remote-User-Id'])})

    async def change(request):
        if worker is None: raise web.HTTPServiceUnavailable()
        if request.content_length is not None and request.content_length>8192: raise web.HTTPRequestEntityTooLarge(max_size=8192,actual_size=request.content_length)
        raw=bytearray()
        async for chunk in request.content.iter_chunked(8192):
            raw.extend(chunk)
            if len(raw)>8192: raise web.HTTPRequestEntityTooLarge(max_size=8192,actual_size=len(raw))
        from shared.ha_notifications import decode
        data=decode(raw); testing=request.path.endswith('/test')
        required={'revision','command_id'} | (set() if testing else {'settings'})
        if not isinstance(data,dict) or set(data)!=required: raise ValueError('Invalid notification request')
        try:
            guard=administration.exclusive('notifications') if administration is not None else unguarded()
            async with guard:
                ensure_allowed()
                async with settings_lock(worker.lock):
                    ensure_allowed()
                    if testing:
                        worker.state.request_test(data['revision'],data['command_id'])
                        return web.json_response({'status':'queued'},status=202)
                    settings=validate_settings(data['settings'])
                    if data['command_id'] in worker.state.data['commands']:
                        return web.json_response(worker.state.configure(settings,data['revision'],data['command_id']))
                    current_targets=worker.state.data['settings']['mobile_targets']
                    if settings['mobile_targets']!=current_targets:
                        await worker.discover()
                        ensure_allowed()
                        if not worker.catalog_ok or any(s not in worker.catalog for s in settings['mobile_targets']): raise ValueError('Select discovered local mobile services')
                    return web.json_response(worker.state.configure(settings,data['revision'],data['command_id']))
        except SettingsConflict: raise web.HTTPConflict(reason='Настройки изменились. Обновите форму.')

    app.add_routes([web.get('/api/notifications',view),web.post('/api/notifications',change),web.post('/api/notifications/test',change)])
