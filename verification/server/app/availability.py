"""Durable common-service outages. Compensation commits before any renewal."""
import asyncio
import json
import secrets
from server.app.subscription import instant, compensation_days, Period, extend_period
from server.app.billing import BillingRepository

class AvailabilityService:
    def __init__(self,store,clock,*,probe):
        self.store,self.clock,self.probe=store,clock,probe
        self.healthy=False
        self.recovered=False

    def _metadata(self,db,key,value):
        db.execute('INSERT OR REPLACE INTO server_metadata VALUES (?,?)',(key,json.dumps(value)))

    def _get(self,db,key,default=None):
        row=db.execute('SELECT value FROM server_metadata WHERE name=?',(key,)).fetchone()
        return json.loads(row[0]) if row else default

    def _checkpoint(self,db,now):
        self._metadata(db,'service_last_healthy',now)
        self._metadata(db,'clock_anchor',now)
        db.execute('DELETE FROM availability_checkpoint')
        for row in db.execute('SELECT * FROM clients').fetchall():
            if row['billing_mode']=='monthly' and row['price_kopecks']>0 and self.store._snapshot(row,now)['access_state']=='allowed':
                db.execute('INSERT INTO availability_checkpoint VALUES (?,?)',(row['id'],row['paid_until']))

    def _open(self,db,now):
        current=db.execute("SELECT * FROM outage_episodes WHERE state='open'").fetchone()
        if current: return current
        start=self._get(db,'service_last_healthy',now)
        instant(start)
        if start>now: raise ValueError('Outage clock is inconsistent')
        episode=secrets.token_hex(16)
        db.execute("INSERT INTO outage_episodes VALUES (?,?,NULL,0,'open')",(episode,start))
        db.execute('''INSERT INTO outage_entitlements
            SELECT ?,client_id,paid_until,1 FROM availability_checkpoint''',(episode,))
        return db.execute('SELECT * FROM outage_episodes WHERE id=?',(episode,)).fetchone()

    def _finish(self,db,episode,now):
        days=compensation_days(now-episode['started_at'])
        repo=BillingRepository(self.store)
        for entitlement in db.execute('SELECT * FROM outage_entitlements WHERE episode_id=? AND eligible=1',(episode['id'],)).fetchall():
            operation=f"outage:{episode['id']}:{entitlement['client_id']}"
            if not days or db.execute('SELECT 1 FROM billing_operations WHERE operation_id=?',(operation,)).fetchone(): continue
            row=db.execute('SELECT * FROM clients WHERE id=?',(entitlement['client_id'],)).fetchone()
            if not row or row['paid_until'] is None: continue
            # A manual price change cannot discard the already purchased period.
            period=Period(row['paid_from'],row['paid_until'],row['anchor_day'],row['billing_timezone'])
            extended=extend_period(period,days)
            db.execute('''UPDATE clients SET paid_until=?,anchor_day=?,deadline=CASE WHEN price_kopecks>0 THEN ? ELSE NULL END,
                revision=revision+1 WHERE id=?''',(extended.end,extended.anchor_day,extended.end,row['id']))
            updated=repo._row(db,row['id'])
            repo._ledger(db,updated,'compensation',operation,now,before=row['balance_kopecks'],days=days)
        db.execute("UPDATE outage_episodes SET ended_at=?,compensated_days=?,state='closed' WHERE id=?",(now,days,episode['id']))

    async def recover(self):
        if not self.recovered:
            now=self.clock.now(); instant(now)
            if getattr(self.clock,'reliable',True):
                with self.store.connection() as db:
                    db.execute('BEGIN IMMEDIATE')
                    if self._get(db,'service_last_healthy') is not None: self._open(db,now)
                self.recovered=True
        await self.sample()

    async def sample(self):
        now=self.clock.now(); instant(now)
        if now<self.store.get_metadata('clock_anchor',0) or not getattr(self.clock,'reliable',True):
            self.healthy=False
            return False
        try:
            result=await asyncio.wait_for(self.probe(),3)
            healthy=isinstance(result,dict) and all(result.get(key) is True for key in ('frp','gateway','npm'))
        except (OSError,TimeoutError):
            healthy=False
        now=self.clock.now(); instant(now)
        if now<self.store.get_metadata('clock_anchor',0) or not getattr(self.clock,'reliable',True):
            self.healthy=False
            return False
        self.healthy=False
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if healthy:
                episode=db.execute("SELECT * FROM outage_episodes WHERE state='open'").fetchone()
                if episode: self._finish(db,episode,now)
                self._checkpoint(db,now)
            else: self._open(db,now)
        self.healthy=healthy
        return healthy

    async def shutdown(self):
        # Last verified healthy checkpoint, not shutdown success, starts offline time.
        now=self.clock.now(); instant(now)
        if now<self.store.get_metadata('clock_anchor',0) or not getattr(self.clock,'reliable',True):
            self.healthy=False
            return False
        self.healthy=False
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._open(db,self.clock.now())
            self._metadata(db,'service_shutdown_at',self.clock.now())
