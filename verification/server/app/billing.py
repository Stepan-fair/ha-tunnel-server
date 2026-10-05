"""Single-database, transactional prepaid subscriptions and an immutable money ledger."""
import json
import secrets
from server.app.journal import Actor, append_event
from server.app.subscription import money_integer, instant, zone, first_period, next_period, Period
from server.app.store import ConflictError


class BillingRepository:
    def __init__(self,store):
        self.store=store

    def _row(self,db,client_id):
        row=db.execute('SELECT * FROM clients WHERE id=?',(client_id,)).fetchone()
        if row is None: raise ValueError('Unknown client')
        return row

    def _ledger(self,db,row,kind,operation_id,now,*,before,actor=None,days=None):
        actor=actor or Actor('system')
        delta=money_integer(row['balance_kopecks']-before,negative=True)
        details={'timezone':row['billing_timezone'],'anchor_day':row['anchor_day']}
        if days is not None: details['days']=days
        db.execute('''INSERT INTO billing_operations
            (operation_id,client_id,kind,at,delta_kopecks,balance_before,balance_after,price_kopecks,
             paid_from,paid_until,actor,details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (operation_id,row['id'],kind,now,delta,before,row['balance_kopecks'],
             row['price_kopecks'],row['paid_from'],row['paid_until'],
             json.dumps({'source':actor.source,'user_id':actor.user_id}),json.dumps(details)))
        append_event(db,action=kind,at=now,actor=actor,client_id=row['id'],domain=row['domain'],
            operation_id=operation_id+':audit',details={'balance_kopecks':row['balance_kopecks'],
            'price_kopecks':row['price_kopecks'],'delta_kopecks':row['balance_kopecks']-before,
            'paid_until':row['paid_until'],'days':days})

    def _reconcile(self,db,row,now,timezone,*,actor=None,fresh_start=False):
        if self.store.migrating: return row
        if row['billing_mode']=='legacy' or row['paused'] or row['revoked'] or not row['secret_hash']:
            return row
        price,balance=row['price_kopecks'],row['balance_kopecks']
        money_integer(price); money_integer(balance,negative=True)
        if price==0:
            if row['deadline'] is not None or row['billing_paused']:
                db.execute('UPDATE clients SET deadline=NULL,duration=NULL,billing_paused=0,revision=revision+1 WHERE id=?',(row['id'],))
            return self._row(db,row['id'])
        if row['paid_until'] is not None and row['paid_from'] is not None and row['paid_from']<=now<row['paid_until']:
            return row
        if balance<price:
            if not row['billing_paused']:
                db.execute('UPDATE clients SET billing_paused=1,revision=revision+1 WHERE id=?',(row['id'],))
                append_event(db,action='financial_pause',at=now,actor=actor or Actor('timer'),
                    client_id=row['id'],domain=row['domain'],details={'paid_until':row['paid_until'],'price_kopecks':price,'balance_kopecks':balance})
            return self._row(db,row['id'])
        period=None
        if row['paid_until'] is not None and row['paid_from'] is not None and not row['billing_paused'] and not fresh_start:
            previous=Period(row['paid_from'],row['paid_until'],row['anchor_day'],row['billing_timezone'])
            candidate=next_period(previous)
            if candidate.start<=now<candidate.end: period=candidate
        if period is None: period=first_period(now,timezone)
        operation=f"purchase:{row['id']}:{period.start:.6f}:{period.end:.6f}"
        db.execute('''UPDATE clients SET balance_kopecks=?,paid_from=?,paid_until=?,anchor_day=?,
            billing_timezone=?,billing_paused=0,deadline=?,duration=NULL,revision=revision+1 WHERE id=?''',
            (balance-price,period.start,period.end,period.anchor_day,period.timezone,period.end,row['id']))
        result=self._row(db,row['id'])
        self._ledger(db,result,'purchase',operation,now,before=balance,actor=actor or Actor('timer'))
        return result

    def command(self,client_id,action,command_id,expected_revision,*,value_kopecks,now,timezone,actor=None):
        if self.store.migrating: raise ConflictError('Domain migration is in progress')
        if action not in ('set_price','topup','set_balance') or not isinstance(command_id,str) or not 1<=len(command_id)<=128:
            raise ValueError('Invalid billing command')
        if type(expected_revision) is not int or expected_revision<0: raise ValueError('Invalid revision')
        money_integer(value_kopecks,negative=action=='set_balance')
        if action=='topup' and value_kopecks<=0: raise ValueError('Topup must be positive')
        instant(now); zone(timezone)
        if hasattr(self.store.clock,'reliable') and not self.store.clock.reliable:
            raise ConflictError('Wait for reliable server time')
        request=json.dumps([action,expected_revision,value_kopecks,timezone],separators=(',',':'))
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            previous=db.execute('SELECT request,result FROM billing_commands WHERE client_id=? AND command_id=?',(client_id,command_id)).fetchone()
            if previous:
                if previous['request']!=request: raise ValueError('Command identifier was reused')
                return json.loads(previous['result'])
            row=self._row(db,client_id)
            if row['revision']!=expected_revision: raise ConflictError('Client policy has changed; refresh it')
            before=row['balance_kopecks']
            fresh=bool(row['billing_paused'] or row['price_kopecks']==0 or before<row['price_kopecks'])
            if action=='set_price':
                db.execute('''UPDATE clients SET price_kopecks=?,billing_mode='monthly',
                    billing_timezone=CASE WHEN paid_from IS NULL THEN ? ELSE billing_timezone END,
                    deadline=CASE WHEN ?=0 THEN NULL ELSE paid_until END,duration=NULL,revision=revision+1 WHERE id=?''',
                    (value_kopecks,timezone,value_kopecks,client_id))
            else:
                value=value_kopecks if action=='set_balance' else money_integer(before+value_kopecks,negative=True)
                money_integer(value-before,negative=True)
                db.execute('UPDATE clients SET balance_kopecks=?,revision=revision+1 WHERE id=?',(value,client_id))
            row=self._row(db,client_id)
            self._ledger(db,row,action,f'manual:{client_id}:{command_id}',now,before=before,actor=actor)
            row=self._reconcile(db,row,now,timezone,actor=actor,fresh_start=fresh)
            result=self.store._snapshot(row,now)
            db.execute('INSERT INTO billing_commands VALUES (?,?,?,?)',(client_id,command_id,request,json.dumps(result)))
            return result

    def reconcile(self,client_id,now,*,timezone,actor=None):
        instant(now); zone(timezone)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row=self._row(db,client_id)
            if not hasattr(self.store.clock,'reliable') or self.store.clock.reliable:
                row=self._reconcile(db,row,now,timezone,actor=actor)
            return self.store._snapshot(row,now)
