"""Pure exact-money and calendar-month calculations; never mutate balances here."""
from calendar import monthrange
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone as utc
from decimal import Decimal
import math
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MIN_MONEY=-(2**63)
MAX_MONEY=2**63-1


def money_integer(value, *, negative=False):
    if type(value) is not int or not (MIN_MONEY if negative else 0)<=value<=MAX_MONEY:
        raise ValueError('Invalid amount')
    return value


def parse_money(value: str, *, allow_negative=False) -> int:
    if not isinstance(value,str): raise ValueError('Money must be decimal text')
    value=value.strip().replace(',','.')
    if not re.fullmatch(r'-?[0-9]{1,19}(?:\.[0-9]{1,2})?',value):
        raise ValueError('Invalid monetary value')
    return money_integer(int(Decimal(value)*100),negative=allow_negative)


def zone(value):
    if not isinstance(value,str) or not 1<=len(value)<=128: raise ValueError('Invalid timezone')
    try: return ZoneInfo(value)
    except (ZoneInfoNotFoundError,ValueError) as exc: raise ValueError('Invalid timezone') from exc


def instant(value):
    if type(value) not in (int,float) or not math.isfinite(value): raise ValueError('Invalid timestamp')
    try: return datetime.fromtimestamp(value,utc.utc)
    except (OSError,ValueError,OverflowError) as exc: raise ValueError('Invalid timestamp') from exc


def _midnight(day, tz):
    naive=datetime.combine(day,time())
    # Midnight can be skipped or repeated. Round-trip through UTC proves validity.
    # Entire skipped civil dates resolve at the next real local instant.
    for minutes in range(2881):
        local=naive+timedelta(minutes=minutes)
        candidates=[]
        for fold in (0,1):
            candidate=local.replace(tzinfo=tz,fold=fold)
            if candidate.astimezone(utc.utc).astimezone(tz).replace(tzinfo=None)==local:
                candidates.append(candidate.timestamp())
        if candidates: return min(candidates)
    raise ValueError('No valid calendar boundary')


def _month(day, count, anchor):
    index=(day.year-1)*12+day.month-1+count
    year,month=index//12+1,index%12+1
    if not 1<=year<=9999: raise ValueError('Calendar limit reached')
    return day.replace(year=year,month=month,day=min(anchor,monthrange(year,month)[1]))


@dataclass(frozen=True)
class Period:
    start: float
    end: float
    anchor_day: int
    timezone: str

    def __post_init__(self):
        instant(self.start); instant(self.end); zone(self.timezone)
        if self.end<=self.start or type(self.anchor_day) is not int or not 1<=self.anchor_day<=31:
            raise ValueError('Invalid calendar period')


@dataclass(frozen=True)
class Projection:
    until: float | None
    kind: str
    limited: bool=False


def first_period(now: float, timezone: str) -> Period:
    local=instant(now).astimezone(zone(timezone))
    boundary=_month(local.date(),1,local.day)
    return Period(now,_midnight(boundary,local.tzinfo),local.day,timezone)


def next_period(period: Period) -> Period:
    end=instant(period.end).astimezone(zone(period.timezone))
    target=_month(end.date(),1,period.anchor_day)
    return Period(period.end,_midnight(target,end.tzinfo),period.anchor_day,period.timezone)


def extend_period(period: Period, days: int) -> Period:
    if type(days) is not int or days<0: raise ValueError('Invalid compensation days')
    if days==0: return period
    end=instant(period.end).astimezone(zone(period.timezone))
    try: target=end.date()+timedelta(days=days)
    except OverflowError as exc: raise ValueError('Calendar limit reached') from exc
    shifted=_midnight(target,end.tzinfo)
    shifted_day=instant(shifted).astimezone(end.tzinfo).day
    return Period(period.start,shifted,shifted_day,period.timezone)


def forecast(period: Period | None, balance_kopecks: int, price_kopecks: int, now: float, timezone: str) -> Projection:
    money_integer(balance_kopecks,negative=True)
    money_integer(price_kopecks)
    instant(now); zone(timezone)
    if price_kopecks==0: return Projection(None,'unlimited')
    months=max(0,balance_kopecks)//price_kopecks
    if period is not None and now<period.end:
        kind='current'
    else:
        if months==0: return Projection(None,'insufficient')
        try: period=first_period(now,timezone)
        except ValueError: return Projection(None,'resume_today',True)
        kind='resume_today'
        months-=1
    if months==0: return Projection(period.end,kind)
    local=instant(period.end).astimezone(zone(period.timezone))
    try: end=_midnight(_month(local.date(),months,period.anchor_day),local.tzinfo)
    except (ValueError,OverflowError): return Projection(None,kind,True)
    return Projection(end,kind)


def compensation_days(seconds: float) -> int:
    if type(seconds) not in (int,float) or not math.isfinite(seconds) or seconds<0:
        raise ValueError('Invalid downtime')
    days,remainder=divmod(seconds,86400)
    return int(days)+(1 if remainder>43200 else 0)


def billing_snapshot(row, now, *, reliable=True):
    mode='legacy' if row['billing_mode']=='legacy' else 'monthly'
    price,balance=row['price_kopecks'],row['balance_kopecks']
    money_integer(price); money_integer(balance,negative=True)
    period=None
    if row['paid_until'] is not None:
        if row['paid_from'] is None: raise ValueError('Incomplete paid period')
        period=Period(row['paid_from'],row['paid_until'],row['anchor_day'],row['billing_timezone'])
    reason=('revoked' if row['revoked'] else 'pending' if not row['secret_hash'] else
        'manual' if row['paused'] else 'clock_error' if not reliable and price>0 else
        'insufficient_funds' if mode=='monthly' and price>0 and (period is None or not period.start<=now<period.end) else None)
    projection=Projection(None,'legacy') if mode=='legacy' else forecast(period,balance,price,now,row['billing_timezone'])
    if reason in ('revoked','pending') and price>0: projection=Projection(None,'unavailable')
    return dict(mode=mode,price_kopecks=price,balance_kopecks=balance,
        paid_from=row['paid_from'],paid_until=row['paid_until'],funds_until=projection.until,
        projection_kind=projection.kind,projection_limited=projection.limited,
        pause_reason=reason,timezone=row['billing_timezone'])
