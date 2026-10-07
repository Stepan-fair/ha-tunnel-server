"""Bounded, public finance snapshot. Shared by UI and Client without server imports."""
import math
from datetime import datetime,timezone
from zoneinfo import ZoneInfo,ZoneInfoNotFoundError

FIELDS={'mode','price_kopecks','balance_kopecks','paid_from','paid_until','funds_until',
    'projection_kind','projection_limited','pause_reason','timezone','updated_at'}
KINDS={'current','resume_today','insufficient','unlimited','unavailable','legacy'}
REASONS={None,'manual','insufficient_funds','revoked','pending','clock_error'}

def validate_billing(data):
    if not isinstance(data,dict) or set(data)!=FIELDS: raise ValueError('Invalid billing fields')
    if not isinstance(data['mode'],str) or data['mode'] not in ('monthly','legacy'): raise ValueError('Invalid billing mode')
    for key in ('price_kopecks','balance_kopecks'):
        value=data[key]
        if type(value) is not int or not -(2**63)<=value<=2**63-1 or key=='price_kopecks' and value<0:
            raise ValueError('Invalid money')
    for key in ('paid_from','paid_until','funds_until','updated_at'):
        value=data[key]
        if value is None and key!='updated_at': continue
        if type(value) not in (int,float) or not math.isfinite(value): raise ValueError('Invalid billing date')
        try: datetime.fromtimestamp(value,timezone.utc)
        except (ValueError,OverflowError,OSError) as exc: raise ValueError('Invalid billing date') from exc
    if (data['paid_from'] is None)!=(data['paid_until'] is None): raise ValueError('Incomplete paid period')
    if data['paid_from'] is not None and data['paid_from']>=data['paid_until']: raise ValueError('Invalid paid period')
    if data['funds_until'] is not None and data['paid_until'] is not None and data['funds_until']<data['paid_until']:
        raise ValueError('Invalid coverage')
    if (type(data['projection_limited']) is not bool or not isinstance(data['projection_kind'],str) or
            data['projection_kind'] not in KINDS or data['pause_reason'] is not None and
            (not isinstance(data['pause_reason'],str) or data['pause_reason'] not in REASONS)):
        raise ValueError('Invalid billing projection')
    name=data['timezone']
    if not isinstance(name,str) or len(name)>128: raise ValueError('Invalid billing timezone')
    try: ZoneInfo(name)
    except (ValueError,ZoneInfoNotFoundError) as exc: raise ValueError('Invalid billing timezone') from exc
    if data['projection_kind']=='unlimited' and (data['price_kopecks']!=0 or data['funds_until'] is not None):
        raise ValueError('Invalid unlimited tariff')
    return data
