"""Shared bounded telemetry schema and monotonic age handling."""
import math

BOOLS=('frp_connected','ha_available')
NUMBERS=('rtt_ms','last_ha_success','last_frp_seen','sampled_at','telemetry_age_s',
         'to_client_bps','from_client_bps','traffic_started_at')
COUNTERS=('to_client_bytes','from_client_bytes','total_bytes')
FIELDS=set(BOOLS+NUMBERS+COUNTERS+('telemetry_error',))
DYNAMIC=('frp_connected','ha_available','rtt_ms','to_client_bps','from_client_bps')


def parse_telemetry(data, received_monotonic):
    if not isinstance(data,dict) or set(data)!=FIELDS: raise ValueError('Invalid telemetry fields')
    for name in BOOLS:
        if data[name] is not None and type(data[name]) is not bool: raise ValueError('Invalid connection status')
    for name in NUMBERS:
        value=data[name]
        if value is not None and (type(value) not in (int,float) or not math.isfinite(value) or value<0): raise ValueError('Invalid telemetry value')
    for name in COUNTERS:
        if type(data[name]) is not int or not 0<=data[name]<=2**64-2: raise ValueError('Invalid traffic counter')
    if data['total_bytes']!=data['to_client_bytes']+data['from_client_bytes']: raise ValueError('Traffic total mismatch')
    if data['telemetry_error'] not in (None,'traffic_storage_error','probe_error'): raise ValueError('Invalid telemetry error')
    return {**data,'_received_monotonic':received_monotonic}


def age_telemetry(data, now):
    result={name:data[name] for name in FIELDS}
    elapsed=max(0,now-data['_received_monotonic'])
    result['telemetry_age_s']=(result['telemetry_age_s'] or 0)+elapsed
    if elapsed>45 or result['telemetry_age_s']>45:
        for name in DYNAMIC: result[name]=None
    return result
