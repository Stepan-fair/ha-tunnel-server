"""Stable HA discovery identities, public state only."""
from datetime import datetime, timezone
import re
from shared.presentation import METRIC_LABELS

BINARY={'frp_connected':'Туннель подключён','ha_available':'Home Assistant доступен','paused':'Пауза','expired':'Срок истёк','revoked':'Доступ отозван'}
SENSORS={'access_state':'Доступ','rtt_ms':'Время ответа HA','to_client_bps':'Скорость к клиенту',
    'from_client_bps':'Скорость от клиента','to_client_bytes':'Трафик к клиенту','from_client_bytes':'Трафик от клиента',
    'total_bytes':'Всего трафика','last_ha_success':'Последний ответ HA','deadline':'Доступ до',
    'traffic_started_at':'Начало учёта трафика','last_frp_seen':'Последний сигнал туннеля','telemetry_age_s':'Возраст показаний'}
BINARY={name:METRIC_LABELS[name] for name in BINARY}
SENSORS={name:METRIC_LABELS[name] for name in SENSORS}
DATES={'last_ha_success','deadline','traffic_started_at','last_frp_seen'}


def namespace(instance_id,role):
    if not re.fullmatch('[a-f0-9]{32}',instance_id) or role not in ('server','client'): raise ValueError('Invalid discovery identity')
    return f'ha_tunnel/{instance_id}/{role}'


def discovery_payloads(instance_id,role,client):
    prefix=namespace(instance_id,role)
    cid=client['client_id']
    if not re.fullmatch('[a-f0-9]{32}',cid): raise ValueError('Invalid client identity')
    uid=f'ha_tunnel_{instance_id}_{role}_{cid}'
    device={'identifiers':[uid],'name':f'HA Tunnel {role}: {client["domain"]}','manufacturer':'HA Tunnel','model':role.title()}
    configs={}
    for component,items in (('binary_sensor',BINARY),('sensor',SENSORS)):
        for name,label in items.items():
            config={'name':label,'unique_id':uid+'_'+name,'device':device,
                'availability_topic':prefix+'/availability','payload_available':'online','payload_not_available':'offline'}
            if component=='button':
                config.update(command_topic=f'{prefix}/{cid}/command',
                    availability=[{'topic':prefix+'/availability'},{'topic':f'{prefix}/{cid}/controls'}],availability_mode='all',
                    payload_press={'action':name,'client_id':cid,'revision':client['revision']})
                config.pop('availability_topic')
            else:
                config.update(state_topic=f'{prefix}/{cid}/state',value_template='{{ value_json.'+name+' }}',expire_after=45)
                config.pop('availability_topic')
                config.update(availability=[{'topic':prefix+'/availability'},
                    {'topic':f'{prefix}/{cid}/state','value_template':'{{ "online" if value_json.'+name+' is not none else "offline" }}'}],availability_mode='all')
                if component=='binary_sensor':
                    config.update(payload_on='ON',payload_off='OFF',value_template='{{ "ON" if value_json.'+name+' else "OFF" }}')
                if name in DATES: config['device_class']='timestamp'
                if name.endswith('_bytes'):
                    config.update(unit_of_measurement='B',device_class='data_size',state_class='total_increasing')
                elif name.endswith('_bps'): config.update(unit_of_measurement='B/s',device_class='data_rate',state_class='measurement')
                elif name=='rtt_ms': config.update(unit_of_measurement='ms',state_class='measurement')
                elif name=='telemetry_age_s': config.update(unit_of_measurement='s',state_class='measurement')
            configs[f'homeassistant/{component}/{uid}/{name}/config']=config
    return configs


def state_payload(client):
    telemetry=client.get('telemetry') or {}
    result={name:client.get(name) for name in ('access_state','paused','expired','revoked','deadline')}
    result.update({name:telemetry.get(name) for name in set(BINARY)|set(SENSORS) if name not in result})
    for name in DATES:
        value=result.get(name)
        if value is not None: result[name]=datetime.fromtimestamp(value,timezone.utc).isoformat()
    return result
