import pytest
from shared.presentation import format_metrics,METRIC_LABELS


def sample(**changes):
    return {'ha_available':True,'frp_connected':True,'rtt_ms':265,'telemetry_age_s':21,
            'to_client_bps':1000,'from_client_bps':0,'to_client_bytes':1000000,
            'from_client_bytes':1024,'total_bytes':1001024,'traffic_started_at':0,**changes}


def test_decimal_units_and_client_directions():
    display=format_metrics(sample(),{'deadline':None},'Europe/Moscow')
    assert display['received']=='1 МБ' and display['sent']=='1,0 КБ'
    assert display['receive_rate']=='1,0 КБ/с' and display['send_rate']=='0 Б/с'
    assert display['access']=='бессрочный'
    assert '03:00:00' in display['statistics_since'] and 'Europe/Moscow' in display['statistics_since']
    assert METRIC_LABELS['to_client_bps']=='Приём' and METRIC_LABELS['from_client_bps']=='Передача'


@pytest.mark.parametrize('age,phrase',[(21,'21 секунду'),(22,'22 секунды'),(25,'25 секунд')])
def test_age_plural(age,phrase):
    assert format_metrics(sample(telemetry_age_s=age),None,'UTC')['updated']=='Обновлено '+phrase+' назад'


def test_stale_has_no_false_zero_but_keeps_counters():
    display=format_metrics(sample(telemetry_age_s=46),None,'UTC')
    assert display['receive_rate']==display['rtt']=='Нет свежих данных'
    assert display['received']=='1 МБ' and 'доступен' not in display['status']
    assert format_metrics(None,None,'UTC')['received']=='Нет данных'


def test_discovery_names_keep_existing_identity_and_units():
    from shared.discovery import discovery_payloads
    iid='a'*32; cid='b'*32
    configs=discovery_payloads(iid,'server',{'client_id':cid,'domain':'alpha.example.org','revision':1})
    for field,name,unit in [('to_client_bps','Приём','B/s'),('from_client_bytes','Отправлено','B')]:
        topic=f'homeassistant/sensor/ha_tunnel_{iid}_server_{cid}/{field}/config'
        assert configs[topic]['name']==name and configs[topic]['unit_of_measurement']==unit
        assert configs[topic]['unique_id']==f'ha_tunnel_{iid}_server_{cid}_{field}'
