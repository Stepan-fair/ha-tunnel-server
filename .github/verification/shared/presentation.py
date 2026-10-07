"""Russian display strings; directions are always from the Client's perspective."""
from datetime import datetime
from zoneinfo import ZoneInfo,ZoneInfoNotFoundError
import math

METRIC_LABELS={'frp_connected':'Туннель подключён','ha_available':'Home Assistant доступен',
    'paused':'Пауза','expired':'Срок доступа истёк','revoked':'Доступ отозван','access_state':'Доступ',
    'rtt_ms':'Время отклика','to_client_bps':'Приём','from_client_bps':'Передача',
    'to_client_bytes':'Получено','from_client_bytes':'Отправлено','total_bytes':'Всего',
    'last_ha_success':'Последний ответ HA','deadline':'Доступ до','traffic_started_at':'Статистика с',
    'last_frp_seen':'Последнее подключение','telemetry_age_s':'С момента обновления'}


def size(value,rate=False):
    if type(value) not in (int,float) or not math.isfinite(value) or value<0: return 'Нет данных'
    units=('Б','КБ','МБ','ГБ','ТБ'); unit=0
    while value>=1000 and unit<len(units)-1: value/=1000; unit+=1
    text=(f'{value:.1f}' if unit==1 else f'{value:.1f}'.removesuffix('.0')).replace('.',',')
    return text+' '+units[unit]+('/с' if rate else '')


def moment(value,zone):
    if value is None: return 'Нет данных'
    try: return datetime.fromtimestamp(value,zone).strftime('%d.%m.%Y, %H:%M:%S')+' ('+str(zone)+')'
    except (ValueError,TypeError,OverflowError,OSError): return 'Нет данных'


def format_metrics(telemetry,access,timezone):
    t=telemetry or {}
    try: zone=ZoneInfo(timezone or 'UTC')
    except (ZoneInfoNotFoundError,ValueError,TypeError): zone=ZoneInfo('UTC')
    age=t.get('telemetry_age_s')
    fresh=type(age) in (int,float) and math.isfinite(age) and 0<=age<=45
    status='Нет свежих данных'
    if fresh:
        status='Home Assistant доступен' if t.get('ha_available') else 'Туннель подключён · ждём ответ HA' if t.get('frp_connected') else 'Нет подтверждённой связи'
    updated='Время обновления неизвестно'
    if type(age) in (int,float) and math.isfinite(age) and age>=0:
        n=round(age); last=n%10; ending=n%100
        noun='секунду' if last==1 and ending!=11 else 'секунды' if 2<=last<=4 and not 12<=ending<=14 else 'секунд'
        updated=f'Обновлено {n} {noun} назад'
    rtt=t.get('rtt_ms')
    return {'status':status,'rtt':str(round(rtt))+' мс' if fresh and rtt is not None else 'Нет свежих данных',
        'receive_rate':size(t.get('to_client_bps'),True) if fresh else 'Нет свежих данных',
        'send_rate':size(t.get('from_client_bps'),True) if fresh else 'Нет свежих данных',
        'received':size(t.get('to_client_bytes')),'sent':size(t.get('from_client_bytes')),
        'total':size(t.get('total_bytes')),'updated':updated,
        'access':'Нет данных' if access is None else 'не оплачен' if (
            access.get('billing',{}).get('mode')=='monthly' and
            access['billing'].get('price_kopecks',0)>0 and access['billing'].get('paid_until') is None
        ) else 'бессрочный' if access.get('deadline') is None else 'до '+moment(access['deadline'],zone),
        'statistics_since':moment(t.get('traffic_started_at'),zone),'timezone':str(zone)}

def format_billing(snapshot,*,stale=False):
    from shared.billing_status import validate_billing
    if snapshot is None:
        return dict(available=False,balance='Нет данных',price='Нет данных',paid='Нет данных',
            funds='Сервер не передаёт сведения о подписке',pause='',updated='Время обновления неизвестно')
    data=validate_billing(snapshot)
    zone=ZoneInfo(data['timezone'])
    def money(value):
        sign='-' if value<0 else ''
        whole,fraction=divmod(abs(value),100)
        return f'{sign}{whole},{fraction:02d} ₽'
    def inclusive(value):
        if value is None: return 'Не оплачен'
        return 'до '+datetime.fromtimestamp(value-1,zone).strftime('%d.%m.%Y')+' включительно'
    zero=data['price_kopecks']==0 and data['mode']=='monthly'
    paid='Бессрочно' if zero else 'Прежний ручной срок' if data['mode']=='legacy' else inclusive(data['paid_until'])
    funds='Бессрочно' if zero else ('За пределами календарного расчёта' if data['projection_limited'] else
        'Недостаточно на один месяц' if data['projection_kind']=='insufficient' else
        'После подключения клиента' if data['projection_kind']=='unavailable' else
        'Прежний ручной срок' if data['projection_kind']=='legacy' else inclusive(data['funds_until']))
    if data['projection_kind']=='resume_today' and data['funds_until'] is not None: funds+=' при запуске сегодня'
    if data['pause_reason']=='manual' and not zero: funds+=' при возобновлении сейчас'
    pause={None:'','manual':'Ручная пауза — пополнение не запускает доступ',
        'insufficient_funds':'Доступ приостановлен: требуется оплата месяца',
        'revoked':'Доступ отозван','pending':'Ожидает подключения',
        'clock_error':'Ожидает проверки времени сервера'}[data['pause_reason']]
    return dict(available=True,balance=money(data['balance_kopecks']),price=money(data['price_kopecks'])+' / месяц',
        paid=paid,funds=funds,pause=pause,
        updated=('Последние известные данные: ' if stale else 'Обновлено: ')+moment(data['updated_at'],zone))
