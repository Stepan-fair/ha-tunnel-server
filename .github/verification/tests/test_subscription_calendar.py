from datetime import datetime
from zoneinfo import ZoneInfo
import pytest
from server.app.subscription import first_period, next_period, extend_period, forecast, compensation_days


def stamp(year,month,day,hour=0,zone='Europe/Moscow'):
    return datetime(year,month,day,hour,tzinfo=ZoneInfo(zone)).timestamp()


def test_paid_15th_ends_before_15th_next_month():
    period=first_period(stamp(2026,10,15,10),'Europe/Moscow')
    assert period.start==stamp(2026,10,15,10)
    assert period.end==stamp(2026,11,15) and period.anchor_day==15
    assert next_period(period).end==stamp(2026,12,15)


@pytest.mark.parametrize('year,end_day',[(2027,28),(2028,29)])
def test_31st_anchor_survives_february(year,end_day):
    period=first_period(stamp(year,1,31,10),'Europe/Moscow')
    assert period.end==stamp(year,2,end_day)
    assert next_period(period).end==stamp(year,3,31)
    assert next_period(next_period(period)).end==stamp(year,4,30)


@pytest.mark.parametrize('day',[29,30,31])
def test_missing_day_is_clamped_but_original_anchor_restored(day):
    period=first_period(stamp(2027,1,day),'Europe/Moscow')
    assert period.end==stamp(2027,2,28)
    assert next_period(period).end==stamp(2027,3,day)


def test_dst_month_is_calendar_not_30_times_24_hours():
    period=first_period(stamp(2026,3,15,10,'Europe/Berlin'),'Europe/Berlin')
    assert period.end==stamp(2026,4,15,0,'Europe/Berlin')


def test_nonexistent_midnight_advances_to_first_valid_local_instant():
    period=first_period(stamp(2018,10,4,10,'America/Sao_Paulo'),'America/Sao_Paulo')
    assert period.end==stamp(2018,11,4,1,'America/Sao_Paulo')


def test_ambiguous_midnight_uses_earliest_valid_instant():
    period=first_period(stamp(2015,10,1,10,'America/Havana'),'America/Havana')
    assert period.end==datetime(2015,11,1,0,tzinfo=ZoneInfo('America/Havana'),fold=0).timestamp()


@pytest.mark.parametrize('seconds,days',[(43200,0),(43201,1),(86400,1),(108000,1),(129600,1),(129601,2),(172800,2),(216000,2),(216001,3)])
def test_exact_downtime_rounding(seconds,days):
    assert compensation_days(seconds)==days


@pytest.mark.parametrize('seconds',[-1,float('inf'),float('nan'),True])
def test_invalid_downtime_rejected(seconds):
    with pytest.raises(ValueError): compensation_days(seconds)


def test_compensation_moves_next_debit_and_future_anchor():
    period=extend_period(first_period(stamp(2026,10,15,10),'Europe/Moscow'),2)
    assert period.end==stamp(2026,11,17)
    assert next_period(period).end==stamp(2026,12,17)


def test_forecast_buys_nothing_and_handles_partial_and_debt():
    now=stamp(2026,10,15,10)
    period=first_period(now,'Europe/Moscow')
    assert forecast(period,60000,30000,now,'Europe/Moscow').until==stamp(2027,1,15)
    assert forecast(period,29999,30000,now,'Europe/Moscow').until==period.end
    assert forecast(period,-10000,30000,now,'Europe/Moscow').until==period.end
    assert period.end==stamp(2026,11,15)
    assert forecast(None,29999,30000,now,'Europe/Moscow').kind=='insufficient'
    assert forecast(None,90000,30000,now,'Europe/Moscow').until==stamp(2027,1,15)
    assert forecast(None,-1000,0,now,'Europe/Moscow').kind=='unlimited'


def test_forecast_huge_balance_is_bounded_and_does_not_overflow():
    result=forecast(first_period(stamp(2026,10,15),'Europe/Moscow'),2**63-1,1,stamp(2026,10,15),'Europe/Moscow')
    assert result.limited and result.until is None


@pytest.mark.parametrize('zone',['not/a_zone','../secret','',None])
def test_invalid_timezone_rejected(zone):
    with pytest.raises(ValueError): first_period(stamp(2026,10,15),zone)
