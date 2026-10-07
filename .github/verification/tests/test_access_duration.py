from datetime import datetime, timezone

import pytest


def utc(value):
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


@pytest.mark.parametrize('start,parts,zone,end', [
    ('2028-01-31T12:00', {'months': 1}, 'UTC', '2028-02-29T12:00'),
    ('2028-02-29T12:00', {'years': 1}, 'UTC', '2029-02-28T12:00'),
    ('2026-10-03T12:00', dict(years=1, months=2, weeks=2, days=3, hours=1, minutes=20), 'UTC', '2027-12-20T13:20'),
    ('2026-03-28T11:00', {'days': 1}, 'Europe/Berlin', '2026-03-29T10:00'),
    ('2026-03-28T11:00', {'hours': 24}, 'Europe/Berlin', '2026-03-29T11:00'),
    # 02:30 is a DST gap; advance to 03:30. Autumn fold chooses first occurrence.
    ('2026-03-28T01:30', {'days': 1}, 'Europe/Berlin', '2026-03-29T01:30'),
    ('2026-10-24T00:30', {'days': 1}, 'Europe/Berlin', '2026-10-25T00:30'),
])
def test_calendar_duration(start, parts, zone, end):
    from server.app.duration import deadline_at, parse_duration
    assert deadline_at(utc(start), parse_duration(parts), zone) == utc(end)


@pytest.mark.parametrize('parts', [{}, {'minutes': 0}, {'days': -1}, {'hours': 1.5},
    {'years': True}, {'seconds': 1}, {'minutes': '10'}, None, {'years': 10000}])
def test_duration_rejects_invalid_inputs(parts):
    from server.app.duration import parse_duration, deadline_at
    with pytest.raises(ValueError):
        deadline_at(utc('2026-01-01T00:00'), parse_duration(parts), 'UTC')


def test_duration_rejects_unknown_zone_and_naive_time():
    from server.app.duration import Duration, deadline_at
    with pytest.raises(ValueError):
        deadline_at(utc('2026-01-01T00:00'), Duration(days=1), 'Missing/Zone')
    with pytest.raises(ValueError):
        deadline_at(datetime(2026, 1, 1), Duration(days=1), 'UTC')


def test_clock_rollback_never_extends_access():
    from server.app.clock import SafeClock
    wall, mono = [1000.0], [0.0]
    clock = SafeClock(lambda: wall[0], lambda: mono[0], 0)
    assert clock.now() == 1000
    wall[0], mono[0] = 900, 5
    assert clock.now() >= 1005
    assert not clock.reliable
    assert clock.checkpoint() >= 1005
    wall[0] = 1010
    assert clock.now() == 1010
    assert clock.reliable


def test_clock_restart_before_saved_anchor_is_unreliable():
    from server.app.clock import SafeClock
    clock = SafeClock(lambda: 900, lambda: 0, 1000)
    assert clock.now() == 1000
    assert not clock.reliable
