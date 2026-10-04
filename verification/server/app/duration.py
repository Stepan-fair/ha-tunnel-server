"""Calendar access periods, with explicit timezone and DST resolution."""
from calendar import monthrange
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


@dataclass(frozen=True)
class Duration:
    years: int = 0
    months: int = 0
    weeks: int = 0
    days: int = 0
    hours: int = 0
    minutes: int = 0

    def __post_init__(self):
        values = asdict(self).values()
        if any(type(v) is not int or not 0 <= v <= 10**9 for v in values) or not any(values):
            raise ValueError('Duration must contain positive whole units')


def parse_duration(data: dict) -> Duration:
    if not isinstance(data, dict) or set(data) - set(Duration.__dataclass_fields__):
        raise ValueError('Invalid duration fields')
    return Duration(**data)


def resolve_local(local: datetime, zone: ZoneInfo) -> datetime:
    candidates = [local.replace(tzinfo=zone, fold=f).astimezone(timezone.utc) for f in (0, 1)]
    valid = [d for d in candidates if d.astimezone(zone).replace(tzinfo=None) == local]
    if valid:
        return min(valid)
    # A gap: fold=0 maps forward by the transition size. Never move backwards.
    forward = [d for d in candidates if d.astimezone(zone).replace(tzinfo=None) > local]
    if not forward:
        raise ValueError('Unable to resolve local date')
    return min(forward)


def deadline_at(start_utc: datetime, duration: Duration, timezone: str) -> datetime:
    from datetime import timezone as tz
    if not isinstance(start_utc, datetime) or start_utc.tzinfo is None or not isinstance(duration, Duration):
        raise ValueError('An aware start and validated duration are required')
    try:
        zone = ZoneInfo(timezone)
        if not any((duration.years, duration.months, duration.weeks, duration.days)):
            return start_utc.astimezone(tz.utc) + timedelta(hours=duration.hours, minutes=duration.minutes)
        local = start_utc.astimezone(zone).replace(tzinfo=None)
        month = (local.year - 1) * 12 + local.month - 1 + duration.years * 12 + duration.months
        year, month_index = divmod(month, 12)
        local = local.replace(year=year + 1, month=month_index + 1,
                              day=min(local.day, monthrange(year + 1, month_index + 1)[1]))
        local += timedelta(days=duration.weeks * 7 + duration.days)
        deadline = resolve_local(local, zone) + timedelta(hours=duration.hours, minutes=duration.minutes)
        if deadline <= start_utc.astimezone(tz.utc):
            raise ValueError('Duration must end after start')
        return deadline
    except (ZoneInfoNotFoundError, OverflowError, TypeError, ValueError) as exc:
        raise ValueError('Invalid timezone or duration exceeds supported dates') from exc
