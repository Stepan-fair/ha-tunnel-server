import re
from urllib.parse import urlsplit

LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z', re.ASCII)
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}\Z', re.ASCII)


def label(value: str) -> str:
    if not isinstance(value, str) or not LABEL.fullmatch(value):
        raise ValueError('Invalid DNS label')
    return value


def domain(value: str) -> str:
    if not isinstance(value, str) or len(value) > 253 or '.' not in value:
        raise ValueError('Invalid domain')
    for part in value.split('.'):
        label(part)
    return value


def origin(value: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError('Invalid server origin')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.username or parsed.password or
            parsed.path not in ('', '/') or parsed.query or parsed.fragment or
            parsed.port not in (None, 443)):
        raise ValueError('HTTPS origin required')
    host = domain(parsed.hostname or '')
    if value not in (f'https://{host}', f'https://{host}/', f'https://{host}:443'):
        raise ValueError('Noncanonical origin')
    return f'https://{host}'


def token(value: str) -> str:
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        raise ValueError('Invalid credential')
    return value
