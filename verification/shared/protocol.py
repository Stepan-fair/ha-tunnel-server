from dataclasses import dataclass, field
import base64
import json

from shared.validation import origin, token


@dataclass(frozen=True)
class Invitation:
    server: str
    code: str = field(repr=False)

    def encode(self) -> str:
        raw = json.dumps({'server': origin(self.server), 'code': token(self.code)},
                         separators=(',', ':')).encode()
        return 'HT1.' + base64.urlsafe_b64encode(raw).decode().rstrip('=')

    @classmethod
    def parse(cls, text: str):
        try:
            if not isinstance(text, str) or not text.startswith('HT1.') or len(text) > 2048:
                raise ValueError()
            encoded = text[4:]
            raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
            data = json.loads(raw)
            if not isinstance(data, dict) or set(data) != {'server', 'code'}:
                raise ValueError()
            return cls(origin(data['server']), token(data['code']))
        except (ValueError, TypeError, UnicodeError, KeyError) as exc:
            raise ValueError('Invalid connection code') from exc


@dataclass(frozen=True)
class Client:
    client_id: str
    domain: str


@dataclass(frozen=True)
class Credentials(Client):
    secret: str = field(repr=False)


@dataclass(frozen=True)
class Enrollment:
    client_id: str
    domain: str
    code: str = field(repr=False)
    expires: int = 0
