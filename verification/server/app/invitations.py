"""Recoverable invitation ciphertext; the encryption key is outside SQLite."""
import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shared.validation import token


class InvitationVault:
    def __init__(self, directory: Path, *, require_existing=False):
        self.path = Path(directory)/'invitations.key'
        if not self.path.exists():
            if require_existing:
                raise ValueError('Invitation key is missing; restore the server state')
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(secrets.token_bytes(32))
                    stream.flush()
                    os.fsync(stream.fileno())
        self.key = self.path.read_bytes()
        if len(self.key) != 32:
            raise ValueError('Invalid invitation key')
        self.path.chmod(0o600)

    def seal(self, client_id: str, code: str) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(self.key).encrypt(nonce, token(code).encode(), client_id.encode('ascii'))

    def open(self, client_id: str, blob: bytes) -> str:
        try:
            if not isinstance(blob, bytes) or not 28 <= len(blob) <= 2048:
                raise ValueError()
            return token(AESGCM(self.key).decrypt(blob[:12], blob[12:], client_id.encode('ascii')).decode('ascii'))
        except Exception:
            raise ValueError('Invitation cannot be decrypted; restore server state') from None
