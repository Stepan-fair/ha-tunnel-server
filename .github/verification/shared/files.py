import os
from pathlib import Path
import tempfile


def sync_directory(path):
    """POSIX rename durability; Windows does not support directory fsync."""
    if os.name != 'posix': return
    fd=os.open(path,os.O_RDONLY | getattr(os,'O_DIRECTORY',0))
    try: os.fsync(fd)
    finally: os.close(fd)


def atomic_write(path: Path, data: bytes, mode=0o600, before_replace=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Repeat ancestor barriers even when directories already exist: a previous
    # mkdir may have succeeded before its fsync failed (including across restart).
    for ancestor in reversed(path.parent.parents): sync_directory(ancestor)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        os.chmod(temporary, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if before_replace is not None:
            before_replace()
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
