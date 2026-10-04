"""Migrate only the application's data volume, then permanently leave root."""
import ctypes
import os
from pathlib import Path
import stat

SERVER_UID=10001
SERVER_GID=10001


def prepare_server_data(directory='/data'):
    directory=Path(directory)
    if not directory.exists(): directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise ValueError('Application data must be a real directory')
    if not hasattr(os,'geteuid') or os.geteuid()!=0: return
    for parent,dirs,files in os.walk(directory,followlinks=False):
        for name in dirs+files:
            path=Path(parent)/name
            if path.is_symlink(): raise ValueError('Unexpected link in application data')
            os.chown(path,SERVER_UID,SERVER_GID,follow_symlinks=False)
    os.chown(directory,SERVER_UID,SERVER_GID,follow_symlinks=False)
    directory.chmod(0o700)


def drop_server_privileges(directory='/data'):
    prepare_server_data(directory)
    if os.geteuid()!=0: return
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0)!=0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(),'Cannot disable privilege escalation')
    os.setgroups([])
    os.setgid(SERVER_GID)
    os.setuid(SERVER_UID)
    if os.geteuid()!=SERVER_UID: raise RuntimeError('Privilege drop failed')
