"""Minimal environment for network-facing children; no application credentials."""
import os


def child_environment():
    names=('PATH','LANG','LC_ALL','TZ','TMPDIR','TEMP','TMP','SystemRoot','WINDIR')
    return {name:os.environ[name] for name in names if name in os.environ}
