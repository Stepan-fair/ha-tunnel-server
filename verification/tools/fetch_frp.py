import hashlib
import json
import platform
from pathlib import Path
import sys
import tarfile
import tempfile
import urllib.request

component=sys.argv[1]
if component not in ('frps','frpc'):
    raise SystemExit('Invalid component')
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
versions=json.loads(Path(__file__).with_name('frp_versions.json').read_text())
version=versions['version']
name=f'frp_{version}_linux_{arch}'
with tempfile.TemporaryDirectory() as temp:
    archive=Path(temp)/'frp.tar.gz'
    urllib.request.urlretrieve(f'https://github.com/fatedier/frp/releases/download/v{version}/{name}.tar.gz',archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=versions[f'linux_{arch}']:
        raise SystemExit('FRP archive checksum mismatch')
    with tarfile.open(archive) as source:
        for member,target in ((f'{name}/{component}',Path('/usr/local/bin')/component),
                              (f'{name}/LICENSE',Path('/usr/share/doc/frp/LICENSE'))):
            info=source.getmember(member)
            if not info.isfile(): raise SystemExit('Invalid archive member')
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(source.extractfile(info).read())
    (Path('/usr/local/bin')/component).chmod(0o755)
