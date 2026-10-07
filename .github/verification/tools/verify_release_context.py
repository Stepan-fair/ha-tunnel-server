"""Require the published image context to match the source tested by CI."""
import argparse
import hashlib
from pathlib import Path
import tempfile

if __package__:
    from tools.package import package
else:
    from package import package


def inventory(root):
    result={}
    for path in root.rglob('*'):
        if path.is_symlink(): raise ValueError('Production context differs: symlink')
        if path.is_file():
            result[path.relative_to(root).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def verify_release_context(repository,component):
    repository=Path(repository)
    # Match Supervisor discovery without exposing CI's copies as installable apps.
    configs={
        path.relative_to(repository).as_posix()
        for path in repository.glob('**/config.*')
        if path.suffix in ('.yaml','.yml','.json')
        and not any(part.startswith('.') or part=='rootfs'
                    for part in path.relative_to(repository).parts)
    }
    if configs!={f'{component}/config.yaml'}:
        raise ValueError('Unexpected discoverable application configuration')
    with tempfile.TemporaryDirectory(prefix='ha-tunnel-context-') as temporary:
        package(Path(temporary)/'expected',component=component)
        expected=inventory(Path(temporary)/'expected'/component)
        actual=inventory(Path(repository)/component)
        if actual!=expected: raise ValueError('Production context differs from verified sources')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--repository',required=True,type=Path)
    parser.add_argument('--component',required=True,choices=('server','client'))
    args=parser.parse_args()
    verify_release_context(args.repository,args.component)
