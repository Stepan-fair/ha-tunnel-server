"""Build fresh add-on contexts using an allowlist, never copying runtime data."""
import argparse
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[1]


def copy(source,target):
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,target)


def package(output,*,component=None):
    if component not in (None,'server','client'): raise ValueError('Unknown component')
    output=Path(output).absolute()
    if output.exists() and any(output.iterdir()):
        raise ValueError('Output must be a new or empty directory')
    if output==ROOT or ROOT.is_relative_to(output):
        raise ValueError('Output must not contain sources')
    output.mkdir(parents=True,exist_ok=True)
    filenames=('LICENSE','SECURITY.md','THIRD_PARTY.md','docs/ACCEPTANCE.md','docs/SECURITY_UPDATE.md') if component else (
        'repository.yaml','README.md','LICENSE','SECURITY.md','THIRD_PARTY.md','docs/ACCEPTANCE.md',
        'docs/DEPLOYMENT.md','docs/SERVER_INSTALL.md','docs/CLIENT_INSTALL.md')
    for filename in filenames:
        if (ROOT/filename).exists(): copy(ROOT/filename,output/filename)
    if component:
        url='https://github.com/Stepan-fair/ha-tunnel-'+component
        (output/'repository.yaml').write_text(f'name: HA Tunnel {component.title()}\nurl: {url}\nmaintainer: Stepan-fair\n',encoding='utf-8')
        copy(ROOT/'docs'/f'{component.upper()}_INSTALL.md',output/'README.md')
    for component in (component,) if component else ('server','client'):
        target=output/component
        for filename in ('config.yaml','Dockerfile','run.sh','DOCS.md','CHANGELOG.md'):
            source=ROOT/'docs'/f'{component.upper()}_INSTALL.md' if filename=='DOCS.md' else ROOT/component/filename
            if source.exists(): copy(source,target/filename)
        for source in (ROOT/component/'translations').glob('*.yaml'):
            copy(source,target/'translations'/source.name)
        copy(ROOT/component/'__init__.py',target/component/'__init__.py')
        for source in (ROOT/component/'app').rglob('*'):
            if source.is_file() and source.suffix in ('.py','.html','.js','.css') and '__pycache__' not in source.parts:
                copy(source,target/component/'app'/source.relative_to(ROOT/component/'app'))
        for source in (ROOT/'shared').glob('*.py'):
            copy(source,target/'shared'/source.name)
        for name in ('fetch_frp.py','frp_versions.json','healthcheck.py'):
            copy(ROOT/'tools'/name,target/'tools'/name)
        copy(ROOT/'requirements.lock',target/'requirements.lock')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--component',choices=('server','client'))
    args=parser.parse_args()
    package(args.output,component=args.component)
