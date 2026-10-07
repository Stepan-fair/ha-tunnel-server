"""Generate a role repository; never publish the private project checkout."""
import argparse
from pathlib import Path
import shutil
if __package__:
    from tools.package import package,ROOT
else:
    from package import package,ROOT


def release_repository(component,output):
    package(output,component=component)
    # Keep the duplicate production/verification text identical on all runners.
    (Path(output)/'.gitattributes').write_text('* text eol=lf\n',encoding='utf-8')
    target=Path(output)/'.github/workflows/build.yml'
    target.parent.mkdir(parents=True,exist_ok=True)
    text=(ROOT/'tools/release_templates/build.yml').read_text(encoding='utf-8')
    target.write_text(text.replace('__ROLE__',component),encoding='utf-8')
    script=Path(output)/'.github/scripts/guard_image.py'
    script.parent.mkdir(parents=True,exist_ok=True)
    script.write_bytes((ROOT/'tools/release_templates/guard_image.py').read_bytes())
    verification=Path(output)/'.github'/'verification'
    for name in ('server','client','shared','tests','tools','docs'):
        for source in (ROOT/name).rglob('*'):
            if (source.is_file() and '__pycache__' not in source.parts and
                    source.suffix in ('.py','.json','.html','.js','.cjs','.css','.yml','.yaml','.md','.sh')):
                destination=verification/source.relative_to(ROOT)
                destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source,destination)
    for name in ('requirements.lock','requirements-dev.lock','repository.yaml','README.md','LICENSE','SECURITY.md','THIRD_PARTY.md','pytest.ini'):
        destination=verification/name; destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/name,destination)
    shutil.copyfile(ROOT/'server/Dockerfile',verification/'server/Dockerfile')
    shutil.copyfile(ROOT/'client/Dockerfile',verification/'client/Dockerfile')
    shutil.copyfile(ROOT/'tools/Dockerfile.test',verification/'tools/Dockerfile.test')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--component',required=True,choices=('server','client'))
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args(); release_repository(args.component,args.output)
