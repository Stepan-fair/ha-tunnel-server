from pathlib import Path
import subprocess
import sys


def test_frozen_baseline_packages_cannot_shadow_current_frp_harness(tmp_path):
    # Old published applications have tools/tests packages but lack new helpers.
    # A separate interpreter reproduces import precedence without FRP execution.
    for name in ('tools','tests'):
        package=tmp_path/name; package.mkdir(); (package/'__init__.py').write_text('')
    root=Path(__file__).resolve().parents[1]
    code='''
import asyncio, pathlib, runpy, sys
root=pathlib.Path(sys.argv[1]); sys.path[:0]=[sys.argv[2],str(root)]
namespace=runpy.run_path(str(root/'tools/frp_performance.py'))
real=runpy.run_path
def stopped(path,*args,**kwargs):
    if str(path).replace('\\\\','/').endswith('tests/integration/test_frp.py'):
        return {'FRPS':None,'FRPC':None}
    return real(path,*args,**kwargs)
runpy.run_path=stopped
try: asyncio.run(namespace['measure'](root,pathlib.Path(sys.argv[2])))
except RuntimeError as error: assert str(error)=='Real FRP binaries required'
else: raise AssertionError('Fixture must not execute FRP')
print('Current harness loaded; no binary launched')
'''
    result=subprocess.run([sys.executable,'-c',code,str(root),str(tmp_path)],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert 'no binary launched' in result.stdout
