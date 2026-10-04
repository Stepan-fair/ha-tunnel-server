import importlib.util
import io
import pytest
from pathlib import Path
from urllib.error import HTTPError,URLError


def guard():
    spec=importlib.util.spec_from_file_location('guard_image',Path('tools/release_templates/guard_image.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('code,body,allowed',[(404,b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}',True),
    (404,b'{"errors":[{"code":"NAME_UNKNOWN"}]}',True),(404,b'gateway error',False),
    (401,b'{}',False),(503,b'{}',False)])
def test_only_confirmed_missing_manifest_allows_release(code,body,allowed):
    module=guard()
    def request(req,timeout): raise HTTPError(req.full_url,code,'error',{},io.BytesIO(body))
    if allowed: module.check_manifest('stepan-fair/image','0.3.0','token',request)
    else:
        with pytest.raises(RuntimeError): module.check_manifest('stepan-fair/image','0.3.0','token',request)


def test_existing_image_and_network_failure_stop_release():
    module=guard()
    class Response:
        def __enter__(self): return self
        def __exit__(self,*args): pass
    def exists(req,timeout): return Response()
    def offline(req,timeout): raise URLError('offline')
    for request in (exists,offline):
        with pytest.raises(RuntimeError): module.check_manifest('stepan-fair/image','0.3.0','token',request)
