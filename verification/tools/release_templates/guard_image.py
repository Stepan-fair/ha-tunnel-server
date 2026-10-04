"""Fail closed unless the registry confirms a version does not exist."""
import base64
import json
import os
import re
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from urllib.parse import urlencode


def check_manifest(repository,version,token,request=urlopen):
    req=Request('https://ghcr.io/v2/'+repository+'/manifests/'+version,headers={
        'Authorization':'Bearer '+token,'Accept':'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json'})
    try:
        with request(req,timeout=15): pass
    except HTTPError as exc:
        if exc.code==404:
            try:
                errors=json.loads(exc.read(65536)).get('errors',[])
                if errors and all(error.get('code') in ('MANIFEST_UNKNOWN','NAME_UNKNOWN') for error in errors): return
            except (ValueError,AttributeError,TypeError): pass
        raise RuntimeError('Registry did not confirm absence; release stopped.') from None
    except (URLError,TimeoutError,OSError):
        raise RuntimeError('Registry unavailable; release stopped.') from None
    raise RuntimeError('Version already published; create a new version.')


def main():
    repository=os.environ['IMAGE'].removeprefix('ghcr.io/')
    version=os.environ['VERSION']
    if not re.fullmatch(r'stepan-fair/ha-tunnel-(server|client)-amd64',repository) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',version):
        raise RuntimeError('Invalid release target')
    credentials=base64.b64encode((os.environ['REGISTRY_USER']+':'+os.environ['REGISTRY_PASSWORD']).encode()).decode()
    req=Request('https://ghcr.io/token?'+urlencode({'service':'ghcr.io','scope':'repository:'+repository+':pull'}),
        headers={'Authorization':'Basic '+credentials})
    try:
        with urlopen(req,timeout=15) as response: token=json.loads(response.read(65536))['token']
    except Exception:
        raise RuntimeError('Registry authorization unavailable; release stopped.') from None
    check_manifest(repository,version,token)


if __name__=='__main__': main()
