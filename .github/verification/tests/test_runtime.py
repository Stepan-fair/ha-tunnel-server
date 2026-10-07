import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def test_pki_preserves_ca_and_renews_leaf(tmp_path):
    from server.app.pki import ensure_pki
    now = datetime.now(timezone.utc)
    first = ensure_pki(tmp_path, 'tunnel.example.org', now)
    ca = first.ca.read_bytes()
    leaf = first.cert.read_bytes()
    cert = x509.load_pem_x509_certificate(leaf)
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ['tunnel.example.org']
    assert not ensure_pki(tmp_path, 'tunnel.example.org', now + timedelta(days=1)).renewed
    changed = ensure_pki(tmp_path, 'tunnel.example.org', now + timedelta(days=80))
    assert changed.renewed
    assert changed.ca.read_bytes() == ca
    assert changed.cert.read_bytes() != leaf
    assert 'PRIVATE' not in ca.decode()
    key = serialization.load_pem_private_key(changed.key.read_bytes(), password=None)
    assert key.key_size >= 3072


def test_pki_does_not_silently_replace_partial_identity(tmp_path):
    from server.app.pki import ensure_pki
    now = datetime.now(timezone.utc)
    files = ensure_pki(tmp_path, 'tunnel.example.org', now)
    (tmp_path/'ca.key').unlink()
    with pytest.raises(ValueError):
        ensure_pki(tmp_path, 'tunnel.example.org', now)
    assert files.ca.exists()


def test_generated_configs_enforce_security(tmp_path):
    from server.app.runtime import server_config
    from client.app.runtime import client_config
    from server.app.pki import ensure_pki
    pki = ensure_pki(tmp_path, 'tunnel.example.org')
    server = server_config(pki, 7000, 18080, 19000)
    assert server['transport']['tls']['force'] is True
    assert server['proxyBindAddr'] == '127.0.0.1'
    assert set(server['auth']['additionalScopes']) == {'HeartBeats','NewWorkConns'}
    assert server['auth']['method'] == 'oidc'
    assert 'webServer' not in server
    creds = {'client_id':'a'*32,'secret':'x'*43,'domain':'ha.example.org',
             'server_url':'https://tunnel.example.org','tunnel_host':'tunnel.example.org','tunnel_port':7000}
    client = client_config(creds, pki.ca)
    assert client['transport']['tls']['enable'] is True
    assert client['transport']['tls']['serverName'] == 'tunnel.example.org'
    assert client['transport']['tls']['trustedCaFile'] == str(pki.ca)
    assert client['auth']['oidc']['tokenEndpointURL'] == 'https://tunnel.example.org/v1/token'
    assert client['proxies'][0]['localIP'] == '127.0.0.1'
    assert client['proxies'][0]['localPort'] == 8123
    assert client['transport']['heartbeatInterval'] == 30
    assert client['transport']['heartbeatTimeout'] == 90


async def test_process_lifecycle_and_secret_free_status(tmp_path):
    from shared.runtime import FrpRuntime
    helper = tmp_path/'helper.py'
    helper.write_text("import time,sys\nprint('private-secret', flush=True)\ntime.sleep(60)\n")
    runtime = FrpRuntime(sys.executable, tmp_path/'runtime.json', prefix=[str(helper)], verify=False)
    await runtime.start({'secret':'private-secret'})
    try:
        assert runtime.status()['running']
        old_pid = runtime.process.pid
        await runtime.restart()
        assert runtime.process.pid != old_pid
        assert 'private-secret' not in json.dumps(runtime.status())
    finally:
        await runtime.stop()
    assert not runtime.status()['running']
    assert runtime.process.returncode is not None


async def test_failed_verification_does_not_start(tmp_path):
    from shared.runtime import FrpRuntime
    helper = tmp_path/'bad.py'
    helper.write_text('import sys\nsys.exit(2)\n')
    runtime = FrpRuntime(sys.executable,tmp_path/'runtime.json',prefix=[str(helper)])
    with pytest.raises(RuntimeError, match='configuration'):
        await runtime.start({})
    assert not runtime.status()['running']
