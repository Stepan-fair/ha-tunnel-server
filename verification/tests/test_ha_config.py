import pytest


def prepare(tmp_path, text):
    from client.app.ha_config import prepare_patch
    path = tmp_path/'configuration.yaml'
    path.write_text(text,encoding='utf-8')
    return path, prepare_patch(path)


def test_add_proxy_settings_preserves_existing_config_and_comments(tmp_path):
    from client.app.ha_config import apply_patch, rollback
    original = '# Мой дом\ndefault_config:\nhttp:\n  server_port: 8123  # local\n  trusted_proxies:\n    - 192.168.1.2\n'
    path, preview = prepare(tmp_path, original)
    assert preview.changed
    record = apply_patch(preview)
    changed = path.read_text(encoding='utf-8')
    for text in ('# Мой дом','server_port: 8123  # local','192.168.1.2','127.0.0.1/32','use_x_forwarded_for: true'):
        assert text in changed
    assert record.backup.read_text(encoding='utf-8') == original
    rollback(record)
    assert path.read_text(encoding='utf-8') == original


def test_missing_http_and_idempotence(tmp_path):
    from client.app.ha_config import apply_patch, prepare_patch
    path, preview = prepare(tmp_path,'default_config:\n')
    apply_patch(preview)
    assert not prepare_patch(path).changed


def test_include_edits_only_local_include(tmp_path):
    from client.app.ha_config import prepare_patch, apply_patch
    main = tmp_path/'configuration.yaml'
    main.write_text('http: !include http.yaml\nsensor: !include sensors.yaml\n')
    child = tmp_path/'http.yaml'
    child.write_text('ip_ban_enabled: true\n')
    original = main.read_bytes()
    preview = prepare_patch(main)
    assert preview.path == child
    apply_patch(preview)
    assert '127.0.0.1/32' in child.read_text()
    assert main.read_bytes() == original


@pytest.mark.parametrize('text',[
    'http: !secret private_http\n',
    'http: !include ../outside.yaml\n',
    'http: !include /etc/passwd\n',
    'http: !include_dir_merge_named http\n',
    'http: {trusted_proxies: !secret proxies}\n',
    'http: {use_x_forwarded_for: !secret enabled}\n',
    'http: {trusted_proxies: [0.0.0.0/0]}\n',
    'http: {trusted_proxies: ["::/0"]}\n',
    'http: {ssl_certificate: /ssl/server.pem}\n',
    'http: {server_port: 8124}\n',
    'http: &alias {server_port: 8123}\nother: *alias\n',
    'http:\nhttp:\n',
    'http: [malformed\n',
])
def test_ambiguous_or_unsafe_config_refuses_without_writing(tmp_path,text):
    from client.app.ha_config import prepare_patch, ConfigProblem
    path=tmp_path/'configuration.yaml'
    path.write_text(text)
    before=path.read_bytes()
    with pytest.raises(ConfigProblem):
        prepare_patch(path)
    assert path.read_bytes()==before


def test_unrelated_secrets_and_anchors_survive(tmp_path):
    from client.app.ha_config import apply_patch
    text = 'example: &name value\nother: *name\npassword: !secret password\nhttp:\n  ip_ban_enabled: true\n'
    path,preview=prepare(tmp_path,text)
    apply_patch(preview)
    changed=path.read_text()
    assert '&name' in changed and '*name' in changed and '!secret password' in changed


def test_concurrent_edit_and_include_change_are_detected(tmp_path):
    from client.app.ha_config import apply_patch,prepare_patch,ConfigProblem,rollback
    path,preview=prepare(tmp_path,'http:\n')
    path.write_text('http:\n  ip_ban_enabled: true\n')
    with pytest.raises(ConfigProblem):
        apply_patch(preview)
    record=apply_patch(prepare_patch(path))
    path.write_text('http:\n  server_port: 9999\n')
    with pytest.raises(ConfigProblem):
        rollback(record)
    child=tmp_path/'http.yaml'
    child.write_text('ip_ban_enabled: true\n')
    path.write_text('http: !include http.yaml\n')
    preview=prepare_patch(path)
    path.write_text('http: !include different.yaml\n')
    with pytest.raises(ConfigProblem):
        apply_patch(preview)


async def test_failed_ha_check_rolls_back_without_restart(tmp_path):
    from client.app.ha_config import configure_ha
    path=tmp_path/'configuration.yaml'
    path.write_text('default_config:\n')
    before=path.read_bytes()
    class Supervisor:
        restarted=False
        async def check_config(self): return False
        async def restart_core(self): self.restarted=True
    supervisor=Supervisor()
    with pytest.raises(ValueError):
        await configure_ha(path,supervisor)
    assert path.read_bytes()==before
    assert not supervisor.restarted


def test_edit_during_backup_is_not_overwritten(tmp_path,monkeypatch):
    from client.app import ha_config
    path,preview=prepare(tmp_path,'default_config:\n')
    write=ha_config.atomic_write
    newer=b'default_config:\n# saved in another editor\n'
    def concurrent_write(target,data,**kwargs):
        write(target,data,**kwargs)
        if str(target).endswith('.bak'):
            path.write_bytes(newer)
    monkeypatch.setattr(ha_config,'atomic_write',concurrent_write)
    with pytest.raises(ha_config.ConfigProblem):
        ha_config.apply_patch(preview)
    assert path.read_bytes()==newer


async def test_restart_failure_can_be_retried_after_controller_restart(tmp_path):
    from client.app.ha_config import configure_ha
    path=tmp_path/'configuration.yaml'
    path.write_text('default_config:\n')
    pending=tmp_path/'pending'
    class Supervisor:
        restarts=0
        async def check_config(self): return True
        async def restart_core(self):
            self.restarts+=1
            if self.restarts==1: raise ValueError('rejected')
        async def wait_proxy_ready(self,timeout=180): pass
    supervisor=Supervisor()
    with pytest.raises(ValueError):
        await configure_ha(path,supervisor,pending)
    assert pending.exists()
    await configure_ha(path,supervisor,pending)
    assert supervisor.restarts==2
    assert not pending.exists()
