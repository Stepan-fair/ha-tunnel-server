"""Conservative, conflict-detecting edits to Home Assistant HTTP configuration."""
from dataclasses import dataclass
import hashlib
import io
import ipaddress
import threading
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, TaggedScalar
from shared.files import atomic_write

WRITE_LOCK = threading.RLock()


class ConfigProblem(ValueError):
    pass


@dataclass(frozen=True)
class PatchPreview:
    path: Path
    original: bytes
    rendered: bytes
    guards: tuple

    @property
    def changed(self):
        return self.original != self.rendered


@dataclass(frozen=True)
class RollbackRecord:
    path: Path
    backup: Path
    original: bytes
    written_hash: str


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reject(message):
    raise ConfigProblem(message)


def anchored(value):
    return bool(getattr(getattr(value, 'anchor', None), 'value', None))


def prepare_patch(path):
    root_path = Path(path).absolute()
    if root_path.is_symlink():
        reject('configuration.yaml является символической ссылкой; требуется ручная настройка HTTP.')
    root = root_path.parent.resolve()
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.allow_duplicate_keys = False
    guards = []

    def read(file):
        if file.is_symlink() or not file.resolve().is_relative_to(root):
            reject('Файл настроек выходит за пределы каталога Home Assistant.')
        raw = file.read_bytes()
        if len(raw) > 4*1024*1024:
            reject('Слишком большой файл настроек; требуется ручная подготовка HTTP.')
        guards.append((file,digest(raw)))
        data = yaml.load(raw.decode('utf-8-sig'))
        if data is None:
            data = CommentedMap()
        if not isinstance(data,CommentedMap):
            reject('Ожидается обычный раздел YAML; требуется ручная настройка HTTP.')
        return raw,data

    try:
        target = root_path
        original,document = read(target)
        http = document.get('http')
        if isinstance(http,TaggedScalar):
            if str(http.tag) != '!include':
                reject('Раздел http использует !secret или сложное включение; настройте его вручную.')
            relative = Path(str(http.value))
            if relative.is_absolute() or '..' in relative.parts or relative.suffix not in ('.yaml','.yml'):
                reject('Допускается только локальный YAML-файл раздела http.')
            target = root/relative
            original,document = read(target)
            http = document
        else:
            if http is None:
                http = CommentedMap()
                document['http'] = http
        if not isinstance(http,CommentedMap) or anchored(http) or http.merge:
            reject('Раздел http использует якорь, слияние или нестандартную структуру; настройте вручную.')
        if http.get('ssl_certificate') or http.get('ssl_key') or http.get('server_port',8123) != 8123:
            reject('Автонастройка поддерживает локальный HTTP на порту 8123; текущие TLS/порт не изменены.')
        forwarded = http.get('use_x_forwarded_for',False)
        if not isinstance(forwarded,bool) or anchored(forwarded):
            reject('use_x_forwarded_for требует ручной настройки.')
        proxies = http.get('trusted_proxies',[])
        if not isinstance(proxies,list) or anchored(proxies):
            reject('trusted_proxies требует ручной настройки: нужен обычный список адресов.')
        for proxy in proxies:
            if not isinstance(proxy,str) or anchored(proxy):
                reject('Неоднозначный trusted_proxies; требуется ручная настройка.')
            if ipaddress.ip_network(proxy,strict=False).prefixlen == 0:
                reject('trusted_proxies доверяет всему интернету; сначала исправьте этот раздел.')
        already = forwarded and any(ipaddress.ip_network(p,strict=False) == ipaddress.ip_network('127.0.0.1/32') for p in proxies)
        if already:
            return PatchPreview(target,original,original,tuple(guards))
        http['use_x_forwarded_for'] = True
        if not any(ipaddress.ip_network(p,strict=False) == ipaddress.ip_network('127.0.0.1/32') for p in proxies):
            proxies.append('127.0.0.1/32')
        http['trusted_proxies'] = proxies
        stream = io.StringIO()
        yaml.dump(document,stream)
        rendered = stream.getvalue().encode('utf-8')
        if b'\r\n' in original:
            rendered = rendered.replace(b'\n',b'\r\n')
        if original.startswith(b'\xef\xbb\xbf'):
            rendered = b'\xef\xbb\xbf'+rendered
        return PatchPreview(target,original,rendered,tuple(guards))
    except ConfigProblem:
        raise
    except Exception:
        raise ConfigProblem('Не удалось безопасно разобрать HTTP-настройки. Исходные файлы не изменены.') from None


def check_guards(guards):
    for path, expected in guards:
        if path.is_symlink() or digest(path.read_bytes()) != expected:
            reject('Настройки изменились после проверки. Повторите подготовку.')


def apply_patch(preview):
    with WRITE_LOCK:
        check_guards(preview.guards)
        backup = preview.path.with_name(preview.path.name+'.ha-tunnel.bak')
        if preview.changed:
            atomic_write(backup,preview.original)
            atomic_write(preview.path,preview.rendered,mode=preview.path.stat().st_mode & 0o777,
                         before_replace=lambda:check_guards(preview.guards))
        return RollbackRecord(preview.path,backup,preview.original,digest(preview.rendered))


def rollback(record):
    with WRITE_LOCK:
        def guard():
            if record.path.is_symlink() or digest(record.path.read_bytes()) != record.written_hash:
                reject('После подготовки файл изменён извне. Автоматический откат остановлен; сохранена копия .ha-tunnel.bak.')
        guard()
        atomic_write(record.path,record.original,mode=record.path.stat().st_mode & 0o777,before_replace=guard)


async def configure_ha(path, supervisor, pending_path=None):
    pending = Path(pending_path) if pending_path is not None else Path(path).with_suffix('.ha-tunnel.pending')
    preview = prepare_patch(path)
    if not preview.changed and not pending.exists():
        return False
    atomic_write(pending,b'HTTP configuration awaiting application\n')
    record = apply_patch(preview) if preview.changed else None
    try:
        valid = await supervisor.check_config()
        if not valid:
            raise ConfigProblem('Home Assistant отклонил настройки. Изменения отменены.')
    except BaseException:
        if record is not None:
            rollback(record)
            pending.unlink(missing_ok=True)
        raise
    # Do not roll back an accepted change after restart request: core may already
    # have loaded it. The caller probes local HA until it is available again.
    await supervisor.restart_core()
    await supervisor.wait_proxy_ready()
    pending.unlink(missing_ok=True)
    return True
