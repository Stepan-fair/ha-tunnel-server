"""Local notification journal. Never part of portable financial backups."""
import copy
import hashlib
import json
from pathlib import Path
import re
import secrets

from shared.files import atomic_write

MAX_BYTES = 1024 * 1024
CATEGORIES = ('funds_low', 'access_ending', 'access_stopped', 'access_recovered', 'connection')
DEFAULTS = dict(enabled=True, ha=True, mobile_targets=[], warning_days=3,
                funds_low=True, access_ending=True, access_stopped=True,
                access_recovered=True, connection=False)
SERVICE = re.compile(r'notify\.mobile_app_[a-z0-9_]{1,128}\Z', re.ASCII)


class NotificationUnavailable(RuntimeError): pass
class SettingsConflict(ValueError): pass


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value): return hashlib.sha256(encoded(value)).hexdigest()


def validate_settings(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULTS): raise ValueError('Invalid notification settings')
    if any(type(value[k]) is not bool for k in ('enabled', 'ha', *CATEGORIES)): raise ValueError('Invalid switch')
    if type(value['warning_days']) is not int or not 1 <= value['warning_days'] <= 30: raise ValueError('Invalid warning window')
    targets = value['mobile_targets']
    if (not isinstance(targets, list) or len(targets) > 8 or
            any(not isinstance(t, str) or not SERVICE.fullmatch(t) for t in targets) or len(set(targets)) != len(targets)):
        raise ValueError('Invalid mobile targets')
    return copy.deepcopy(value)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('Duplicate notification field')
        result[key] = value
    return result


class NotificationState:
    def __init__(self, path, namespace):
        if namespace not in ('server', 'client'): raise ValueError('Invalid notification role')
        self.path, self.role = Path(path), namespace
        self.diagnostic = None
        self.data = dict(schema=1, role=namespace, namespace=secrets.token_hex(16), revision=0,
                         settings=copy.deepcopy(DEFAULTS), commands={}, records={}, cursor=0, cleanup=[])
        try:
            with self.path.open('rb') as stream: raw = stream.read(MAX_BYTES + 1)
        except FileNotFoundError: return
        except OSError:
            self.diagnostic = 'storage_error'; return
        try:
            if len(raw) > MAX_BYTES: raise ValueError('Oversize journal')
            value = json.loads(raw, object_pairs_hook=unique_pairs)
            self._validate(value)
            self.data = value
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError): self.diagnostic = 'storage_error'

    def _validate(self, value):
        if not isinstance(value, dict) or set(value) != set(self.data): raise ValueError('Invalid journal')
        if type(value['schema']) is not int or value['schema'] != 1 or value['role'] != self.role: raise ValueError('Invalid journal identity')
        if not isinstance(value['namespace'], str) or not re.fullmatch('[a-f0-9]{32}', value['namespace']): raise ValueError('Invalid namespace')
        validate_settings(value['settings'])
        if type(value['revision']) is not int or value['revision'] < 0: raise ValueError('Invalid settings revision')
        if type(value['cursor']) is not int or value['cursor'] < 0: raise ValueError('Invalid cursor')
        cleanup=value['cleanup']
        if not isinstance(cleanup,list) or len(cleanup)>1024 or any(not isinstance(i,str) or not re.fullmatch('ha_tunnel_'+self.role+'_[a-f0-9]{32}_[a-f0-9]{32}',i) for i in cleanup) or len(set(cleanup))!=len(cleanup): raise ValueError('Invalid cleanup')
        if not isinstance(value['commands'], dict) or len(value['commands']) > 64: raise ValueError('Invalid commands')
        for command, item in value['commands'].items():
            if not re.fullmatch('[A-Za-z0-9_-]{1,128}', command) or not isinstance(item, dict) or set(item) != {'hash','revision'}: raise ValueError('Invalid command')
            if not isinstance(item['hash'], str) or not re.fullmatch('[a-f0-9]{64}', item['hash']) or type(item['revision']) is not int: raise ValueError('Invalid command result')
        if not isinstance(value['records'], dict) or len(value['records']) > 1024: raise ValueError('Invalid records')
        for ident, record in value['records'].items():
            if not isinstance(record, dict) or set(record) != {'binding','family','episode','desired','version','acknowledged','created_at','ha_delivered','mobile','context','retired'}: raise ValueError('Invalid record')
            if record['family'] not in ('financial','connection') or not isinstance(record['binding'], str) or len(record['binding']) > 512: raise ValueError('Invalid family')
            if ident != self.identifier(record['binding'], record['family'], namespace=value['namespace']): raise ValueError('Invalid ID')
            if not isinstance(record['episode'],str) or len(record['episode'])>128 or not re.fullmatch('[a-f0-9]{32}',record['version']): raise ValueError('Invalid episode')
            if any(type(record[k]) is not bool for k in ('acknowledged','ha_delivered','retired')): raise ValueError('Invalid marker')
            if record['created_at'] is not None and (not isinstance(record['created_at'],str) or len(record['created_at'])>128): raise ValueError('Invalid Core version')
            self._desired(record['desired'])
            if not isinstance(record['mobile'],dict) or len(record['mobile'])>8 or any(not SERVICE.fullmatch(k) or not isinstance(v,str) or len(v)>128 for k,v in record['mobile'].items()): raise ValueError('Invalid delivery marker')
            if not isinstance(record['context'],dict) or len(encoded(record['context']))>2048: raise ValueError('Invalid episode context')
            context=record['context']
            if record['binding']=='__test__':
                if (set(context)!={'targets','ha','complete'} or type(context['ha']) is not bool or
                        type(context['complete']) is not bool): raise ValueError('Invalid test context')
                validate_settings({**DEFAULTS,'mobile_targets':context['targets']})
            elif record['family']=='financial':
                if set(context)-{'source_key','stopped','stop','recovered','marker','episode'}: raise ValueError('Invalid financial context')
                if 'stopped' in context and type(context['stopped']) is not bool: raise ValueError('Invalid stopped marker')
                for key in ('source_key','stop','recovered','marker','episode'):
                    if key in context and context[key] is not None:
                        if not isinstance(context[key],str) or not re.fullmatch('[a-f0-9]{'+('64' if key=='source_key' else '32')+'}',context[key]): raise ValueError('Invalid financial marker')
            else:
                if set(context)-{'phase','episode','sent'}: raise ValueError('Invalid connection context')
                if 'phase' in context and context['phase'] not in ('lost','recovered','clear'): raise ValueError('Invalid connection phase')
                if 'sent' in context and type(context['sent']) is not bool: raise ValueError('Invalid sent marker')
                if 'episode' in context and (not isinstance(context['episode'],str) or not re.fullmatch('[a-f0-9]{32}',context['episode'])): raise ValueError('Invalid connection marker')

    @staticmethod
    def _desired(desired):
        if desired is None: return
        if not isinstance(desired, dict) or set(desired) != {'title','message','kind','mobile_key'}: raise ValueError('Invalid card')
        for name, limit in (('title',128),('message',2048),('kind',64),('mobile_key',128)):
            if not isinstance(desired[name],str) or len(desired[name])>limit: raise ValueError('Invalid card text')

    @property
    def records(self): return self.data['records']

    def identifier(self, binding, family, *, namespace=None):
        return 'ha_tunnel_' + self.role + '_' + (namespace or self.data['namespace']) + '_' + digest([binding,family])[:32]

    def _commit(self, data):
        if self.diagnostic == 'storage_error': raise NotificationUnavailable('Notification journal unavailable')
        raw = encoded(data)
        # Admit desired work only with room for its later durable delivery ACKs.
        # A full journal must not allow a send whose completion cannot be saved.
        reserve=0
        for record in data['records'].values():
            if record['desired'] is None or record['acknowledged']: continue
            projected={**record['mobile'],**{t:record['desired']['mobile_key'] for t in data['settings']['mobile_targets']}}
            reserve+=max(0,len(encoded(projected))-len(encoded(record['mobile'])))
            if record['created_at'] is None: reserve+=512
        if len(raw)+reserve > MAX_BYTES or len(data['records']) > 1024:
            self.diagnostic = 'capacity'; raise NotificationUnavailable('Notification capacity reached')
        try: atomic_write(self.path, raw)
        except OSError as exc:
            self.diagnostic = 'write_error'; raise NotificationUnavailable('Notification write failed') from exc
        self.data = data
        self.diagnostic = None

    def view(self):
        return dict(settings=copy.deepcopy(self.data['settings']), revision=self.data['revision'], diagnostic=self.diagnostic)

    def configure(self, settings, expected_revision, command_id):
        settings = validate_settings(settings)
        if not isinstance(command_id,str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}',command_id): raise ValueError('Invalid command')
        if type(expected_revision) is not int or expected_revision<0: raise ValueError('Invalid revision')
        request_hash = digest([settings,expected_revision])
        previous = self.data['commands'].get(command_id)
        if previous:
            if previous['hash'] != request_hash: raise SettingsConflict('Command changed')
            return self.view()  # Never reapply an earlier command over newer settings.
        if self.data['revision'] != expected_revision: raise SettingsConflict('Settings changed')
        data = copy.deepcopy(self.data)
        data['settings'] = settings
        if not settings['enabled']: self._cancel_test(data)
        data['revision'] += 1
        data['commands'][command_id] = dict(hash=request_hash,revision=data['revision'])
        while len(data['commands'])>64: del data['commands'][next(iter(data['commands']))]
        for record in data['records'].values():
            record['mobile'] = {k:v for k,v in record['mobile'].items() if k in settings['mobile_targets']}
            if settings['ha'] and not self.data['settings']['ha'] and record['desired'] is not None:
                record['ha_delivered']=False
        self._commit(data)
        return self.view()

    def _cancel_test(self, data):
        record=data['records'].get(self.identifier('__test__','connection'))
        if record is None or record['desired'] is None: return False
        record.update(desired=None,episode='cancelled',version=secrets.token_hex(16),
            acknowledged=False,created_at=None,ha_delivered=False,mobile={},
            context=dict(targets=[],ha=False,complete=True))
        return True

    def cancel_test(self):
        data=copy.deepcopy(self.data)
        if self._cancel_test(data): self._commit(data)

    def observe(self, binding_key, family, episode, desired, *, context=None, retired=False):
        if not isinstance(binding_key,str) or len(binding_key)>512 or family not in ('financial','connection'): raise ValueError('Invalid notification binding')
        if not isinstance(episode,str) or len(episode)>128: raise ValueError('Invalid episode')
        self._desired(desired)
        ident = self.identifier(binding_key,family)
        old_record = self.records.get(ident)
        record = copy.deepcopy(old_record)
        if record is None:
            record = dict(binding=binding_key,family=family,episode='',desired=None,version=secrets.token_hex(16),
                          acknowledged=False,created_at=None,ha_delivered=False,mobile={},context={},retired=False)
        if record['episode'] != episode or record['desired'] != desired:
            # Text changes do not un-acknowledge the same episode. Severity/coverage transitions do.
            if record['episode'] != episode: record['acknowledged'] = False
            record.update(episode=episode,desired=copy.deepcopy(desired),version=secrets.token_hex(16),ha_delivered=False,created_at=None)
        if context is not None: record['context'] = copy.deepcopy(context)
        record['retired'] = retired
        if record != old_record:
            data = copy.deepcopy(self.data)
            data['records'][ident] = record
            self._commit(data)
        elif self.diagnostic == 'storage_error': raise NotificationUnavailable('Notification journal unavailable')
        return ident

    def request_test(self, expected_revision, command_id):
        if not isinstance(command_id,str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}',command_id): raise ValueError('Invalid command')
        if type(expected_revision) is not int: raise ValueError('Invalid revision')
        request_hash=digest(['test',expected_revision])
        previous=self.data['commands'].get(command_id)
        if previous:
            if previous['hash']!=request_hash: raise SettingsConflict('Command changed')
            return
        if expected_revision!=self.data['revision']: raise SettingsConflict('Settings changed')
        settings=self.data['settings']
        if not settings['enabled'] or not (settings['ha'] or settings['mobile_targets']): raise ValueError('Enable a notification channel')
        data=copy.deepcopy(self.data); version=secrets.token_hex(16)
        ident=self.identifier('__test__','connection')
        data['records'][ident]=dict(binding='__test__',family='connection',episode=version,version=version,
            desired=dict(title='HA Tunnel · Проверка',message='Проверка локальных уведомлений HA Tunnel.',kind='test',mobile_key=version),
            acknowledged=False,created_at=None,ha_delivered=False,mobile={},
            context=dict(targets=list(settings['mobile_targets']),ha=settings['ha'],complete=False),retired=False)
        data['commands'][command_id]=dict(hash=request_hash,revision=expected_revision)
        while len(data['commands'])>64: del data['commands'][next(iter(data['commands']))]
        self._commit(data)

    def reset_namespace(self):
        """Portable restore rotates local delivery only, never financial instance_id."""
        data=copy.deepcopy(self.data)
        data.update(namespace=secrets.token_hex(16),revision=data['revision']+1,settings=copy.deepcopy(DEFAULTS),
                    commands={},records={},cursor=0,
                    cleanup=list(dict.fromkeys([*data['cleanup'],*data['records']])))
        if len(data['cleanup'])>1024: raise NotificationUnavailable('Notification cleanup capacity')
        self._commit(data)

    def cleaned(self, ident):
        if ident not in self.data['cleanup']: return
        data=copy.deepcopy(self.data); data['cleanup'].remove(ident); self._commit(data)

    def checkpoint_cursor(self, cursor):
        if self.data['cursor']==cursor: return
        data=copy.deepcopy(self.data); data['cursor']=cursor; self._commit(data)

    def update(self, ident, version, **changes):
        record = self.records.get(ident)
        if record is None or record['version'] != version: return False
        data=copy.deepcopy(self.data); data['records'][ident].update(changes)
        if data!=self.data: self._commit(data)
        return True

    def bind_card(self, ident, version, created_at):
        return self.update(ident,version,created_at=created_at,ha_delivered=True)

    def acknowledge(self, notification_id, *, version=None, created_at=None):
        record = self.records.get(notification_id)
        if (record is None or record['desired'] is None or version != record['version'] or
                created_at is None or record['created_at'] != created_at): return False
        return self.update(notification_id,version,acknowledged=True)

    def forget_retired(self):
        data=copy.deepcopy(self.data)
        data['records']={k:v for k,v in data['records'].items() if not (v['retired'] and v['ha_delivered'])}
        if data!=self.data: self._commit(data)
