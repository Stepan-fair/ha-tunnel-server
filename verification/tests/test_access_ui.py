from pathlib import Path


def test_server_controls_labels_and_safe_rendering():
    js=Path('server/app/templates/app.js').read_text(encoding='utf-8')
    html=Path('server/app/templates/index.html').read_text(encoding='utf-8')
    for label in ('Пуск','Пауза','Показать код','Выдать новый код','Сохранить и запустить','Бессрочно'):
        assert label in js+html
    assert 'innerHTML' not in js
    for unit in ('years','months','weeks','days','hours','minutes'): assert unit in js
    assert 'revision' in js and 'commandId()' in js
    assert '18080' not in html and 'Dunaiskiy' not in html


def test_client_telemetry_and_stale_panel():
    js=Path('client/app/templates/app.js').read_text(encoding='utf-8')
    assert 'presentation' in js and 'receive_rate' in js and 'total' in js
    assert 'innerHTML' not in js and 'Показания недоступны' in js
