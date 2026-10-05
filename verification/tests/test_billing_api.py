from pathlib import Path
def test_subscription_admin_controls_are_safe_and_monthly():
    js=Path('server/app/templates/app.js').read_text(encoding='utf-8')
    for text in ('Стоимость в месяц','Пополнить','Установить баланс','set_price','set_balance','topup','/billing'):
        assert text in js
    assert 'innerHTML' not in js
    assert "c.paused?'Пуск':'Пауза'" in js
    assert "c.billing?.mode!=='legacy'" in js
