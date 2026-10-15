'use strict';
function renderDependencyStatus(status){
 const labels={waiting_dependency:'Ожидание NPM или Supervisor. Повторная проверка выполняется автоматически.',proof_expired:'Подтверждение адреса NPM истекло. Публичный доступ закрыт до новой проверки.',invalid_candidate:'Сохранённый NPM не совпадает с проверенным приложением. Проверьте настройки.'};
 byId('dependency-status').textContent=(status?.local_ready?'Адрес NPM подтверждён; локальный шлюз запущен.':labels[status?.state]||'Состояние зависимости пока неизвестно.')+' '+({healthy:'Локальная проверка сервиса успешна.',unhealthy:'Локальный сервис недоступен.',unknown:'Локальная проверка сервиса ещё не подтверждена.'}[status?.local_health]||'Локальная проверка сервиса ещё не подтверждена.')+' Доступность из внешней сети не проверена.';
}
