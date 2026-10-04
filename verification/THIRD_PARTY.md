# Компоненты

FRP 0.71.0 — Apache-2.0, https://github.com/fatedier/frp; закреплённый source commit 4a23aa181c1d7e28eecaa8216024ed753b9d27c8 проверяется SHA256 и собирается Go1.26.8 с исправлениями Azure/go-ntlmssp0.1.1 и x/crypto0.56.0. Лицензия, go.mod/go.sum и build-info находятся в `/usr/share/doc/frp/`. Официальные release binaries Go1.25.12 больше не используются в образах.

Сохраняются лицензии Go и фактически подключённых модулей, их список — `module-notices.txt`. Сборка использует upstream тег `noweb`: встроенные страницы FRP не поставляются, административный REST API и собственная панель HA Tunnel сохраняются. Символы бинарных файлов сохраняются для точного govulncheck; его отчёты включены в образ, найденные уязвимости блокируют сборку.

Python — PSF; nginx — BSD-2-Clause. Официальные пакеты образа сохраняют лицензионные файлы поставщиков.

paho-mqtt 2.1.0 — Eclipse Public License2.0 / Eclipse Distribution License1.0. tzdata2026.5 — Apache-2.0, данные IANA общественное достояние. Mosquitto в изолированном тестовом образе — EPL2.0 / EDL1.0; в приложения он не включается.

Python-пакеты и их версии перечислены в `requirements.lock`; лицензии входят в metadata установленных distributions. Основные: aiohttp — Apache-2.0, cryptography — Apache-2.0 или BSD-3-Clause, PyJWT — MIT, ruamel.yaml — MIT. Точные SPDX/лицензии транзитивных зависимостей следует включить в SBOM при выпуске собранных образов; полноценный SBOM ещё не сформирован.
