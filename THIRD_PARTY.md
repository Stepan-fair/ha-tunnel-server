# Компоненты

FRP 0.71.0 — Apache-2.0, https://github.com/fatedier/frp; лицензия из проверенного архива устанавливается в `/usr/share/doc/frp/LICENSE`.

Python — PSF; nginx — BSD-2-Clause. Официальные пакеты образа сохраняют лицензионные файлы поставщиков.

paho-mqtt 2.1.0 — Eclipse Public License2.0 / Eclipse Distribution License1.0. tzdata2026.5 — Apache-2.0, данные IANA общественное достояние. Mosquitto в изолированном тестовом образе — EPL2.0 / EDL1.0; в приложения он не включается.

Python-пакеты и их версии перечислены в `requirements.lock`; лицензии входят в metadata установленных distributions. Основные: aiohttp — Apache-2.0, cryptography — Apache-2.0 или BSD-3-Clause, PyJWT — MIT, ruamel.yaml — MIT. Точные SPDX/лицензии транзитивных зависимостей следует включить в SBOM при выпуске собранных образов; полноценный SBOM ещё не сформирован.
