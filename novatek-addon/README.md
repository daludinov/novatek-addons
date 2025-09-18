# Novatek Monitor (Home Assistant Add-on)

Аддон опрашивает устройство Novatek (EM-125/126/129) и публикует значения в MQTT c автодискавери Home Assistant.

## Установка
1. Добавьте локальный репозиторий с аддоном в Supervisor.
2. Установите "Novatek Monitor".
3. В настройках укажите IP `device_host` и пароль устройства `device_password`.
4. Убедитесь, что MQTT брокер доступен (обычно `core-mosquitto`).

## Опции
- device_host: IP устройства (например `172.24.15.248`).
- device_password: пароль устройства (строка, по документации).
- mqtt_host, mqtt_port, mqtt_username, mqtt_password: параметры подключения к MQTT.
- base_topic: базовый топик (по умолчанию `novatek`).
- discovery_prefix: префикс автодискавери (по умолчанию `homeassistant`).
- poll_fast_seconds: период опроса быстрых метрик (напряжение/частота/мощности/температура).
- poll_slow_seconds: период опроса диагностик и энергий.

## Публикуемые сущности
- Сенсоры (measurement): `volt_msr` (В), `freq_msr` (Гц), `tempr_msr` (°C), `powa_msr` (W), `pows_msr` (W).
- Энергия (total/total_increasing): `enrga_msr`, `enrga_d_msr`, `enrga_w_msr`, `enrga_m_msr` (кВт⋅ч).
- Бинарные: `*_enable` (pow, freq, dst, cloud, hctrl, wifi_dhcp, sync_sntp).
- Атрибуты устройства: `wifi_ssid` (HEX→ASCII), `wifi_ip/gw/mask`, `device_ip`, `device_mac`, `time`, `time_gmt`.

## Примечания
- Сессии: перед опросом аддон получает `SID` и использует префикс `/{SID}` в путях.
- Единицы и масштаб: `volt` делится на 10, `freq` на 100, `temp` на 10, `energy` на 1000.
- Конфиденциальные поля (`dev_passw`, `wifi_passw`) не публикуются.
