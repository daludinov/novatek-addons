import os
import time
import json
import binascii
import hashlib
import threading
from typing import Dict, Any
import re

import requests
from paho.mqtt import client as mqtt


def hex_to_ascii(value: str) -> str:
    try:
        return binascii.unhexlify(value).decode("ascii")
    except Exception:
        return value


class NovatekClient:
    def __init__(self, host: str, password: str):
        self.base = f"http://{host}"
        self.password = password
        self.sid = None  # type: str | None
        self.session = requests.Session()

    def _get(self, path: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
        url = self.base + path
        r = self.session.get(url, params=params, timeout=10)
        r.raise_for_status()
        return r.json()

    def login(self) -> str:
        di = self._get("/api/login?device_info")
        user_info_hex = di.get("user_info", "")
        user_info = hex_to_ascii(user_info_hex)
        device_info = user_info[:6]
        salt = self._get("/api/login?salt").get("SALT", "")
        payload = f"{device_info}{self.password}{salt}".encode("utf-8")
        hash_hex = hashlib.sha1(payload).hexdigest()
        data = self._get("/api/login?login=" + hash_hex)
        sid = data.get("SID")
        if not sid:
            raise RuntimeError(f"Login failed: {data}")
        self.sid = sid
        return sid

    def with_sid(self, api_path: str) -> str:
        assert self.sid, "Not logged in"
        return f"/{self.sid}{api_path}"

    def get_value(self, key: str) -> Dict[str, Any]:
        """Получить значение ключа, с автообновлением SID при ошибках.
        Ретрай 1 раз после повторного логина при 401/403 или STATUS=ERROR_LOGIN.
        """
        last_err: Exception | None = None
        for attempt in range(2):
            try:
                resp = self._get(self.with_sid(f"/api/all/get?{key}"))
            except requests.HTTPError as e:  # type: ignore
                last_err = e
                code = getattr(e.response, "status_code", None)
                if attempt == 0 and code in (401, 403):
                    self.login()
                    continue
                raise
            except Exception as e:
                last_err = e
                if attempt == 0:
                    try:
                        self.login()
                        continue
                    except Exception:
                        pass
                raise

            status = resp.get("STATUS")
            if attempt == 0 and status == "ERROR_LOGIN":
                self.login()
                continue
            return resp
        if last_err:
            raise last_err
        return {"STATUS": "ERROR"}


class MqttPublisher:
    def __init__(self, host: str, port: int, username: str | None, password: str | None):
        self.enabled = True
        self.client = mqtt.Client()
        if username:
            self.client.username_pw_set(username, password or None)
        try:
            # Set Last Will on bridge status topic
            self.client.will_set("novatek/bridge/status", payload="offline", retain=False, qos=0)
            self.client.connect(host, port, keepalive=60)
            self.client.loop_start()
            print(f"[MQTT] Connected to {host}:{port}", flush=True)
        except Exception:
            self.enabled = False
            print(f"[MQTT] Disabled (connection failed to {host}:{port})", flush=True)

    def publish(self, topic: str, payload: Any, retain: bool = False):
        if not self.enabled:
            return
        if isinstance(payload, (int, float)):
            self.client.publish(topic, str(payload), retain=retain)
        elif isinstance(payload, str):
            self.client.publish(topic, payload, retain=retain)
        else:
            self.client.publish(topic, json.dumps(payload, ensure_ascii=False), retain=retain)


SENSORS = [
    {"key": "volt_msr", "name": "Voltage", "device_class": "voltage", "unit": "V", "scale": 0.1, "state_class": "measurement"},
    {"key": "freq_msr", "name": "Frequency", "device_class": "frequency", "unit": "Hz", "scale": 0.01, "state_class": "measurement"},
    {"key": "tempr_msr", "name": "Temperature", "device_class": "temperature", "unit": "°C", "scale": 0.1, "state_class": "measurement"},
    {"key": "cur_msr", "name": "Current", "device_class": "current", "unit": "A", "scale": 0.1, "state_class": "measurement"},
    {"key": "powa_msr", "name": "Power Active", "device_class": "power", "unit": "W", "scale": 1.0, "state_class": "measurement"},
    {"key": "pows_msr", "name": "Power Sum", "device_class": "power", "unit": "W", "scale": 1.0, "state_class": "measurement"},
    {"key": "enrga_msr", "name": "Energy Total", "device_class": "energy", "unit": "kWh", "scale": 0.001, "state_class": "total_increasing"},
    {"key": "enrga_d_msr", "name": "Energy Day", "device_class": "energy", "unit": "kWh", "scale": 0.001, "state_class": "total"},
    {"key": "enrga_w_msr", "name": "Energy Week", "device_class": "energy", "unit": "kWh", "scale": 0.001, "state_class": "total"},
    {"key": "enrga_m_msr", "name": "Energy Month", "device_class": "energy", "unit": "kWh", "scale": 0.001, "state_class": "total"},
]

BINARY_SENSORS = [
    {"key": "pow_enable", "name": "Protection Power Enabled"},
    {"key": "freq_enable", "name": "Protection Frequency Enabled"},
    {"key": "dst_enable", "name": "DST Enabled"},
    {"key": "cloud_enable", "name": "Cloud Enabled"},
    {"key": "hctrl_enable", "name": "HCtrl Enabled"},
    {"key": "wifi_dhcp_enable", "name": "WiFi DHCP Enabled"},
    {"key": "sync_sntp_enable", "name": "SNTP Enabled"},
]


def main():
    default_host = os.getenv("NOVATEK_DEVICE_HOST", "172.24.15.248")
    device_password = os.getenv("NOVATEK_DEVICE_PASSWORD", "4129177")
    devices_env = (os.getenv("NOVATEK_DEVICES", "") or "").strip()
    devices = [h.strip() for h in devices_env.split(",") if h.strip()]
    if not devices:
        devices = [default_host]

    mqtt_host = os.getenv("NOVATEK_MQTT_HOST", "core-mosquitto")
    mqtt_port = int(os.getenv("NOVATEK_MQTT_PORT", "1883"))
    mqtt_username = os.getenv("NOVATEK_MQTT_USERNAME") or None
    mqtt_password = os.getenv("NOVATEK_MQTT_PASSWORD") or None
    base_topic = os.getenv("NOVATEK_BASE_TOPIC", "novatek")
    discovery_prefix = os.getenv("NOVATEK_DISCOVERY_PREFIX", "homeassistant")
    poll_fast = int(os.getenv("NOVATEK_POLL_FAST", "10"))
    poll_slow = int(os.getenv("NOVATEK_POLL_SLOW", "60"))

    print(f"[INIT] Devices={devices} MQTT={mqtt_host}:{mqtt_port}", flush=True)
    mqtt_pub = MqttPublisher(mqtt_host, mqtt_port, mqtt_username, mqtt_password)

    clients: Dict[str, NovatekClient] = {}
    last_slow: Dict[str, float] = {}

    def ensure_login(host: str) -> str:
        cli = clients[host]
        for _ in range(3):
            try:
                sid = cli.login()
                print(f"[LOGIN] {host} SID={sid}", flush=True)
                return sid
            except Exception as e:
                print(f"[LOGIN] {host} failed: {e}", flush=True)
                time.sleep(1)
        raise RuntimeError(f"Failed to login {host} after retries")

    def publish_discovery_for_host(host: str):
        # Санитизируем host для discovery topic (точки и прочие символы недопустимы)
        safe_host = re.sub(r"[^a-z0-9_-]", "_", host.lower().replace(".", "_"))
        node_id = f"novatek_{safe_host}"
        device_info = {
            "identifiers": [f"novatek_{safe_host}"],
            "manufacturer": "Novatek",
            "model": "EM-129",
            "name": f"Novatek {host}",
        }
        for s in SENSORS:
            unique_id = f"novatek_{safe_host}_{s['key']}"
            state_topic = f"{base_topic}/{host}/state/{s['key']}"
            avail_topic = f"{base_topic}/{host}/status"
            config = {
                "name": f"Novatek {host} {s['name']}",
                "state_topic": state_topic,
                "unique_id": unique_id,
                "device": device_info,
                "unit_of_measurement": s["unit"],
                "device_class": s["device_class"],
                "state_class": s["state_class"],
                "value_template": "{{ value|float }}",
                "availability_topic": avail_topic,
                "payload_available": "online",
                "payload_not_available": "offline",
            }
            object_id = s["key"]
            topic = f"{discovery_prefix}/sensor/{node_id}/{object_id}/config"
            mqtt_pub.publish(topic, config, retain=True)

        for b in BINARY_SENSORS:
            unique_id = f"novatek_{safe_host}_{b['key']}"
            state_topic = f"{base_topic}/{host}/state/{b['key']}"
            avail_topic = f"{base_topic}/{host}/status"
            config = {
                "name": f"Novatek {host} {b['name']}",
                "state_topic": state_topic,
                "unique_id": unique_id,
                "device": device_info,
                "device_class": "power" if "pow" in b["key"] else None,
                "payload_on": "1",
                "payload_off": "0",
                "availability_topic": avail_topic,
                "payload_available": "online",
                "payload_not_available": "offline",
            }
            config = {k: v for k, v in config.items() if v is not None}
            object_id = b["key"]
            topic = f"{discovery_prefix}/binary_sensor/{node_id}/{object_id}/config"
            mqtt_pub.publish(topic, config, retain=True)

        attr_topic = f"{base_topic}/{host}/state/attributes"
        mqtt_pub.publish(f"{discovery_prefix}/sensor/{node_id}/info/config", {
            "name": f"Novatek {host} Info",
            "state_topic": f"{base_topic}/{host}/state/info",
            "json_attributes_topic": attr_topic,
            "unique_id": f"novatek_{safe_host}_info",
            "device": device_info,
            "availability_topic": f"{base_topic}/{host}/status",
            "payload_available": "online",
            "payload_not_available": "offline",
            "value_template": "{{ value }}",
        }, retain=True)
        # Publish initial availability (retained) and info (retained)
        mqtt_pub.publish(f"{base_topic}/{host}/status", "online", retain=True)
        mqtt_pub.publish(f"{base_topic}/{host}/state/info", "online", retain=True)

    for host in devices:
        clients[host] = NovatekClient(host, device_password)
        last_slow[host] = 0.0
        ensure_login(host)
        publish_discovery_for_host(host)
        # Initial diagnostic publish so entities don't stay unknown
        try:
            diag_keys = [
                "enrga_msr", "enrga_d_msr", "enrga_w_msr", "enrga_m_msr",
                "wifi_ip", "wifi_gw", "wifi_mask", "wifi_ssid",
                "device_ip", "device_mac",
                "time", "time_gmt", "sync_sntp_time",
                "pow_enable", "freq_enable", "dst_enable", "cloud_enable", "hctrl_enable", "wifi_dhcp_enable", "sync_sntp_enable",
            ]
            attrs: Dict[str, Any] = {}
            cli = clients[host]
            for key in diag_keys:
                try:
                    data = cli.get_value(key)
                except Exception:
                    continue
                if data.get("STATUS") != "OK":
                    continue
                k = [x for x in data.keys() if x != "STATUS"][0]
                v = data[k]
                if key == "wifi_ssid" and isinstance(v, str):
                    v = hex_to_ascii(v)
                if key.startswith("enrga_") and isinstance(v, (int, float)):
                    v = v * 0.001
                    # publish energy states immediately (retained)
                    mqtt_pub.publish(f"{base_topic}/{host}/state/{key}", v, retain=True)
                attrs[key] = v
                if key.endswith("_enable"):
                    mqtt_pub.publish(f"{base_topic}/{host}/state/{key}", "1" if v else "0")
            mqtt_pub.publish(f"{base_topic}/{host}/state/attributes", attrs)
        except Exception:
            pass

    while True:
        now = time.time()
        for host in devices:
            cli = clients[host]
            try:
                fast_keys = [s["key"] for s in SENSORS if s["state_class"] == "measurement"]
                pub_count = 0
                for key in fast_keys:
                    data = cli.get_value(key)
                    if data.get("STATUS") != "OK":
                        if data.get("STATUS") not in ("OK", None):
                            print(f"[GET] {host} {key} -> {data.get('STATUS')}", flush=True)
                        continue
                    raw_val = [v for k, v in data.items() if k != "STATUS"][0]
                    sensor_def = next(s for s in SENSORS if s["key"] == key)
                    value = (raw_val or 0) * sensor_def["scale"]
                    mqtt_pub.publish(f"{base_topic}/{host}/state/{key}", value)
                    pub_count += 1

                if now - last_slow[host] >= poll_slow:
                    last_slow[host] = now
                    diag_keys = [
                        "enrga_msr", "enrga_d_msr", "enrga_w_msr", "enrga_m_msr",
                        "wifi_ip", "wifi_gw", "wifi_mask", "wifi_ssid",
                        "device_ip", "device_mac",
                        "time", "time_gmt", "sync_sntp_time",
                        "pow_enable", "freq_enable", "dst_enable", "cloud_enable", "hctrl_enable", "wifi_dhcp_enable", "sync_sntp_enable",
                    ]
                    attrs: Dict[str, Any] = {}
                    for key in diag_keys:
                        try:
                            data = cli.get_value(key)
                        except Exception as e:
                            print(f"[GET] {host} {key} exception: {e}", flush=True)
                            continue
                        if data.get("STATUS") != "OK":
                            print(f"[GET] {host} {key} -> {data.get('STATUS')}", flush=True)
                            continue
                        k = [x for x in data.keys() if x != "STATUS"][0]
                        v = data[k]
                        if key == "wifi_ssid" and isinstance(v, str):
                            v = hex_to_ascii(v)
                        if key.startswith("enrga_") and isinstance(v, (int, float)):
                            v = v * 0.001
                            # publish energy states to their topics
                            mqtt_pub.publish(f"{base_topic}/{host}/state/{key}", v)
                        attrs[key] = v
                        if key.endswith("_enable"):
                            mqtt_pub.publish(f"{base_topic}/{host}/state/{key}", "1" if v else "0")
                    mqtt_pub.publish(f"{base_topic}/{host}/state/attributes", attrs)
                    print(f"[PUBLISH] {host} fast={pub_count} attrs={len(attrs)}", flush=True)

            except Exception as e:
                print(f"[ERROR] {host} loop error: {e}", flush=True)
                try:
                    ensure_login(host)
                except Exception:
                    pass

        time.sleep(poll_fast)


if __name__ == "__main__":
    main()


