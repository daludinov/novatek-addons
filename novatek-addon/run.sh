#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH=/data/options.json
if [ -f "$CONFIG_PATH" ]; then
  device_host=$(jq -r '.device_host' "$CONFIG_PATH")
  device_password=$(jq -r '.device_password' "$CONFIG_PATH")
  devices=$(jq -r '.devices // empty' "$CONFIG_PATH" 2>/dev/null || echo "")
  mqtt_host=$(jq -r '.mqtt_host' "$CONFIG_PATH")
  mqtt_port=$(jq -r '.mqtt_port' "$CONFIG_PATH")
  mqtt_username=$(jq -r '.mqtt_username // empty' "$CONFIG_PATH")
  mqtt_password=$(jq -r '.mqtt_password // empty' "$CONFIG_PATH")
  base_topic=$(jq -r '.base_topic' "$CONFIG_PATH")
  discovery_prefix=$(jq -r '.discovery_prefix' "$CONFIG_PATH")
  poll_fast=$(jq -r '.poll_fast_seconds' "$CONFIG_PATH")
  poll_slow=$(jq -r '.poll_slow_seconds' "$CONFIG_PATH")

  export NOVATEK_DEVICE_HOST="$device_host"
  export NOVATEK_DEVICE_PASSWORD="$device_password"
  export NOVATEK_DEVICES="$devices"
  export NOVATEK_MQTT_HOST="$mqtt_host"
  export NOVATEK_MQTT_PORT="$mqtt_port"
  export NOVATEK_MQTT_USERNAME="$mqtt_username"
  export NOVATEK_MQTT_PASSWORD="$mqtt_password"
  export NOVATEK_BASE_TOPIC="$base_topic"
  export NOVATEK_DISCOVERY_PREFIX="$discovery_prefix"
  export NOVATEK_POLL_FAST="$poll_fast"
  export NOVATEK_POLL_SLOW="$poll_slow"
fi

exec python3 /app/novatek.py

