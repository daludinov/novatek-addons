ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base:3.19
FROM ${BUILD_FROM}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apk add --no-cache python3 py3-paho-mqtt py3-requests curl jq

WORKDIR /app

COPY run.sh /app/run.sh
COPY novatek.py /app/novatek.py

RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]

