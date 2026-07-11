#!/bin/bash
set -e

echo "[entrypoint] Creating keys directory..."
mkdir -p /etc/keys


echo "[entrypoint] Launching SOC Receiver C Daemon in background..."
./soc_receiver > /var/log/soc_receiver.log 2>&1 &

echo "[entrypoint] Launching Java Spring Boot SOC Console in foreground..."
exec java -jar dashboard.jar
