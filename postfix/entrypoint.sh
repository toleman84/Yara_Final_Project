#!/bin/bash
set -e

# Start rsyslog (ignore kernel log errors)
echo "[*] Starting rsyslogd..."
rsyslogd 

# Make sure the transport map is up to date (optional safety)
postmap /etc/postfix/transport

# Start Postfix in the foreground (best practice for Docker)
echo "[*] Starting Postfix in foreground..."
exec postfix start-fg