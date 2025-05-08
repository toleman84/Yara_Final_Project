#!/bin/bash
set -e

# Start rsyslog daemon
echo "Starting rsyslog..."
rsyslogd

# Start Postfix in foreground mode (container-friendly)
echo "Starting postfix..."
exec postfix start-fg
echo "[*] Postfix service started [*]"
