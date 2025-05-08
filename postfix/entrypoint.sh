#!/bin/bash
set -e

# Start rsyslog daemon
echo "[*] Starting rsyslogd..."
rsyslogd

# Start Postfix in foreground mode (container-friendly)
echo "[*] Starting postfix in foreground mode...[*]"
exec postfix start-fg
echo "[*] postfix started...[*]"

mkdir -p /var/log/scanner
# This ensures all stdout/stderr (including the “Quarantined…” warnings) go into /var/log/scanner/scanner.log.
exec python3 /app/scanner 2>&1 | tee -a /var/log/scanner/scanner.log