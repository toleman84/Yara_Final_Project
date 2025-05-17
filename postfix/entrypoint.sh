#!/bin/bash
set -e

# Start rsyslog (ignore kernel log errors)
echo "[*] Starting rsyslogd..."
rsyslogd 2>/dev/null  # Silence imklog warnings

# Start Postfix in the background
echo "[*] Starting postfix..."
postfix start


# Keep the container alive
tail -f /dev/null