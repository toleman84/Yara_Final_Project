#!/bin/bash
set -e

# Start rsyslog daemon
rsyslogd

# Start Postfix in foreground mode (container-friendly)
exec postfix start-fg
