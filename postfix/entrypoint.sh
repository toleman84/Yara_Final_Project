#!/bin/bash
set -e

# Start rsyslog without imklog and without PID file
rsyslogd -n -iNONE &

# Give rsyslog a moment to spin up
sleep 1

# Start Postfix in the foreground
exec postfix start-fg
