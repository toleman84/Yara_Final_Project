#!/bin/bash
set -e

# Preserve original Postfix files from package install
ORIGINAL_DIR="/etc/postfix/original"
mkdir -p ${ORIGINAL_DIR}
if [ -z "$(ls -A ${ORIGINAL_DIR})" ]; then
    echo "Backing up original Postfix files"
    cp -a /usr/share/postfix/* ${ORIGINAL_DIR}/
fi

# Restore essential files if missing
[ -f /etc/postfix/postfix-files ] || cp ${ORIGINAL_DIR}/postfix-files /etc/postfix/
[ -f /etc/postfix/postfix-script ] || cp ${ORIGINAL_DIR}/postfix-script /etc/postfix/

# Start services
echo "Starting rsyslogd"
rsyslogd

echo "Starting postfix"
postfix start

# Keep container running
echo "Tailing mail logs"
tail -F /var/log/mail.log