# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Argentina/Buenos_Aires

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        postfix \
        rsyslog \
        procmail \
        tzdata \
        mailutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    \
    # ─── setup rsyslog for Postfix logging ───────────────────────────────────
    mkdir -p /etc/rsyslog.d /var/log/postfix && \
    printf 'mail.*\t-/var/log/postfix/mail.log\n' > /etc/rsyslog.d/30-postfix.conf && \
    touch    /var/log/postfix/mail.log && \
    chown syslog:adm        /var/log/postfix/mail.log && \
    chmod 640               /var/log/postfix/mail.log

# Copy your entrypoint and Postfix config files
COPY entrypoint.sh              /entrypoint.sh
COPY main.cf                    /etc/postfix/main.cf
COPY transport                  /etc/postfix/transport
COPY header_checks              /etc/postfix/header_checks

# Fix permissions and regenerate transport map
RUN chmod +x /entrypoint.sh && \
    chmod 644 /etc/postfix/main.cf /etc/postfix/header_checks && \
    postmap /etc/postfix/transport && \
    chown root:postfix /etc/postfix/transport.db && \
    chmod 640        /etc/postfix/transport.db

# Create Postfix maildrop queue directory
RUN mkdir -p /var/spool/postfix/maildrop && \
    chown postfix:postdrop /var/spool/postfix/maildrop && \
    chmod 730           /var/spool/postfix/maildrop

# system users for sender/recipient
RUN adduser --system --no-create-home recipient && \
    adduser --system --no-create-home sender

# Expose SMTP ports
EXPOSE 25 10026

# Launch rsyslog and then Postfix
ENTRYPOINT ["/entrypoint.sh"]
