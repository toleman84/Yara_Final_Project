# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Postfix, Python, and utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    postfix \
    rsyslog \
    procmail \
    mailutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy config files
COPY entrypoint.sh /entrypoint.sh
COPY transport /etc/postfix/transport
COPY header_checks /etc/postfix/header_checks

# Set permissions for Postfix files
RUN chmod +x /entrypoint.sh  && \
    chmod 644 /etc/postfix/main.cf /etc/postfix/header_checks && \
    postmap /etc/postfix/transport && \
    chown root:postfix /etc/postfix/transport.db && \
    chmod 640 /etc/postfix/transport.db

# Create Postfix queue directories with correct permissions
RUN mkdir -p /var/spool/postfix/maildrop && \
    chown postfix:postdrop /var/spool/postfix/maildrop && \
    chmod 730 /var/spool/postfix/maildrop

# Create system users
RUN adduser --system --no-create-home recipient && \
    adduser --system --no-create-home sender

# Expose SMTP ports
EXPOSE 25 10026

# Use custom entrypoint
ENTRYPOINT ["/entrypoint.sh"]