# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Postfix and necessary utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends postfix rsyslog mailutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy and process transport map
COPY transport /etc/postfix/transport
RUN postmap /etc/postfix/transport && \
    chown root:postfix /etc/postfix/transport.db && \
    chmod 640 /etc/postfix/transport.db

# Create system users (if needed for mail routing)
RUN adduser --system --no-create-home recipient && \
    adduser --system --no-create-home sender

# Expose SMTP ports
EXPOSE 25 10026

# Use custom entrypoint
ENTRYPOINT ["/entrypoint.sh"]
