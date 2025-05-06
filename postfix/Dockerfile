# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Postfix and necessary utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends postfix rsyslog && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose SMTP port
EXPOSE 25 10026

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]

