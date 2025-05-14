FROM python:3.11-slim

# Install system dependencies and the OS YAML binding
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-yaml && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY sigma_scanner/sigma_log_scanner.py /app/
COPY rules/sigma /app/rules/sigma

CMD ["python", "/app/sigma_log_scanner.py"]
