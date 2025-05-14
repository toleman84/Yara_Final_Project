FROM python:3.11-slim

# Install system dependencies (optional), then PyYAML
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    pip install --no-cache-dir pyyaml && \
    apt-get remove -y gcc && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY sigma_scanner/sigma_log_scanner.py /app/
COPY rules/sigma /app/rules/sigma

CMD ["python", "/app/sigma_log_scanner.py"]
