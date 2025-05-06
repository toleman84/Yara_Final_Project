FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    aiosmtpd \
    aiosmtplib \
    python-magic \
    yara-python


RUN mkdir -p /app/rules/yara /app/rules/sigma /app/quarantine

COPY scanner.py /app/

WORKDIR /app
CMD ["python", "scanner.py"]