# Use Python slim
FROM python:3.10-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directories first (better layer caching)
RUN mkdir -p /app/rules/yara /app/rules/sigma /app/quarantine

# Work directory
WORKDIR /app

# Install Python dependencies
COPY scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY scanner/scanner.py /app/scanner.py 
COPY rules/yara/ /app/rules/yara/
COPY rules/sigma/ /app/rules/sigma/

# Run the scanner
CMD ["python", "scanner.py"]