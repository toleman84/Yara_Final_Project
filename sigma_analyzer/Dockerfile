# Use your preferred Python base
FROM python:3.11-slim

WORKDIR /app

# 1) Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 2) Copy your analyzer code and compiled rules
COPY analyzer.py ./
COPY compiled/ ./compiled/

# 3) Ensure log directory exists
RUN mkdir -p /var/log/sigma

# 4) Run the analyzer
CMD ["python", "analyzer.py"]
