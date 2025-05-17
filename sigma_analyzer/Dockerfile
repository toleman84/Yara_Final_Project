FROM python:3.11-slim
WORKDIR /app

# Copy dependencies first to leverage Docker cache
COPY sigma_analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY sigma_analyzer/analyzer.py .
COPY sigma_analyzer/loki-backend.yaml .
COPY sigma_analyzer/rules ./rules
COPY sigma_analyzer/compiled ./compiled

COPY sigma_analyzer/entrypoint.sh .

# executable
RUN chmod +x entrypoint.sh

# loop script as the entrypoint
ENTRYPOINT ["./entrypoint.sh"]
