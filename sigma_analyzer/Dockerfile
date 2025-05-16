FROM python:3.11-slim
WORKDIR /app

# Copy only what’s needed
COPY sigma_analyzer/requirements.txt .
COPY sigma_analyzer/loki-backend.yaml .
COPY sigma_analyzer/analyzer.py .
COPY sigma_analyzer/rules ./rules
COPY sigma_analyzer/compiled ./compiled
# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "analyzer.py"]
