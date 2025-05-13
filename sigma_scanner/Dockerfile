FROM python:3.11-slim
WORKDIR /app
COPY sigma_scanner/sigma_log_scanner.py /app/
COPY rules/sigma /app/rules/sigma
RUN pip install pyyaml
CMD ["python", "/app/sigma_log_scanner.py"]
