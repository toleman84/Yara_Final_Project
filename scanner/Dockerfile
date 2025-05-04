# imagen base ligera
FROM python:3.12-slim

# Información del mantenedor
LABEL mainterpreter="email@gmail.com"
LABEL description="Secure Email Sanner with YARA and Sigma Rules"

# Actualizamos paquetes y preparamos el entorno
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Crear directorios necesarios
RUN mkdir -p /app/rules /quarantine

# Copiar el código del scanner
COPY scanner.py /app/scanner.py

# Copiar las reglas de YARA
COPY yara_rules/ /rules/

# Definir el directorio de trabajo
WORKDIR /app

# Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Variales de entorno (default pero pueden sobreescribirse en docker-compose)
ENV SCAN_PORT=10025
ENV QUARANTINE_DIR=/quarantine

# Exponer el puerto interno para recibir emails del content_filter
EXPOSE 10025

# Comando por defecto para ejecutar el scanner
CMD ["python", "scanner.py"]

# Para construir la imagen>
# docker build -t email_scanner .

# Para arrancar el contenedor en modo bash para explorarlo:
# docker run -it --rm --name email_scanner_debug -v /quarantine:/quarantine email_scanner /bin/bash

# Para ejecutar el contenedor, usar el siguiente comando:
# docker run -d -p 10025:10025 --name email_scanner -v /scanner/quarantine:/quarantine email_scanner
