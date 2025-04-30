# imagen base ligera
FROM python:3.12-slim

# Información del mantenedor
LABEL mainterpreter="gdponcemarsiglia@gmail.com"
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

# Para ejecutar el contenedor, usar el siguiente comando:
# docker run -d -p 10025:10025 --name email_scanner -v /path/to/quarantine:/quarantine email_scanner

# Para ejecutar el contenedor en modo interactivo, usar el siguiente comando:
# docker run -it --rm -p 10025:10025 --name email_scanner -v /path/to/quarantine:/quarantine email_scanner

# Para ejecutar el contenedor en modo interactivo y acceder a la consola de Python, usar el siguiente comando:
# docker run -it --rm -p 10025:10025 --name email_scanner -v /path/to/quarantine:/quarantine email_scanner /bin/bash

