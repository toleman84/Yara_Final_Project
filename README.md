# SecureMail Scanner 📧🛡️
Sistema de filtrado y análisis de correos electrónicos en tiempo real, diseñado para interceptar, analizar y bloquear amenazas basadas en reglas YARA y Sigma.

---

## 🚀 ¿Qué es SecureMail Scanner?
SecureMail Scanner es una plataforma contenerizada de seguridad de correo electrónico, construida sobre:

- **Postfix** como servidor SMTP.
- **Python Scanner** usando **YARA** para análisis de malware.
- **Grafana + Loki + Promtail** para visualización y alertas.
- **Docker Compose** para despliegue modular y escalable.

Inspirado en arquitecturas de seguridad de cloud corporativo (Google, Microsoft, AWS).

---

## 🛠️ Stack Tecnológico
| Componente | Tecnología |
| :--- | :--- |
| SMTP Server | Postfix |
| Malware Scanner | Python + YARA |
| Event Correlation | Sigma |
| Visualización de Logs | Grafana |
| Agregado de Logs | Loki + Promtail |
| Contenerización | Docker Compose |

---

# 🏛️ Arquitectura del Sistema de Escaneo de Correos

Este proyecto implementa una arquitectura modular para la recepción, análisis y visualización de correos electrónicos en busca de amenazas.

## Diagrama General

```mermaid
flowchart TD
    A       [🌐 Internet / External Senders] --> B[📮 Postfix SMTP Server (Docker)]
    B -->   C[🔎 Content Filter → Python Scanner]
    C -->   |Clean Email| D[📥 Local Delivery]
    C -->   |Malware Detected| E[🚨 Quarantine + Alert System]
    E -->   F[📊 Grafana Dashboard (Logs & Alerts)]
```

---

## 📦 Despliegue Rápido
1. Clona el repositorio:
```bash
git clone https://github.com/tuusuario/securemail-scanner.git
cd securemail-scanner
```

2. Construye y levanta los contenedores:
```
docker-compose up --build
```

3. Accede al Dashboard:
```
- Grafana: http://localhost:3000
- Usuario: admin
- Contraseña: changeme
```

## 🔥 Características Principales
- Escaneo de correos en tiempo real.
- Motor de detección basado en YARA (customizable).
- Cuarentena automática de correos sospechosos.
- Alertas de incidentes por Grafana y Promtail.
- Resiliencia: Auto-restart de servicios críticos.
- Listo para producción con red privada Docker.

# 📚 Estructura del Proyecto
secure-email-scanner/
├── docker-compose.yml
├── postfix/
│   ├── Dockerfile
│   ├── main.cf
│   └── master.cf
├── scanner/
│   ├── Dockerfile
│   ├── scanner.py
│   ├── yara_rules/
│   └── quarantine/
├── grafana/
│   └── dashboards/
├── promtail/
│   └── config.yml
├── loki/
│   └── config.yaml
├── README.md
├── LICENSE
└── docs/
    ├── architecture.png
    └── installation_guide.md

# 🛡️ Roadmap
- Implementar limpieza automática de cuarentena.
- Integración de detección Sigma completa.
- Integración SMTP/TLS real para tráfico cifrado.
- Portal Web de revisión de cuarentena.

# 👨‍💻 Contribuciones
¡Pull Requests bienvenidos!
Por favor sigue la estructura de ramas:
```
- feature/* para nuevas funcionalidades
- bugfix/* para correcciones
- docs/* para documentación
```

# 🌟 Créditos
Proyecto inspirado por las mejores prácticas de seguridad de correo electrónico en entornos cloud modernos.
Desarrollado con ❤️ por toleman.
