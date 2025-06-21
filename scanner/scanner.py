#!/usr/bin/env python3
"""
Email Threat Scanner with YARA
Optimized for Loki/Grafana with structured JSON logs
"""

import os
import time
import json
import logging
import email
import yara
import asyncio
from email.policy import default
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope
from aiosmtplib import SMTP
from typing import List

CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 10025,
    "reinject_host": os.environ.get("REINJECTION_HOST", "postfix"),
    "reinject_port": int(os.environ.get("REINJECTION_PORT", 10026)),
    "yara_rules_dir": "/app/rules/yara",
    "quarantine_dir": "/app/quarantine",
    "log_json": os.environ.get("LOG_JSON", "true").lower() == "true",
    "service_name": "scanner"
}

# ---------- Structured JSON Logger for Loki ----------
class LokiJsonFormatter(logging.Formatter):
    def format(self, record):
        base = {
            "timestamp": int(time.time()),
            "level": record.levelname,
            "service": CONFIG["service_name"]
        }

        if isinstance(record.msg, dict):
            base.update(record.msg)
        else:
            base["message"] = record.getMessage()

        return json.dumps(base)


def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(LokiJsonFormatter())
    logger.addHandler(handler)

    log_path = os.environ.get("LOG_PATH", "/var/log/mail_scanner.json")
    try:
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(LokiJsonFormatter())
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Could not set up file logging: {e}")

# ---------- YARA ----------
def load_yara_rules():
    try:
        rule_files = {}
        for root, _, files in os.walk(CONFIG["yara_rules_dir"]):
            for file in files:
                if file.lower().endswith(('.yar', '.yara')):
                    path = os.path.join(root, file)
                    rule_files[os.path.splitext(file)[0]] = path

        if not rule_files:
            logging.warning("No YARA rule files found.")
            return None

        compiled = yara.compile(filepaths=rule_files)
        logging.info(f"Loaded YARA rules: {list(rule_files.keys())}")
        return compiled

    except Exception as e:
        logging.error(f"YARA load failed: {str(e)}")
        return None

# ---------- Email Scanner ----------
class EmailScanner:
    def __init__(self, yara_rules):
        self.yara_rules = yara_rules

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        logging.info(f"Accepted recipient: {address}")
        return "250 OK"

    async def handle_DATA(self, server, session, envelope: Envelope):
        try:
            threats = []
            ts = int(time.time())
            msg = email.message_from_bytes(envelope.content, policy=default)

            if self.yara_rules:
                for part in msg.walk():
                    if part.get_content_maintype() == "multipart":
                        continue
                    payload = part.get_payload(decode=True)
                    if payload:
                        matches = self.yara_rules.match(data=payload)
                        threats.extend(m.rule for m in matches)

            if threats:
                await self._quarantine_email(envelope, threats, ts, msg)
                return "250 Message quarantined"
            else:
                success = await self._reinject_email(envelope)
                if success:
                    await self._log_success(envelope, ts, msg)
                    return "250 Message delivered"
                else:
                    return "451 Failed to reinject message"

        except Exception as e:
            logging.error(f"Processing failed: {str(e)}")
            return "451 Temporary error"

    async def _reinject_email(self, envelope: Envelope) -> bool:
        try:
            async with SMTP(
                hostname=CONFIG["reinject_host"],
                port=CONFIG["reinject_port"],
                timeout=10
            ) as client:
                result, _ = await client.sendmail(
                    envelope.mail_from,
                    envelope.rcpt_tos,
                    envelope.original_content
                )

                if result:  # Non-empty dict means failed recipients
                    logging.error(f"Failed to reinject email. Errors: {result}")
                    return False

                logging.info("Email reinjected successfully")
                return True

        except Exception as e:
            logging.error(f"SMTP reinjection error: {str(e)}")
            return False

    async def _quarantine_email(self, envelope, threats: List[str], timestamp: int, msg):
        os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)

        rule_tag = threats[0] if threats else "unknown_rule"
        safe_tag = "".join(c for c in rule_tag if c.isalnum() or c in ("-", "_"))
        filename = f"quarantine_{safe_tag}_{timestamp}.eml"
        filepath = os.path.join(CONFIG["quarantine_dir"], filename)

        with open(filepath, "wb") as f:
            f.write(envelope.content)

        for threat in threats:
            event = {
                "timestamp": timestamp,
                "sender": envelope.mail_from,
                "recipient": ",".join(envelope.rcpt_tos),
                "subject": msg.get("subject", ""),
                "yara_hit": threat,
                "quarantined_file": filename,
                "quarantined": True,
                "status": "quarantined"
            }
            logging.warning(event)


    async def _log_success(self, envelope, timestamp: int, msg):
        event = {
            "timestamp": timestamp,
            "sender": envelope.mail_from,
            "recipient": ",".join(envelope.rcpt_tos),
            "subject": msg.get("subject", ""),
            "yara_hits": [],
            "quarantined": False,
            "status": "delivered"
        }
        logging.info(json.dumps(event))

# ---------- Main ----------
def main():
    setup_logger()
    yara_rules = load_yara_rules()
    controller = Controller(
        EmailScanner(yara_rules), hostname=CONFIG["listen_host"], port=CONFIG["listen_port"]
    )

    logging.info(f"Starting scanner on {CONFIG['listen_host']}:{CONFIG['listen_port']}")
    controller.start()
    asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    main()
