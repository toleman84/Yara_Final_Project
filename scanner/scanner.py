#!/usr/bin/env python3
"""
Email Threat Scanner with YARA Only
- Sigma scanning removed for simplicity
- Docker-optimized paths
- Logs both quarantined and successfully delivered emails to JSON file
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

# ===================== Configuration =====================
CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 10025,
    "reinject_host": "postfix",
    "reinject_port": 10026,
    "yara_rules_dir": "/app/rules/yara",
    "quarantine_dir": "/app/quarantine",
    "log_file": "/var/log/mail_scanner.log",
    "json_log": "/var/log/mail_scanner.json",
}

# ===================== YARA Implementation =====================
def load_yara_rules():
    try:
        rule_files = {}
        for root, _, files in os.walk(CONFIG["yara_rules_dir"]):
            for file in files:
                if file.lower().endswith(('.yar', '.yara')):
                    path = os.path.join(root, file)
                    rule_files[os.path.splitext(file)[0]] = path
        return yara.compile(filepaths=rule_files) if rule_files else None
    except Exception as e:
        logging.error(f"YARA load failed: {str(e)}")
        return None

# ===================== Email Processing =====================
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
                # Scan all parts (attachments and text)
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
                await self._reinject_email(envelope)
                await self._log_success(envelope, ts, msg)
                return "250 Message delivered"

        except Exception as e:
            logging.error(f"Processing failed: {str(e)}")
            return "451 Temporary error"

    async def _reinject_email(self, envelope: Envelope):
        async with SMTP(
            hostname=CONFIG["reinject_host"], port=CONFIG["reinject_port"], timeout=10
        ) as client:
            await client.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.original_content)
        logging.info("Email reinjected successfully")

    async def _quarantine_email(self, envelope, threats: List[str], timestamp: int, msg):
        os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)

        # Use the rule name as the filename identifier
        rule_tag = threats[0] if threats else "unknown_rule"
        safe_tag = "".join(c for c in rule_tag if c.isalnum() or c in ("-", "_"))
        filename = f"quarantine_{safe_tag}.eml"
        filepath = os.path.join(CONFIG["quarantine_dir"], filename)

        with open(filepath, "wb") as f:
            f.write(envelope.content)

        logging.warning(f"Quarantined: {filepath} | Threats: {', '.join(threats)}")

        event = {
            "timestamp": timestamp,
            "sender": envelope.mail_from,
            "recipient": ",".join(envelope.rcpt_tos),
            "subject": msg.get("subject", ""),
            "yara_hits": threats,
            "quarantined_file": filename,
            "quarantined": True,
        }

        with open(CONFIG["json_log"], "a") as jf:
            jf.write(json.dumps(event) + "\n")


    async def _log_success(self, envelope, timestamp: int, msg):
        event = {
            "timestamp": timestamp,
            "sender": envelope.mail_from,
            "recipient": ",".join(envelope.rcpt_tos),
            "subject": msg.get("subject", ""),
            "yara_hits": "no matches",
            "quarantined": False,
        }
        with open(CONFIG["json_log"], "a") as jf:
            jf.write(json.dumps(event) + "\n")

# ===================== Main Service =====================
def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(CONFIG["log_file"]),
            logging.StreamHandler(),
        ],
    )

    yara_rules = load_yara_rules()
    controller = Controller(
        EmailScanner(yara_rules), hostname=CONFIG["listen_host"], port=CONFIG["listen_port"]
    )

    logging.info(f"Starting YARA-only scanner on {CONFIG['listen_host']}:{CONFIG['listen_port']}")
    controller.start()
    asyncio.get_event_loop().run_forever()


if __name__ == "__main__":
    main()