#!/usr/bin/env python3
"""
Email Threat Scanner with YARA Only
- Sigma scanning removed for simplicity
- Docker-optimized paths
"""

import asyncio
import logging
import os
import email
import time
import yara
import json 
from email.policy import default
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope
from aiosmtplib import SMTP
from typing import Dict, Any, List

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
            # Run YARA scan
            threats = []
            if self.yara_rules:
                matches = self.yara_rules.match(data=envelope.content)
                threats.extend(f"YARA:{m.rule}" for m in matches)

            if threats:
                await self._quarantine_email(envelope, threats)
                return "250 Message quarantined"

            await self._reinject_email(envelope)
            return "250 Message delivered"
        except Exception as e:
            logging.error(f"Processing failed: {str(e)}")
            return "451 Temporary error"

    async def _reinject_email(self, envelope: Envelope):
        async with SMTP(hostname=CONFIG["reinject_host"], port=CONFIG["reinject_port"], timeout=10) as client:
            await client.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.original_content)
        logging.info("Email reinjected successfully")

    async def _quarantine_email(self, envelope, threats: List[str]):
        os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)
        msg = email.message_from_bytes(envelope.content, policy=default)
        ts = int(time.time())
        filename = f"quarantine_{ts}_{len(threats)}.eml"
        filepath = os.path.join(CONFIG["quarantine_dir"], filename)
        with open(filepath, 'wb') as f:
            f.write(envelope.content)

        logging.warning(f"Quarantined: {filepath} | Threats: {', '.join(threats)}")
        event = {
            "timestamp": ts,
            "sender": envelope.mail_from,
            "recipient": ",".join(envelope.rcpt_tos),
            "subject":   msg.get("subject",""),        # capture subject
            "yara_hits": threats,
            "quarantined": True
        }

        # Append to JSON log
        with open(CONFIG["json_log"], "a") as jf:
          jf.write(json.dumps(event) + "\n")
# ===================== Main Service =====================
def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(CONFIG["log_file"]),
            logging.StreamHandler()
        ]
    )

    yara_rules = load_yara_rules()
    controller = Controller(
        EmailScanner(yara_rules),
        hostname=CONFIG["listen_host"],
        port=CONFIG["listen_port"]
    )

    logging.info(f"Starting YARA-only scanner on {CONFIG['listen_host']}:{CONFIG['listen_port']}")
    controller.start()
    asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    main()
