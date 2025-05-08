#!/usr/bin/env python3
"""
Email Threat Scanner with YARA + Sigma
- Fixed time module reference
- Proper class method structure
- Docker-optimized paths
"""

import asyncio
import logging
import os
import re
import email
import time  
import yara
from email.policy import default
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session
from aiosmtplib import SMTP
from typing import Dict, List, Any

# ===================== Configuration =====================
CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 10025,
    "reinject_host": "postfix",
    "reinject_port": 10026,
    "yara_rules_dir": "/app/rules/yara",
    "sigma_rules_dir": "/app/rules/sigma",
    "quarantine_dir": "/app/quarantine",
    "log_file": "/var/log/mail_scanner.log"
}

# ===================== Sigma Implementation =====================
class SigmaRule:
    def __init__(self, rule_data: Dict):
        self.name = rule_data.get("title", "unnamed_rule")
        self.detection = rule_data.get("detection", {})
        
    def evaluate(self, email_data: Dict) -> bool:
        try:
            if "keywords" in self.detection:
                text = email_data.get("body", "").lower()
                if any(kw.lower() in text for kw in self.detection["keywords"]):
                    return True
                    
            if "fields" in self.detection:
                for field, patterns in self.detection["fields"].items():
                    field_value = str(email_data.get(field, "")).lower()
                    patterns = [patterns] if isinstance(patterns, str) else patterns
                    if any(re.search(p.lower(), field_value) for p in patterns):
                        return True
            return False
        except Exception as e:
            logging.warning(f"Sigma rule error: {str(e)}")
            return False

def load_sigma_rules() -> List[SigmaRule]:
    try:
        import yaml
        return [SigmaRule(yaml.safe_load(f)) 
                for root, _, files in os.walk(CONFIG["sigma_rules_dir"])
                for file in files if file.endswith(('.yml', '.yaml'))
                for f in [open(os.path.join(root, file), 'r')]]
    except Exception as e:
        logging.error(f"Sigma load failed: {str(e)}")
        return []

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
    def __init__(self, yara_rules, sigma_rules):
        self.yara_rules = yara_rules
        self.sigma_rules = sigma_rules

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        logging.info(f"Accepted recipient: {address}")
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        try:
            msg = email.message_from_bytes(envelope.content, policy=default)
            email_data = self._prepare_email_data(msg)
            threats = []
            
            # YARA scanning
            if self.yara_rules:
                if matches := self.yara_rules.match(data=envelope.content):
                    threats.extend(f"YARA:{match.rule}" for match in matches)
            
            # Sigma scanning
            threats += [f"SIGMA:{rule.name}" for rule in self.sigma_rules if rule.evaluate(email_data)]
            
            if threats:
                await self._quarantine_email(envelope, threats)
                return "250 Message quarantined"
                
            await self._reinject_email(envelope)
            return "250 Message delivered"
        except Exception as e:
            logging.error(f"Processing failed: {str(e)}")
            return "451 Temporary error"

    def _prepare_email_data(self, msg) -> Dict[str, Any]:
        return {
            "subject": msg.get("subject", ""),
            "from": msg.get("from", ""),
            "body": self._extract_text_content(msg),
            "attachments": self._extract_attachments(msg)
        }

    def _extract_text_content(self, msg) -> str:
        return "\n".join(
            part.get_payload(decode=True).decode('utf-8', errors='ignore')
            for part in msg.walk()
            if part.get_content_type() == "text/plain"
        )

    def _extract_attachments(self, msg) -> List[Dict]:
        return [{
            "filename": part.get_filename(),
            "type": part.get_content_type(),
            "size": len(part.get_payload(decode=True))
        } for part in msg.walk() if part.get_filename()]

    async def _reinject_email(self, envelope):
        try:
            async with SMTP(
                hostname=CONFIG["reinject_host"],
                port=CONFIG["reinject_port"],
                timeout=10
            ) as client:
                await client.sendmail(
                    envelope.mail_from,
                    envelope.rcpt_tos,
                    envelope.original_content
                )
            logging.info("Email reinjected successfully")
        except Exception as e:
            logging.error(f"Reinjection failed: {str(e)}")
            raise

    async def _quarantine_email(self, envelope, threats):
        try:
            os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)
            timestamp = int(time.time())  
            filename = f"quarantine_{timestamp}_{len(threats)}.eml"
            filepath = os.path.join(CONFIG["quarantine_dir"], filename)
            
            with open(filepath, 'wb') as f:
                f.write(envelope.content)
                
            logging.warning(f"Quarantined: {filepath} | Threats: {', '.join(threats)}")
        except Exception as e:
            logging.error(f"Quarantine failed: {str(e)}")
            raise

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
    
    controller = Controller(
        EmailScanner(load_yara_rules(), load_sigma_rules()),
        hostname=CONFIG["listen_host"],
        port=CONFIG["listen_port"]
    )
    
    try:
        logging.info(f"Starting scanner on {CONFIG['listen_host']}:{CONFIG['listen_port']}")
        controller.start()
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()

if __name__ == "__main__":
    main()