#!/usr/bin/env python3
"""
Enhanced Email Threat Scanner with YARA + Sigma Rules
(Final Consolidated Script)
"""

import asyncio
import logging
import os
import email
import time
import yara
from email.policy import default
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope
from aiosmtplib import SMTP
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
from types import SimpleNamespace
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaError

# ===================== Configuration =====================
CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 10025,
    "reinject_host": "postfix",
    "reinject_port": 10026,
    "yara_rules_dir": "/app/rules/yara",
    "sigma_rules_dir": "/app/rules/sigma",
    "quarantine_dir": "/app/quarantine",
    "log_file": "/var/log/mail_scanner.log",
    "max_email_size": 1024 * 1024,
    "max_attachment_size": 512 * 1024,
    "allowed_content_types": [
        "text/plain", "text/html", "application/pdf", "application/zip"
    ]
}

# ===================== Sigma Rule Wrapper =====================
class SigmaRuleWrapper:
    def __init__(self, rule: SigmaRule):
        self.rule = rule
        self.field_map = {
            "subject": "email_subject",
            "from": "email_sender",
            "to": "email_recipient",
            "body": "email_body",
            "attachments.filename": "email_attachment_name",
            "attachments.content": "email_attachment_content"
        }

    def _convert_to_events(self, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        base = {
            "subject": email_data.get("subject", ""),
            "from": email_data.get("from", ""),
            "to": email_data.get("to", ""),
            "body": email_data.get("body", "")
        }
        events = [base]
        for att in email_data.get("attachments", []):
            evt = base.copy()
            evt["attachments.filename"] = att.get("filename", "")
            evt["attachments.content"] = att.get("content", "")
            events.append(evt)
        return events

    def evaluate(self, email_data: Dict[str, Any]) -> bool:
        """Evaluate events against Sigma detections."""
        try:
            events = self._convert_to_events(email_data)
            for evt in events:
                # Map fields
                mapped = { self.field_map.get(k, k): v for k, v in evt.items() }
                # Add static state
                mapped["email_source"] = "mailserver"
                event_obj = SimpleNamespace(**mapped)

                # Check each detection
                for det in self.rule.detection.detections.values():
                    try:
                        result = det.postprocess(event_obj)
                        if result:
                            logging.info(f"[SIGMA] Rule matched: {self.rule.title}")
                            return True
                    except Exception as e:
                        logging.error(f"[SIGMA] Detection error in rule {self.rule.title}: {e}")
            return False
        except SigmaError as e:
            logging.error(f"[SIGMA] Sigma evaluation error [{self.rule.id}]: {e}")
            return False

def _is_email_rule(rule: SigmaRule) -> bool:
    prod = getattr(rule.logsource, "product", "")
    return prod and prod.lower() in {"mail", "email"}

def load_sigma_rules() -> List[SigmaRuleWrapper]:
    wrappers: List[SigmaRuleWrapper] = []
    for root, _, files in os.walk(CONFIG["sigma_rules_dir"]):
        for fname in files:
            if fname.lower().endswith(('.yml', '.yaml')):
                path = os.path.join(root, fname)
                try:
                    with open(path, 'r') as f:
                        coll = SigmaCollection.from_yaml(f)
                        for rule in coll.rules:
                            if _is_email_rule(rule):
                                wrappers.append(SigmaRuleWrapper(rule))
                                logging.info(f"[SIGMA] Loaded rule: {rule.title}")
                except Exception as e:
                    logging.error(f"[SIGMA] Failed loading {fname}: {e}")
    return wrappers

# ===================== YARA =====================
def load_yara_rules() -> Optional[yara.Rules]:
    try:
        filepaths = {}
        for root, _, files in os.walk(CONFIG["yara_rules_dir"]):
            for fname in files:
                if fname.lower().endswith(('.yar', '.yara')):
                    name = os.path.splitext(fname)[0]
                    filepaths[name] = os.path.join(root, fname)
        return yara.compile(filepaths=filepaths) if filepaths else None
    except Exception as e:
        logging.error(f"[YARA] Loading error: {e}")
        return None

# ===================== Email Scanner =====================
class EmailScanner:
    def __init__(self):
        self.yara = load_yara_rules()
        self.sigma = load_sigma_rules()
        self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(CONFIG["log_file"]),
                logging.StreamHandler()
            ]
        )

    def _decode_part(self, part) -> str:
        try:
            return part.get_payload(decode=True).decode('utf-8', errors='replace')
        except:
            return ""

    async def handle_DATA(self, server, session, envelope: Envelope):
        try:
            # Enforce max email size
            if len(envelope.content) > CONFIG["max_email_size"]:
                return "552 Message too large"

            msg = email.message_from_bytes(envelope.content, policy=default)
            data = {
                "subject": msg.get("subject", ""),
                "from": msg.get("from", ""),
                "to": msg.get("to", ""),
                "body": self._extract_body(msg),
                "attachments": self._extract_attachments(msg)
            }

            threats: List[str] = []

            # YARA scan
            if self.yara:
                try:
                    for m in self.yara.match(data=envelope.content):
                        threats.append(f"YARA:{m.rule}")
                except Exception as e:
                    logging.error(f"[YARA] Error: {e}")

            # Sigma scan
            for rule in self.sigma:
                if rule.evaluate(data):
                    threats.append(f"SIGMA:{rule.rule.title}")

            # Quarantine or deliver
            if threats:
                await self._quarantine(envelope, threats)
                return "250 Message quarantined"
            await self._reinject(envelope)
            return "250 Message delivered"

        except Exception as e:
            logging.error(f"[Scanner] Processing failed: {e}")
            return "451 Temporary error"

    def _extract_body(self, msg) -> str:
        parts: List[str] = []
        for p in msg.walk():
            ctype = p.get_content_type()
            if ctype == "text/plain":
                parts.append(self._decode_part(p))
            elif ctype == "text/html":
                parts.append(BeautifulSoup(self._decode_part(p), "html.parser").get_text())
        return "\n".join(parts)

    def _extract_attachments(self, msg) -> List[Dict[str, Any]]:
        attachments: List[Dict[str, Any]] = []
        for p in msg.walk():
            fn = p.get_filename()
            if fn and p.get_content_type() in CONFIG["allowed_content_types"]:
                buf = p.get_payload(decode=True)
                if buf and len(buf) <= CONFIG["max_attachment_size"]:
                    attachments.append({
                        "filename": fn,
                        "content": buf.decode('utf-8', errors='replace')
                    })
        return attachments

    async def _reinject(self, envelope: Envelope):
        async with SMTP(hostname=CONFIG["reinject_host"], port=CONFIG["reinject_port"]) as client:
            await client.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.original_content)

    async def _quarantine(self, envelope: Envelope, threats: List[str]):
        os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)
        ts = int(time.time())
        fname = f"quarantine_{ts}_{hash(envelope.content)}.eml"
        path = os.path.join(CONFIG["quarantine_dir"], fname)
        with open(path, 'wb') as f:
            f.write(envelope.content)
        logging.warning(f"[Quarantine] {path}, threats: {threats}")

def main():
    scanner = EmailScanner()
    controller = Controller(scanner, hostname=CONFIG["listen_host"], port=CONFIG["listen_port"])
    controller.start()
    asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    main()
