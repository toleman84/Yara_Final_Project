#!/usr/bin/env python3
"""
Email Threat Scanner Service
- Listens for incoming emails on port 10025
- Scans content using YARA rules
- Reinjects clean emails to Postfix (10026)
- Quarantines malicious emails
"""

import asyncio
import logging
import os
import email
import yara
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session
from email.policy import default
from aiosmtplib import SMTP

# ===================== Configuration =====================
CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 10025,
    "reinject_host": "postfix",
    "reinject_port": 10026,
    "yara_rules_dir": "/app/rules/yara",
    "quarantine_dir": "/app/quarantine",
    "log_file": "/var/log/mail_scanner.log"
}

# ===================== Initialization =====================
def setup_logging():
    """Configure logging to both file and console"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(CONFIG["log_file"]),
            logging.StreamHandler()
        ]
    )

def load_yara_rules():
    """
    Load all YARA rules from the specified directory
    Returns compiled rules or None if failed
    """
    try:
        if not os.path.exists(CONFIG["yara_rules_dir"]):
            logging.error(f"YARA rules directory not found: {CONFIG['yara_rules_dir']}")
            return None

        rule_files = {}
        for file in os.listdir(CONFIG["yara_rules_dir"]):
            if file.endswith(('.yar', '.yara')):
                rule_name = os.path.splitext(file)[0]
                rule_path = os.path.join(CONFIG["yara_rules_dir"], file)
                rule_files[rule_name] = rule_path

        if not rule_files:
            logging.error("No valid YARA rule files found")
            return None

        logging.info(f"Loaded YARA rules: {list(rule_files.keys())}")
        return yara.compile(filepaths=rule_files)

    except Exception as e:
        logging.error(f"Failed to load YARA rules: {str(e)}")
        return None

# ===================== Email Processing =====================
class EmailScanner:
    def __init__(self, yara_rules):
        self.yara_rules = yara_rules

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Accept valid recipients"""
        envelope.rcpt_tos.append(address)
        logging.info(f"Accepted recipient: {address}")
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        """Process incoming email message"""
        try:
            logging.info(f"Processing email from {envelope.mail_from}")

            # Parse the email
            msg = email.message_from_bytes(envelope.content, policy=default)

            # Scan for threats
            if await self.scan_for_threats(msg, envelope.content):
                await self.quarantine_email(envelope)
                return "250 Message quarantined"
            
            # Reinject clean email
            await self.reinject_email(envelope)
            return "250 Message delivered"

        except Exception as e:
            logging.error(f"Failed to process email: {str(e)}", exc_info=True)
            return "451 Temporary processing error"

    async def scan_for_threats(self, msg, raw_data):
        """Scan email content and attachments using YARA rules"""
        if not self.yara_rules:
            logging.warning("No YARA rules available - allowing all mail")
            return False

        try:
            # Scan raw email content
            if self.yara_rules.match(data=raw_data):
                return True

            # Scan all parts of the email
            for part in msg.walk():
                if part.get_content_maintype() == "text":
                    if content := part.get_payload(decode=True):
                        if self.yara_rules.match(data=content):
                            return True

                # Scan attachments
                if part.get_filename():
                    if content := part.get_payload(decode=True):
                        if self.yara_rules.match(data=content):
                            return True

            return False

        except Exception as e:
            logging.error(f"Scanning error: {str(e)}")
            return False

    async def reinject_email(self, envelope):
        """Send clean email back to Postfix"""
        try:
            async with SMTP(
                hostname="postfix",
                port=10026,
                timeout=10
            ) as client:
                await client.sendmail(
                envelope.mail_from,
                envelope.rcpt_tos,
                envelope.original_content
            )
            logging.info("Successfully reinjected clean email")

        except Exception as e:
            logging.error(f"Failed to reinject email: {str(e)}")
            raise

    async def quarantine_email(self, envelope):
        """Save potentially malicious email"""
        try:
            os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)
            filename = f"quarantine_{envelope.mail_from}_{len(envelope.content)}.eml"
            filepath = os.path.join(CONFIG["quarantine_dir"], filename)

            with open(filepath, 'wb') as f:
                f.write(envelope.content)

            logging.warning(f"Quarantined suspicious email: {filepath}")

        except Exception as e:
            logging.error(f"Failed to quarantine email: {str(e)}")
            raise

# ===================== Main Service =====================
async def run_scanner_service():
    """Start and maintain the SMTP scanner service"""
    setup_logging()
    yara_rules = load_yara_rules()

    controller = Controller(
        EmailScanner(yara_rules),
        hostname=CONFIG["listen_host"],
        port=CONFIG["listen_port"]
    )

    try:
        logging.info(f"Starting email scanner on {CONFIG['listen_host']}:{CONFIG['listen_port']}")
        controller.start()
        
        # Keep the service running
        while True:
            await asyncio.sleep(3600)

    except KeyboardInterrupt:
        logging.info("Shutting down scanner service")
    except Exception as e:
        logging.error(f"Scanner crashed: {str(e)}", exc_info=True)
    finally:
        controller.stop()

if __name__ == "__main__":
    asyncio.run(run_scanner_service())