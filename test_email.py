#!/usr/bin/env python3
import smtplib
from email.message import EmailMessage
import time

# ───── Configuration ─────────────────────────────────────────────────────────
SMTP_HOST = "127.0.0.1"
SMTP_PORT = 10026   
FROM_ADDR  = "sender@email-threat-docker.local"
TO_ADDR    = "recipient@email-threat-docker.local"

# ───── Test Messages ─────────────────────────────────────────────────────────
tests = [
    # (subject, body, [optional] attachments as dict)
    ("Team Lunch",        "Who's up for pizza on Friday?", None),
    ("Greetings",         "Just saying hello!",         None),
    ("Reminder: TPS",     "Please send TPS reports.",   None),
    ("Encoded payload",   "SGVsbG8gd29ybGQh",           None),
    ("Verify Your Account","Click here to verify.",     None),
    ("Check this link",   "http://phish.com/login",      None),
    ("Account Verification","Please verify account.",   None),
    ("Invoice attached",  "See attached invoice.",      {"invoice.exe": b"MZ..."}),
    ("CEO Request",       "Wire transfer ASAP.",         None),
    ("Hello there",       "How are you today?",         None),
    ("Security Alert",    "Unexpected login detected.", None),
    ("Meeting Notes",     "Minutes from today’s meeting.", None),
    ("Project Update",    "Build and deploy succeeded.", None),
    ("Urgent Action",     "Please act now!",            None),
    ("Suspicious Login",  "Login attempt from Russia.", None),
    ("Newsletter April",  "Our April newsletter is out!", None),
    ("Happy Friday!",     "Enjoy your weekend.",         None),
    ("Re: Your Question", "Thanks for reaching out.",    None),
    ("FYI: Maintenance",  "Downtime tonight 12–2am.",   None),
    ("Greetings Again",   "Just following up.",           None),
]

def send_email(subject, body, attachment=None):
    msg = EmailMessage()
    msg["From"]    = FROM_ADDR
    msg["To"]      = TO_ADDR
    msg["Subject"] = subject
    msg.set_content(body)
    if attachment:
        for fname, data in attachment.items():
            msg.add_attachment(data,
                               maintype="application",
                               subtype="octet-stream",
                               filename=fname)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        result = smtp.send_message(msg)
    # send_message returns {} or {'addr': (code, message)} on errors
    return result

def main():
    print("Sending test emails...\n")
    for subj, body, attach in tests:
        resp = send_email(subj, body, attach)
        status = "Email sent" if not resp else f"Email refused: {resp}"
        print(f"{subj!r}: {status}")
        time.sleep(0.1)

if __name__ == "__main__":
    main()
