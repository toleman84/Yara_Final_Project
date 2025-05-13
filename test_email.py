#!/usr/bin/env python3
import smtplib
from email.message import EmailMessage
import random
import time

# Configuration
SMTP_HOST = "localhost"
SMTP_PORT = 10026
FROM_ADDR = "sender@email-threat-docker.local"
TO_ADDR = "recipient@email-threat-docker.local"

# 10 payloads designed to trigger specific rules
malicious_bodies = [
    # phishing_keywords
    ("Urgent Action Required", "Please click here to verify your account."),
    ("Security Alert", "Confirm your credentials now!"),
    ("Verify Your Account", "Click here: http://phish.com/login"),
    # domain rule (once scoped to http://)
    ("Check this link", "Visit http://example.xyz/"),
    # contains_base64 (if you still have that)
    ("Encoded payload", "SGVsbG8gd29ybGQh"),  # "Hello world!" in base64
    # executable attachment (if you support attachments)
    ("Invoice attached", "See the attached invoice.", {"invoice.exe": b"MZ..." }),
    # high-risk geography (subject bait)
    ("Login from Russia", "We noticed a login from Moscow."),
    # CEO fraud
    ("CEO Request: Wire Transfer", "Please process a wire transfer of $10,000."),
    # generic phishing link
    ("Account Verification", "http://malicious.example.com/verify"),
    # suspicious login attempt
    ("Suspicious Login Attempt", "Someone tried to login to your account.")
]

# 10 clean bodies
clean_bodies = [
    ("Hello there", "Just checking in—how are you?"),
    ("Meeting Notes", "Attached the minutes from today's meeting."),
    ("Happy Friday!", "Hope you have a great weekend."),
    ("Newsletter April", "Our April newsletter is out!"),
    ("Re: Your Question", "Thanks for reaching out, here's the info."),
    ("Team Lunch", "Who's up for pizza on Friday?"),
    ("Project Update", "The build succeeded and we deployed."),
    ("Reminder: TPS Reports", "Please send your TPS reports by EOD."),
    ("FYI: System Maintenance", "We'll have downtime tonight 12–2am."),
    ("Greetings", "Wishing you a wonderful day!")
]

def send_email(subject, body, attachment=None):
    msg = EmailMessage()
    msg["From"] = FROM_ADDR
    msg["To"] = TO_ADDR
    msg["Subject"] = subject
    msg.set_content(body)
    if attachment:
        for fname, data in attachment.items():
            msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=fname)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        resp = s.send_message(msg)
        return resp  # None means accepted

def main():
    tests = []
    # Build malicious tests
    for subj, body, *opt in malicious_bodies:
        attachment = opt[0] if opt else None
        tests.append((subj, body, attachment, True))  # True = should be quarantined

    # Build clean tests
    for subj, body in clean_bodies:
        tests.append((subj, body, None, False))      # False = should be delivered

    # Shuffle to avoid order bias
    random.shuffle(tests)

    print(f"Sending {len(tests)} test emails...\n")
    results = []
    for idx, (subj, body, attachment, should_quarantine) in enumerate(tests, 1):
        resp = send_email(subj, body, attachment)
        status = "QUARANTINED" if should_quarantine else "DELIVERED"
        print(f"{idx:02d}. {subj!r} -> expected: {status} | SMTP resp: {resp}")
        results.append((idx, subj, should_quarantine, resp is None))
        time.sleep(0.2)  # slight delay

    # Summary
    print("\nSummary:")
    for idx, subj, should_q, success in results:
        outcome = "QUARANTINE" if success else "DELIVERED"
        correct = (should_q and success) or (not should_q and not success)
        mark = "✅" if correct else "❌"
        print(f"{mark} [{idx:02d}] {subj!r}: expected={'QUARANTINE' if should_q else 'DELIVER'} got={outcome}")

if __name__ == "__main__":
    main()
