import smtplib
import time
from email.message import EmailMessage

# Configuration
SMTP_SERVER = '127.0.0.1'
SMTP_PORT = 25
RECIPIENT = 'recipient@email-threat-docker.local'
DELAY_SECONDS = 1  # delay between sending emails in seconds

# Define 10 clean emails
emails = [
    {
        "from": "notifications@company.com",
        "subject": "Welcome to Our Service",
        "body": """Dear User,

Thank you for signing up for our service. We’re excited to have you on board. You can log in anytime at https://app.company.com to manage your account.

Best regards,
Company Team
"""
    },
    {
        "from": "newsletter@store.com",
        "subject": "September Newsletter – Special Offers Inside!",
        "body": """Hello,

Check out our latest products and exclusive deals on our website at https://www.store.com. We appreciate your loyalty and hope you enjoy these updates.

Sincerely,
Store Team
"""
    },
    {
        "from": "hr@company.com",
        "subject": "Upcoming Holiday Schedule",
        "body": """Dear Team,

Please note that the company will be closed on Monday for the public holiday. Regular work resumes on Tuesday at 9 AM. Enjoy your long weekend!

Best,
HR Department
"""
    },
    {
        "from": "teamlead@company.com",
        "subject": "Project Kickoff Meeting",
        "body": """Hi Everyone,

You are invited to the project kickoff meeting this Friday at 2 PM in Conference Room A. Please see the calendar invite and let me know if you have any questions.

Thanks,
Team Lead
"""
    },
    {
        "from": "noreply@itdept.company.com",
        "subject": "Scheduled Maintenance Tonight",
        "body": """Dear User,

This is to inform you that there will be a brief network outage tonight from 11 PM to midnight due to scheduled maintenance. No action is required on your part.

IT Department
"""
    },
    {
        "from": "alerts@service.com",
        "subject": "Your Subscription Renewal Confirmation",
        "body": """Hi,

Your subscription has been successfully renewed. The payment of $49.99 has been processed. Thank you for choosing our service!

Regards,
Billing Team
"""
    },
    {
        "from": "events@company.com",
        "subject": "Join Us for the Charity Run!",
        "body": """Hello,

You are invited to participate in our annual charity run this weekend. Visit our website for details and registration. We look forward to seeing you there!

Cheers,
Community Outreach Team
"""
    },
    {
        "from": "security@service.com",
        "subject": "Password Change Successful",
        "body": """Hello,

This is a confirmation that your account password was successfully changed. If you did not make this change, please contact our support team immediately.

Thank you,
Security Team
"""
    },
    {
        "from": "devteam@company.com",
        "subject": "Feature X Deployment",
        "body": """Team,

Feature X has been deployed to the production environment. All tests passed, and performance is stable. Please report any issues to the development channel.

Thanks,
Dev Team
"""
    },
    {
        "from": "communications@company.com",
        "subject": "Town Hall Meeting Next Week",
        "body": """Dear Colleagues,

We will be holding a company-wide town hall meeting next Wednesday at 10 AM via video conference. An invite with dial-in details will follow soon.

Best regards,
Communications
"""
    },
]

# Define 20 malicious emails
malicious_emails = [
    {
        "from": "billing@legit-company.com",
        "subject": "Urgent: Invoice Payment Required",
        "body": """Hello,

Your invoice is overdue. Click here to view and pay: http://phishingsite.example.com/invoice?id=12345

Thank you.
"""
    },
    {
        "from": "deals@newsletter.com",
        "subject": "Hot Deals This Weekend!",
        "body": """Hi,

Don't miss out on exclusive offers at spamdomain.net! Visit our site: http://spamdomain.net/sale

Cheers.
"""
    },
    {
        "from": "security@onlinebank.com",
        "subject": "Account Locked",
        "body": """Dear user,

We detected suspicious activity. Please click here to unlock your account: http://fakebank.example.com/verify

Regards.
"""
    },
    {
        "from": "support@service.com",
        "subject": "Password Reset Required",
        "body": """Hello,

Your password must be reset due to a security issue. Click here to reset your password immediately: http://service.example.com/reset-password

Thanks.
"""
    },
    {
        "from": "Alice Smith <alice.smith@bigcorp.com>",
        "subject": "Urgent Wire Transfer",
        "body": """Hi,

I am in a meeting right now. Please urgently transfer $15,000 to account 987654321 at ACME Bank.
Do not reply to this email.

Thanks.
"""
    },
    {
        "from": "info@company.com",
        "subject": "Important Document",
        "body": """Hello,

See the attached invoice.exe for details on your recent purchase. It's an urgent matter.
"""
    },
    {
        "from": "admin@company.com",
        "subject": "Monthly Report",
        "body": """Attached is the report. The attachment contains the antivirus test string: X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
Please check it.
"""
    },
    {
        "from": "notifications@company.com",
        "subject": "Security Alert",
        "body": """Hi,

Please see the attached update.scr to view important security information.
"""
    },
    {
        "from": "support@service.com",
        "subject": "System Notification",
        "body": """Hello,

Please visit http://example.com/%68%61%63%6b%65%64 where you'll find important information.
"""
    },
    {
        "from": "support@service.com",
        "subject": "Final Warning",
        "body": """Dear customer,

This is your final warning to update your payment information. Visit our secure portal here: http://secure-update.example.com/account
"""
    },
    {
        "from": "hr@company.com",
        "subject": "Mandatory W-2 Form",
        "body": """Hello,

Please click here to fill out your W-2 tax form: http://legit-bank.info/w2form
"""
    },
    {
        "from": "updates@deals.com",
        "subject": "Special Announcement",
        "body": """Don’t miss this! Visit spamdomain.net now for more details.
"""
    },
    {
        "from": "support@apple.com",
        "subject": "Account Verification Needed",
        "body": """Dear User,

Your Apple ID has unusual activity. Click here to sign in and secure your account: http://malicious-verify.example.com/login
"""
    },
    {
        "from": "support@bank.com",
        "subject": "Password Reset Request",
        "body": """Hello,

We received a request to reset your password. Click here to reset it: http://bank.example.com/reset
"""
    },
    {
        "from": "hr@company.com",
        "subject": "Mandatory Company Survey",
        "body": """Hello,

Please click here to complete the employee satisfaction survey: http://survey.example.com/
"""
    },
    {
        "from": "support@onlineservice.com",
        "subject": "Suspicious Login Attempt",
        "body": """We’ve noticed a login from a new device. Click here to review the activity: http://alert.example.com/review
"""
    },
    {
        "from": "security@bigcorp.com",
        "subject": "Account Compromised",
        "body": """Your account was compromised. Reset your password immediately: http://bigcorp.example.com/reset
"""
    },
    {
        "from": "rewards@shopping.com",
        "subject": "You've Won a $100 Gift Card!",
        "body": """Congratulations! Claim your $100 gift card by clicking here: http://freegift.example.com/claim
"""
    },
    {
        "from": "survey@company.com",
        "subject": "Quick Employee Survey",
        "body": """Hello,

Click here to provide feedback and win a prize: http://survey.example.com/
"""
    },
    {
        "from": "recruiter@jobs.com",
        "subject": "Job Interview Invitation",
        "body": """Hi,

We received your resume for an open position. Please fill out this form: http://jobs.example.com/form
"""
    },
]

# Combine into one list
emails += malicious_emails

# Send emails
with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
    for idx, email in enumerate(emails, start=1):
        msg = EmailMessage()
        msg['From'] = email['from']
        msg['To'] = RECIPIENT
        msg['Subject'] = email['subject']
        msg.set_content(email['body'])
        
        try:
            smtp.send_message(msg)
            print(f"[✔] Sent email {idx}/{len(emails)}: {email['subject']}")
        except Exception as e:
            print(f"[✗] Failed to send email {idx}: {e}")
        
        # Delay before sending the next email
        if idx < len(emails):
            time.sleep(DELAY_SECONDS)