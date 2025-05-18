rule Suspicious_Urgency_Language
{
    meta:
        author      = "SeMail"
        description = "Detect mails with urgent lenguage often used in phishing low severity"
        created     = "2025-05-17"
        severity    = "low"
    strings:
        $s1 = "URGENT"
        $s2 = "Immediate action required"
        $s3 = "Your account will be locked"
        $s4 = "Security Alert"
        $s5 = "Unauthorized login attempt"
    condition:
        any of ($s*)
}
