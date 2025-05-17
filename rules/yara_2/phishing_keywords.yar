rule phishing_keywords
{
    meta:
        description = "Detects common phishing keywords in email body"
        author = "Manus AI"
        date = "2025-04-30"

    strings:
        $keyword1 = "verify your account"
        $keyword2 = "update your payment details"
        $keyword3 = "confirm your credentials"
        $keyword4 = "urgent action required"
        $keyword5 = "security alert"
        $keyword6 = "suspicious login attempt"

    condition:
        any of ($keyword*)
}

