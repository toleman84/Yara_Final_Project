rule Suspicious_Urgency_Language
{
    meta:
        description = "Detect suspicious urgency or password reset keywords"
    strings:
        $password = /password/i
        $reset = /reset/i
        $urgent = /urgent/i
        $immediate = /immediate/i
        $action = /action required/i

    condition:
        2 of ($password, $reset, $urgent, $immediate, $action)
}

