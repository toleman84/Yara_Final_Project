rule Phishing_MFA_Fatigue {
    meta:
        author      = "SeMail"
        description = "Detects repeated MFA-approval request spam"
        severity    = "low"
        created     = "2025-05-17"
    strings:
        $mfa1            = "approve sign-in request" nocase
    condition:
        #mfa1 > 3
}