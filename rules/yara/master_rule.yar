rule Malicious_Email_Detection {
    meta:
        author = "Security Team"
        description = "Detects common patterns in phishing or malicious emails"
        severity = "high"
        created = "2025-05-17"

    strings:
        // Suspicious URLs (domains or encoded paths)
        $url1 = /http:\/\/.*(phish|malicious|verify|secure-update|alert|freegift|survey|legit-bank|fakebank|spamdomain|example\.com)/ nocase
        $url2 = /http:\/\/.*%[0-9a-f]{2}/ nocase  // Encoded characters in path
        
        // Executable or suspicious attachment indicators
        $file1 = "invoice.exe" nocase
        $file2 = "update.scr" nocase
        $file3 = "attachment.scr" nocase
        $eicar = "X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" nocase

        // Social engineering and urgency
        $social1 = "urgent wire transfer" nocase
        $social2 = "do not reply to this email" nocase
        $social3 = "click here to reset your password" nocase
        $social4 = "account locked" nocase
        $social5 = "you've won" nocase
        $social6 = "congratulations" nocase
        $social7 = "claim your gift" nocase
        $social8 = "mandatory survey" nocase
        $social9 = "update your payment information" nocase
        $social10 = "fill out your W-2" nocase

        // Fake authoritative senders
        $sender1 = "support@" nocase
        $sender2 = "security@" nocase
        $sender3 = "hr@" nocase
        $sender4 = "billing@" nocase
        $sender5 = "admin@" nocase
        $sender6 = "notifications@" nocase
        $sender7 = "recruiter@" nocase
        $sender8 = "rewards@" nocase

    condition:
        any of ($url*) or
        any of ($file*) or
        any of ($eicar) or
        (any of ($sender*) and any of ($social*)) or
        (any of ($social*) and any of ($url*))
}
