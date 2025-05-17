rule Phishing_Content_Detection {
    meta:
        author = "SeMail"
        description = "Detects phishing content in emails"
        severity = "high"
        created = "2025-05-16"
    
    strings:
        // Urgency phrases
        $urgency1 = "immediate action" nocase
        $urgency2 = "urgent" nocase
        $urgency3 = "immediately" nocase
        $urgency4 = "within 24 hours" nocase
        $urgency5 = "your account will be suspended" nocase
        $urgency6 = "verification required" nocase
        
        // Requests for sensitive information
        $sensitive_info1 = "confirm your details" nocase
        $sensitive_info2 = "update your information" nocase
        $sensitive_info3 = "verify your identity" nocase
        $sensitive_info4 = "enter your password" nocase
        $sensitive_info5 = "provide your credentials" nocase
        
        // Threats
        $threat1 = "your account will be locked" nocase
        $threat2 = "restricted access" nocase
        $threat3 = "suspicious activity" nocase
        $threat4 = "login attempt" nocase
        $threat5 = "security breach" nocase
        
        // Commonly impersonated services
        $service1 = "PayPal" nocase
        $service2 = "Microsoft" nocase
        $service3 = "Amazon" nocase
        $service4 = "Apple" nocase
        $service5 = "Netflix" nocase
        $service6 = "Google" nocase
        $service7 = "Facebook" nocase
        $service8 = "Dropbox" nocase
        
    condition:
        (any of ($urgency*) and any of ($sensitive_info*)) or
        (any of ($threat*) and any of ($service*)) or
        (any of ($service*) and any of ($sensitive_info*))
}
