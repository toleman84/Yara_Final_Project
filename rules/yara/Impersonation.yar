rule Impersonation_Detection {
    meta:
        author = "SeMail"
        description = "Detects identity impersonation techniques in emails"
        severity = "high"
        created = "2025-05-16"
    
    strings:
        // High-profile sender names
        $high_profile1 = "CEO" nocase
        $high_profile2 = "Director" nocase
        $high_profile3 = "President" nocase
        $high_profile4 = "Zuckerberg" nocase
        $high_profile5 = "Bezos" nocase
        $high_profile6 = "Nadella" nocase
        $high_profile7 = "Human Resources" nocase
        $high_profile8 = "IT Department" nocase
        
        // Email domain mismatches
        $domain_mismatch1 = /From:.*@.*\.(ru|cn|tk|top|xyz|ml)/ nocase
        $domain_mismatch2 = /From:.*@.*-.*\.com/ nocase
        $domain_mismatch3 = /From:.*@.*\d+\.com/ nocase
        
        // Spoofing techniques
        $spoofing1 = "noreply@" nocase
        $spoofing2 = "no-reply@" nocase
        $spoofing3 = "support@" nocase
        $spoofing4 = "security@" nocase
        $spoofing5 = "service@" nocase
        
        // Authority phrases
        $authority1 = "I am the CEO" nocase
        $authority2 = "as director" nocase
        $authority3 = "under my authority" nocase
        $authority4 = "direct request" nocase
        $authority5 = "executive order" nocase
        
        // Unusual requests
        $unusual_request1 = "urgent transfer" nocase
        $unusual_request2 = "confidential" nocase
        $unusual_request3 = "do not discuss this" nocase
        $unusual_request4 = "handle this personally" nocase
        $unusual_request5 = "sensitive matter" nocase
        
    condition:
        (any of ($high_profile*) and any of ($unusual_request*)) or
        any of ($domain_mismatch*) or
        (any of ($spoofing*) and any of ($authority*)) or
        (any of ($high_profile*) and any of ($authority*))
}
