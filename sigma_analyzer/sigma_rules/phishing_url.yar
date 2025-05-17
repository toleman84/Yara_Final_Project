rule Phishing_URL_Detection {
    meta:
        author = "Security Team"
        description = "Detecta URLs de phishing en correos electrónicos"
        severity = "high"
        created = "2025-05-16"
    
    strings:
        // Dominios sospechosos
        $suspicious_domain1 = "paypal-account-verify.com" nocase
        $suspicious_domain2 = "secure-banking-center.com" nocase
        $suspicious_domain3 = "account-verification-service.net" nocase
        $suspicious_domain4 = "document-preview.info" nocase
        $suspicious_domain5 = "invoice-payment-secure.com" nocase
        $suspicious_domain6 = "microsoft-security-alert.com" nocase
        $suspicious_domain7 = "google-drive-share.info" nocase
        $suspicious_domain8 = "dropbox-file-share.net" nocase
        $suspicious_domain9 = "amazon-order-update.info" nocase
        $suspicious_domain10 = "faceb00k-security.com" nocase
        
        // Patrones de URL sospechosos
        $url_pattern1 = /https?:\/\/[^\s\/$.?#].[^\s]*\/(secure|verify|login|account|auth)/ nocase
        $url_pattern2 = /https?:\/\/[^\s\/$.?#].[^\s]*\/(pay|invoice|billing)/ nocase
        
        // Palabras clave en URLs
        $url_keyword1 = "secure-login" nocase
        $url_keyword2 = "account-verify" nocase
        $url_keyword3 = "password-reset" nocase
        $url_keyword4 = "confirm-identity" nocase
        $url_keyword5 = "unusual-activity" nocase
        
    condition:
        any of ($suspicious_domain*) or 
        any of ($url_pattern*) or 
        any of ($url_keyword*)
}
