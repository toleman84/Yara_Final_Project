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

rule Phishing_URL_Detection2
{
    meta:
        description = "Detect suspicious phishing URLs and javascript: URIs"

    strings:
        $http_js = /http[s]?:\/\/[^\s"'<>]+/
        $javascript_uri = "javascript:"
        $script_tag = /<script.*?>.*?<\/script>/ nocase

    condition:
        any of ($http_js, $javascript_uri, $script_tag)
}

rule Phishing_Content_Detection {
    meta:
        author = "Security Team"
        description = "Detecta contenido de phishing en correos electrónicos"
        severity = "high"
        created = "2025-05-16"

    strings:
        // Frases de urgencia
        $urgency1 = "acción inmediata" nocase
        $urgency2 = "urgente" nocase
        $urgency3 = "inmediatamente" nocase
        $urgency4 = "antes de 24 horas" nocase
        $urgency5 = "su cuenta será suspendida" nocase
        $urgency6 = "verificación requerida" nocase

        // Solicitudes de información sensible
        $sensitive_info1 = "confirme sus datos" nocase
        $sensitive_info2 = "actualice su información" nocase
        $sensitive_info3 = "verifique su identidad" nocase
        $sensitive_info4 = "ingrese su contraseña" nocase
        $sensitive_info5 = "proporcione sus credenciales" nocase

        // Amenazas
        $threat1 = "su cuenta será bloqueada" nocase
        $threat2 = "acceso restringido" nocase
        $threat3 = "actividad sospechosa" nocase
        $threat4 = "intento de inicio de sesión" nocase
        $threat5 = "violación de seguridad" nocase

        // Servicios comúnmente suplantados
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
