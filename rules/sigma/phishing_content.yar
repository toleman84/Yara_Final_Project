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
