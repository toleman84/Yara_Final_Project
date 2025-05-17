rule Impersonation_Detection {
    meta:
        author = "Security Team"
        description = "Detecta técnicas de suplantación de identidad en correos electrónicos"
        severity = "high"
        created = "2025-05-16"
    
    strings:
        // Nombres de remitentes de alto perfil
        $high_profile1 = "CEO" nocase
        $high_profile2 = "Director" nocase
        $high_profile3 = "Presidente" nocase
        $high_profile4 = "Zuckerberg" nocase
        $high_profile5 = "Bezos" nocase
        $high_profile6 = "Nadella" nocase
        $high_profile7 = "Recursos Humanos" nocase
        $high_profile8 = "Departamento de TI" nocase
        
        // Discrepancias en el dominio del correo
        $domain_mismatch1 = /From:.*@.*\.(ru|cn|tk|top|xyz|ml)/ nocase
        $domain_mismatch2 = /From:.*@.*-.*\.com/ nocase
        $domain_mismatch3 = /From:.*@.*\d+\.com/ nocase
        
        // Técnicas de spoofing
        $spoofing1 = "noreply@" nocase
        $spoofing2 = "no-reply@" nocase
        $spoofing3 = "support@" nocase
        $spoofing4 = "security@" nocase
        $spoofing5 = "service@" nocase
        
        // Frases de autoridad
        $authority1 = "soy el CEO" nocase
        $authority2 = "como director" nocase
        $authority3 = "en mi autoridad" nocase
        $authority4 = "solicitud directa" nocase
        $authority5 = "orden ejecutiva" nocase
        
        // Solicitudes inusuales
        $unusual_request1 = "transferencia urgente" nocase
        $unusual_request2 = "confidencial" nocase
        $unusual_request3 = "no discuta esto" nocase
        $unusual_request4 = "manéjelo personalmente" nocase
        $unusual_request5 = "asunto delicado" nocase
        
    condition:
        (any of ($high_profile*) and any of ($unusual_request*)) or
        any of ($domain_mismatch*) or
        (any of ($spoofing*) and any of ($authority*)) or
        (any of ($high_profile*) and any of ($authority*))
}
