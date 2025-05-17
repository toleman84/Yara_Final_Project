rule Malicious_Macro_Detection {
    meta:
        author = "Security Team"
        description = "Detecta macros potencialmente maliciosas en documentos adjuntos"
        severity = "high"
        created = "2025-05-16"
    
    strings:
        // Indicadores de macros en documentos
        $macro_indicator1 = "AutoOpen" nocase
        $macro_indicator2 = "AutoExec" nocase
        $macro_indicator3 = "AutoExit" nocase
        $macro_indicator4 = "Document_Open" nocase
        $macro_indicator5 = "Workbook_Open" nocase
        
        // Técnicas comunes en macros maliciosas
        $suspicious_func1 = "Shell" nocase
        $suspicious_func2 = "CreateObject" nocase
        $suspicious_func3 = "WScript.Shell" nocase
        $suspicious_func4 = "PowerShell" nocase
        $suspicious_func5 = "ActiveXObject" nocase
        $suspicious_func6 = "RegWrite" nocase
        $suspicious_func7 = "GetObject" nocase
        
        // Ofuscación y evasión
        $evasion1 = "Chr(" nocase
        $evasion2 = "ChrW(" nocase
        $evasion3 = "StrReverse" nocase
        $evasion4 = "Replace(" nocase
        $evasion5 = "hidden" nocase
        
        // Instrucciones para habilitar macros
        $enable_macro1 = "habilitar macros" nocase
        $enable_macro2 = "enable macros" nocase
        $enable_macro3 = "habilitar contenido" nocase
        $enable_macro4 = "enable content" nocase
        $enable_macro5 = "habilitar edición" nocase
        
    condition:
        (any of ($macro_indicator*) and any of ($suspicious_func*)) or
        (any of ($evasion*) and any of ($suspicious_func*)) or
        any of ($enable_macro*)
}
