rule Malicious_Attachment_Detection {
    meta:
        author = "Security Team"
        description = "Detecta archivos adjuntos potencialmente maliciosos en correos electrónicos"
        severity = "high"
        created = "2025-05-16"
    
    strings:
        // Extensiones de archivo sospechosas
        $ext_exe = ".exe" nocase
        $ext_scr = ".scr" nocase
        $ext_bat = ".bat" nocase
        $ext_cmd = ".cmd" nocase
        $ext_js = ".js" nocase
        $ext_vbs = ".vbs" nocase
        $ext_ps1 = ".ps1" nocase
        $ext_jar = ".jar" nocase
        
        // Nombres de archivo sospechosos
        $filename1 = "security_update" nocase
        $filename2 = "invoice" nocase
        $filename3 = "document" nocase
        $filename4 = "urgent" nocase
        $filename5 = "confidential" nocase
        
        // Patrones de contenido sospechoso en archivos adjuntos
        $content1 = "powershell -e" nocase
        $content2 = "cmd.exe /c" nocase
        $content3 = "rundll32" nocase
        $content4 = "regsvr32" nocase
        $content5 = "wscript" nocase
        $content6 = "cscript" nocase
        
    condition:
        (any of ($ext_*) and any of ($filename*)) or
        any of ($content*)
}
