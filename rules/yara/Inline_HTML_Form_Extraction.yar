rule Inline_HTML_Form_Extraction {
    meta:
        author      = "SeMail"
        description = "Detects inline HTML forms in email bodies"
        severity    = "high"
        created     = "2025-05-17"
    strings:
        // Match `<form` tags with an action attribute, up to the closing ‘>’
        $form1 = /<form\s+action=[^>]*>/i
    condition:
        any of ($form*)
}
