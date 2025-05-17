rule Phishing_Spear_Bait {
    meta:
        author      = "SeMail"
        description = "Detects spear-phishing: personalized greeting + finance lure"
        severity    = "medium"
        created     = "2025-05-17"
    strings:
        // Personalized greeting
        $personal1       = /Hi\s+[A-Z][a-z]+,/ 
        $personal2       = /Dear\s+[A-Z][a-z]+/ 
        // Finance keywords
        $finance1        = "invoice" nocase
        $finance2        = "wire transfer" nocase
        $finance3        = "payment required" nocase
    condition:
        any of ($personal*) and any of ($finance*)
}