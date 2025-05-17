rule Domain_Homoglyph_Detect {
    meta:
        author      = "SeMail"
        description = "Detects basic look-alike (homoglyph) domains"
        severity    = "medium"
        created     = "2025-05-17"
    strings:
        // e.g. examp1e.com (digit 1 in place of l)
        $glyph1          = /[A-Za-z0-9-]+\.[A-Za-z0-9-]*1[A-Za-z0-9-]*\.(com|net|org)/ nocase
    condition:
        any of ($glyph*)
}