rule URL_Encoding_Evasion {
    meta:
        author      = "SeMail"
        description = "Detects percent-encoded URLs used for evasion"
        severity    = "medium"
        created     = "2025-05-17"
    strings:
        $pct1            = /%[0-9A-F]{2}/
    condition:
        any of ($pct*)
}