rule URL_Shortener_Abuse {
    meta:
        author      = "SeMail"
        description = "Detects use of URL-shortening services"
        severity    = "medium"
        created     = "2025-05-17"
    strings:
        $short1          = "bit.ly/" nocase
        $short2          = "tinyurl.com/" nocase
        $short3          = "t.co/" nocase
        $short4          = "goo.gl/" nocase
    condition:
        any of ($short*)
}