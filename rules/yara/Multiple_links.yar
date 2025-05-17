rule Multiple_Links
{
    meta:
        author      = "SeMail"
        description = "Detect 3 or more distinct HTTP(S) links"
        severity    = "low"
        created     = "2025-05-17"
    strings:
        $link = /https?:\/\/[^\s"']+/ nocase
    condition:
        #link >= 3
}