rule Multiple_Links
{
    meta:
        description = "Detect 3 or more distinct HTTP(S) links"
        severity    = "low"
    strings:
        $link = /https?:\/\/[^\s"']+/ nocase
    condition:
        #link >= 3
}