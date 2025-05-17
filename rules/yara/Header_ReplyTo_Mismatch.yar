rule Header_Domain_Mismatch_Simple {
    meta:
        author      = "SeMail"
        description = "Detects From:/Reply-To: domain mismatches by TLD patterns"
        severity    = "medium"
        created     = "2025-05-17"
    strings:
        // From: in unusual TLDs
        $from_ru   = /From:.*<[^>]+@\w+\.(ru|cn|tk|top|xyz|ml)>/ nocase
        // Reply-To: in common TLDs
        $reply_com = /Reply-To:.*<[^>]+@\w+\.(com|net|org)>/ nocase
    condition:
        $from_ru and $reply_com
}
