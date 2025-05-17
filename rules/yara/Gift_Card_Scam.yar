rule Gift_Card_Scam {
    meta:
        author      = "SeMail"
        description = "Detects gift-card giveaway scams"
        severity    = "medium"
        created     = "2025-05-17"
    strings:
        $gift1           = "you've won" nocase
        $gift2           = "gift card" nocase
        $gift3           = "claim your gift" nocase
    condition:
        any of ($gift*)
}