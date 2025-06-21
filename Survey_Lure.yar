rule Survey_Lure {
    meta:
        author      = "SeMail"
        description = "Detects reward-for-survey lures"
        severity    = "low"
        created     = "2025-05-17"
    strings:
        $survey1         = "complete the survey" nocase
        $survey2         = "win a prize" nocase
    condition:
        any of ($survey*)
}