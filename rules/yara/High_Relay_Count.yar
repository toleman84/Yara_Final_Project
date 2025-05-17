rule High_Relay_Count {
    meta:
        author      = "SeMail"
        description = "Detects excessive Received: hops"
        severity    = "low"
        created     = "2025-05-17"
    strings:
        $rcvd = "Received:" nocase
    condition:
        #rcvd > 5
}
