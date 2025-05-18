rule EICAR_Test_File {
    meta:
        author      = "SeMail"
        description = "Detects EICAR antivirus test string"
        severity    = "low"
        created     = "2025-05-17"

    strings:
        $eicar = "X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" nocase

    condition:
        any of ($eicar)
}
