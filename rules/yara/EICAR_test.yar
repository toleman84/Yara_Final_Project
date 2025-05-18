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

rule EICAR_Test
{
    meta:
        description = "Detect EICAR antivirus test string"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule EICAR_Test_String
{
    meta:
        description = "Detect EICAR antivirus test string"
        severity    = "high"
    strings:
        $e = "X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $e
}

