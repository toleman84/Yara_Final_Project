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