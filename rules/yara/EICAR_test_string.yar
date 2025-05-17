rule EICAR_Test_File {
    meta:
        description = "Detects EICAR test string in email body"
    
    strings:
        $eicar = "X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    condition:
        $eicar
}