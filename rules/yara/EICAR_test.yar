<<<<<<< HEAD:rules/yara/EICAR_test_string.yar
rule EICAR_Test_File {
=======
rule EICAR_Test_File
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
>>>>>>> 0e38c59ed7c40c9a5708ed7fc6c25df32f7365ef:rules/yara/EICAR_test.yar
    meta:
        description = "Detects EICAR test string in email body"
    
    strings:
        $eicar = "X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    condition:
<<<<<<< HEAD:rules/yara/EICAR_test_string.yar
        $eicar
}
=======
        $e
}
>>>>>>> 0e38c59ed7c40c9a5708ed7fc6c25df32f7365ef:rules/yara/EICAR_test.yar
