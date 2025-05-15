rule Malicious_Macro
{
    strings:
        $a = "autoOpen" nocase 
        $b = "createObject(\"Wscript.Shell\")" nocase
    condition:
        all of them
}