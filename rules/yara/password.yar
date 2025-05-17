rule Password_Hint_Detected
{
    meta:
        author      = "SeMail"
        description = "Detects password hint in body"
        severity    = "low"
        created     = "2025-05-17"
    strings:
        $pw1 = "Password: infected"
        $pw2 = "The password is"
    condition:
        any of them
}
 
      