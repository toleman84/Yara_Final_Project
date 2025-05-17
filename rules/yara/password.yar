rule Password_Hint_Detected
{
    meta:
        description = "Detects password hint in body"
    strings:
        $pw1 = "Password: infected"
        $pw2 = "The password is"
    condition:
        any of them
}
