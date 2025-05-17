rule Password_Hint_Detected
{
    meta:
        description = "Detects actual password hints or disclosures, avoids generic phrases"
    strings:
        $pw1 = /password\s*[:\-]\s*[a-z0-9!@#\$%^&*()_+=\-]{4,}/ nocase
        $pw2 = /the password is\s+[a-z0-9!@#\$%^&*()_+=\-]{4,}/ nocase
        $pw3 = /password hint/i
        $pw4 = /password[:\-]?\s*hint/i
        $pw5 = /your password is\s+[a-z0-9!@#\$%^&*()_+=\-]{4,}/ nocase
        $pw6 = /password for\s+\w+\s+is\s+[a-z0-9!@#\$%^&*()_+=\-]{4,}/ nocase
        $pw7 = /password reset/i
        $pw8 = /reset your password/i

    condition:
        any of them
}

