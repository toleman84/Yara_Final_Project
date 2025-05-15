rule Phishing_Login_Link
{
    strings:
        $link = "http://login.security-checkup.com" nocase
        $text = "your account is at risk" nocase
    condition:
        all of them
}