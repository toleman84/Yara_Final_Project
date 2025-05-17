rule Credential_Harvest_Attempt
{
    strings:
        $1 = "Please confirm your password"
        $2 = "http://intranet.company.com/login.php"
    condition:
        all of them
}