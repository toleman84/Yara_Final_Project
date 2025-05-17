rule Beacon_Command
{
    strings:
        $cmd = "http://malicious-c2.io/beacon" nocase
        $ref = "get /status" nocase
    condition:
        all of them
}