rule Ransomware_Note
{
    strings:
        $msg = /your files have been encrypted.?/ nocase
        $btc = /send\s+1\s+btc\s+to/       nocase
    condition:
        all of them
}
