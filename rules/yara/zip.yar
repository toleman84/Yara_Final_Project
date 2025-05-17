rule Detect_Zip_File
{
    meta:
        author      = "SeMail"
        description = "Detects ZIP archive"
        severity    = "medium"
        created     = "2025-05-17"
    strings:
        $zip = { 50 4B 03 04 }
    condition:
        $zip
}

