rule Detect_Zip_File
{
    meta:
        description = "Detects ZIP archive"
    strings:
        $zip = { 50 4B 03 04 }
    condition:
        $zip
}

