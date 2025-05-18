rule Detect_Zip_File
{
    meta:
        description = "Detects ZIP archive"
    strings:
        $zip1 = { 50 4B 03 04 }
        $zip2 = { 50 4B 05 06 }
        $zip3 = { 50 4B 07 08 }
    condition:
        any of them
}

