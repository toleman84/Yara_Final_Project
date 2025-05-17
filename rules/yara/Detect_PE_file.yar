rule Detect_PE_File
{
    meta:
        description = "Detect basic PE executable files (EXE, DLL, MSI)"

    strings:
        $mz = {4D 5A}          // 'MZ' DOS header signature
        $pe = {50 45 00 00}    // 'PE\0\0' NT header signature

    condition:
        $mz at 0 and $pe in (0..4096)
}
