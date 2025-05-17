rule executable_attachment
{
    meta:
        description = "Detects common executable file extensions in attachments"
        author = "Manus AI"
        date = "2025-04-30"

    strings:
        // Look for filename patterns in Content-Disposition headers or similar
        $filename_exe = /filename=".*\.exe"/ nocase
        $filename_dll = /filename=".*\.dll"/ nocase
        $filename_bat = /filename=".*\.bat"/ nocase
        $filename_scr = /filename=".*\.scr"/ nocase
        $filename_msi = /filename=".*\.msi"/ nocase
        $filename_vbs = /filename=".*\.vbs"/ nocase

        // Optionally, look for magic bytes (PE header for exe/dll)
        $magic_mz = { 4D 5A } // MZ header

    condition:
        (any of ($filename*)) or ($magic_mz at 0)
}

