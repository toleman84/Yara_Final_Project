rule Suspicious_PDF_Attachment
{
    meta:
        description = "Flags any email containing a PDF attachment"

    strings:
        $pdf_ext = ".pdf"
        $content_type = "application/pdf"

    condition:
        any of ($*)
}

