rule contains_base64
{
    meta:
        author      = "Jaume Martin (tweaked)"
        description = "Detect long Base64 strings in email body, ignoring headers"

    strings:
        // Match 80+ Base64 chars (20 groups of 4) plus up to two '=' padding
        $b64 = /[A-Za-z0-9+\/]{80,}={0,2}/

        // Ignore the standard MIME header that declares Base64 encoding
        $hdr = /Content-Transfer-Encoding:\s*base64/

    condition:
        // Only trigger when we see a long Base64 blob AND it's not just
        // the header line itself.
        $b64 and not $hdr
}
