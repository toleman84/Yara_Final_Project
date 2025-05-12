rule domain
{
    meta:
        author      = "holberton"
        description = "Match HTTP/HTTPS URLs with at least one dot in the host"

    strings:
        // Match “http://” or “https://”
        // then one or more letters, digits, dots or hyphens
        // then a literal dot + TLD of 2+ letters
        // optional slash + non-space chars
        $url = /https?:\/\/[A-Za-z0-9\.-]+\.[A-Za-z]{2,}(\/\S*)?/

    condition:
        $url
}
