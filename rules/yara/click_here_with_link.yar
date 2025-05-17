rule Click_Here_With_Link
{
    meta:
        description = "Phrase 'click here' with a following URL within 200 bytes"
        severity    = "medium"
    strings:
        $c = /click here/               nocase
        $h = /https?:\/\/[^\s"']+/     nocase
    condition:
        $c and $h and
        (
            (@c > @h and uint16(@c - @h) < 200) or
            (@h > @c and uint16(@h - @c) < 200)
        )
}

