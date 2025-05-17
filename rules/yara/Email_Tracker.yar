rule Email_Tracker_Pixel
{
    meta:
        description = "Detect tracking pixel in email (1x1 transparent gif/png/jpg)"

    strings:
        $tracker_img = /<img[^>]*src=["'].*(pixel|tracker).*["'][^>]*>/ nocase
        $tiny_size = /width=["']?1["']? height=["']?1["']?/ nocase

    condition:
        $tracker_img and $tiny_size
}

