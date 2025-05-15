rule Fake_Job_Offer
{
    strings:
        $link = /hr\.recruitment-portal\.com\/resume\.exe/i
    condition: $link
}