rule Scam_Invoice_Pattern
{
    strings:
        $invoice = "please see attached invoice" nocase
        $bank = "wire to account" nocase
    condition:
        all of them
}