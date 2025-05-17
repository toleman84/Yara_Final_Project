rule JS_Malware_Trigger
{
    meta:
        autor = "SeMail"
        description = "Detect malicious JS in HTML emails"
        severity = "medium"
        created  = "2025-05-17"
    strings:
        $script = /<script>.*(download|fetch|eval|XMLHttpRequest|stealCreds).*<\/script>/ nocase
    condition:
        $script
}
