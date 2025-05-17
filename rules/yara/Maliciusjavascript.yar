rule JS_Malware_Trigger
{
    meta:
        description = "Detect malicious JS in HTML emails"
    strings:
        $script = /<script>.*(download|fetch|eval|XMLHttpRequest|stealCreds).*<\/script>/ nocase
    condition:
        $script
}
