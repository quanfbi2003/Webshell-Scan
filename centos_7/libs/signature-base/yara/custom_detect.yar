rule CD2_Detect_PHP_WebShell {
    meta:
        description = "Detects generic PHP web shell"
        author = "Your Name"
        reference = "Your Reference"
    strings:
        $php_tag = "<?php"
        $webshell1 = "base64_decode" wide ascii
        $webshell2 = "eval" wide ascii
    condition:
        $php_tag at 0 and 1 of ($webshell*)
}

rule CD3_HeurBackdoorPHPShellGen {
    meta:
        description = "Yara rule to detect HEUR:Backdoor.PHP.WebShell.gen"
        author = "Bard, Google AI"
        date = "2023-09-22"
        version = "1.0"
    strings:
        $s1 = "system("
        $s2 = "exec("
        $s3 = "popen("
        $s4 = "passthru("
        $s5 = "shell_exec("
        $s6 = "eval("
        $s7 = "escapeshellcmd("
        $s8 = "escapeshellarg("
        $s9 = "backtick("
        $s10 = "proc_open("
    condition:
        any of them
}

rule CD4_HeurBackdoorPHPShellGen2 {
    meta:
        description = "Yara rule to detect HEUR:Backdoor.PHP.WebShell.gen using base64 encoded strings"
        author = "Bard, Google AI"
        date = "2023-09-22"
        version = "1.0"
    strings:
        $s1 = "eval(base64_decode("
    condition:
        any of them
}

rule CD5_HeurBackdoorPHPShellGen3 {
    meta:
        description = "Yara rule to detect HEUR:Backdoor.PHP.WebShell.gen using obfuscated strings"
        author = "Bard, Google AI"
        date = "2023-09-22"
        version = "1.0"
    strings:
        $s1 = "\x65\x76\x61\x6C\x28\x24\x5F\x50\x4F\x53\x5B\x27\x63\x6D\x64\x27\x5D\x29"
        $s2 = "\x65\x78\x65\x63\x28\x24\x5F\x50\x4F\x53\x5B\x27\x63\x6D\x64\x27\x5D\x29"
        $s3 = "\x70\x6F\x70\x65\x6E\x28\x24\x5F\x50\x4F\x53\x5B\x27\x63\x6D\x64\x27\x5D\x29"
        $s4 = "\x70\x61\x73\x73\x74\x68\x72\x75\x28\x24\x5F\x50\x4F\x53\x5B\x27\x63\x6D\x64\x27\x5D\x29"
        $s5 = "\x73\x68\x65\x6C\x6C\x5F\x65\x78\x65\x63\x28\x24\x5F\x50\x4F\x53\x5B\x27\x63\x6D\x64\x27\x5D\x29"
        $s6 = "\x65\x76\x61\x6C\x28\x62\x61\x73\x65\x36\x34\x5f\x64\x65\x63\x6F\x64\x65\x28\x24\x5F\x50\x4F\x53\x5B\x27\x63\x6D\x64\x27\x5D\x29\x29"
    condition:
        any of them
}

rule CD6_Detect_JSP_Webshell {
    meta:
        description = "Detects JSP webshell code"
    strings:
        $jspCode = "<%@ page import=\"java.util.*,java.io.*\"%>"
        $cmdFunction = "if (request.getParameter(\"cmd\") != null) {"
        $execCmd = "Runtime.getRuntime().exec("
    condition:
        $jspCode and $cmdFunction and $execCmd
}
