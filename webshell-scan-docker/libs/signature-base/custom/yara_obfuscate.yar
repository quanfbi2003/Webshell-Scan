/*
  ANTT obfuscation-focused YARA rules (enabled via custom/ directory).
  Complements gen_webshells.yar and yara_custom.yara.
*/

rule ANTT_OBFUSC_Eval_Base64 {
    meta:
        description = "PHP eval on base64_decode payload (common obfuscated webshell)"
        author = "ANTT"
        score = 55
    strings:
        $a = /eval\s*\(\s*base64_decode\s*\(/ ascii wide nocase
        $b = /@eval\s*\(\s*base64_decode\s*\(/ ascii wide nocase
    condition:
        (uint8(0) == 0x3c and uint8(1) == 0x3f) and
        any of ($a, $b) and
        filesize < 512000
}

rule ANTT_OBFUSC_Gzinflate_Chain {
    meta:
        description = "PHP gzinflate/gzuncompress on encoded payload"
        author = "ANTT"
        score = 50
    strings:
        $gz1 = /gzinflate\s*\(/ ascii wide nocase
        $gz2 = /gzuncompress\s*\(/ ascii wide nocase
        $enc = /base64_decode|str_rot13|rawurldecode/ ascii nocase
    condition:
        any of ($gz1, $gz2) and $enc and filesize < 512000
}

rule ANTT_OBFUSC_StrRot13_Eval {
    meta:
        description = "str_rot13 combined with eval/assert"
        author = "ANTT"
        score = 45
    strings:
        $r = /str_rot13\s*\(/ ascii wide nocase
        $e = /eval\s*\(|assert\s*\(/ ascii wide nocase
    condition:
        $r and $e and filesize < 256000
}

rule ANTT_OBFUSC_Chr_Concat_Exec {
    meta:
        description = "chr() concatenation with execution primitive"
        author = "ANTT"
        score = 45
    strings:
        $chr = /(chr\s*\(\s*\d+\s*\)\s*\.?\s*){12,}/ ascii nocase
        $exec = /eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(/ ascii nocase
    condition:
        $chr and $exec and filesize < 128000
}

rule ANTT_OBFUSC_PhpInput_Exec {
    meta:
        description = "php://input or POST with dynamic execution"
        author = "ANTT"
        score = 50
    strings:
        $in1 = "php://input" ascii wide nocase
        $in2 = /\$_(POST|REQUEST|GET)\s*\[/ ascii wide nocase
        $exec = /eval\s*\(|assert\s*\(|preg_replace\s*\([^)]*\/e/ ascii wide nocase
        $dyn = /\$\{/ ascii
    condition:
        any of ($in1, $in2) and any of ($exec, $dyn) and filesize < 256000
}

rule ANTT_OBFUSC_CreateFunction {
    meta:
        description = "create_function webshell pattern"
        author = "ANTT"
        score = 55
    strings:
        $cf = /create_function\s*\(/ ascii wide nocase
        $in = /\$_(POST|REQUEST|GET|COOKIE)/ ascii wide nocase
    condition:
        $cf and $in and filesize < 128000
}

rule ANTT_OBFUSC_Suspicious_Small_PHP {
    meta:
        description = "Tiny PHP with multiple obfuscation primitives (suspicious tier)"
        author = "ANTT"
        score = 35
    strings:
        $php = "<?" ascii
        $o1 = /base64_decode/ ascii nocase
        $o2 = /gzinflate|gzuncompress|str_rot13/ ascii nocase
        $o3 = /eval\s*\(|assert\s*\(/ ascii nocase
        $o4 = /\$_(GET|POST|REQUEST)/ ascii nocase
    condition:
        $php at 0 and filesize < 8192 and 2 of ($o1, $o2, $o3, $o4)
}
