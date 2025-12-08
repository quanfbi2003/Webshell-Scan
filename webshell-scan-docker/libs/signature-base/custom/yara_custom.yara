rule ANTT_PHP_Static_Command_Enumeration_Webshell {
    meta:
        description = "Detects PHP webshells that execute static/hardcoded system commands for host enumeration"
        author = "ANTT"
        date = "2025-12-04"

    strings:
        $php_short = /<\?/ nocase       
        $php_long  = "<?php" ascii nocase
        
        // Common command execution functions
        $exec_func = /(system|shell_exec|exec|passthru|popen|proc_open)\s*\(/ ascii nocase
        
        // Typical reconnaissance/enumeration commands
        $cmd_id       = "id" ascii nocase
        $cmd_whoami   = "whoami" ascii nocase
        $cmd_uname    = "uname" ascii nocase
        $cmd_pwd      = "pwd" ascii nocase
        $cmd_ls       = "ls" ascii nocase
        $cmd_ifconfig = "ifconfig" ascii nocase
        $cmd_ip       = "ip " ascii nocase
        $cmd_ps       = "ps " ascii nocase
        $cmd_cat_etc  = "/etc/" ascii
        $cmd_passwd   = "passwd" ascii nocase
        $cmd_hosts    = "hosts" ascii nocase

    condition:
        // File must start with <? or <?php (fixed syntax)
        ($php_short at 0 or $php_long at 0) and
        
        // At least one command execution function in first 1KB
        any of ($exec_func) in (0..1024) and
        
        // Require at least two different enumeration indicators
        (
            2 of ($cmd_id, $cmd_whoami, $cmd_uname, $cmd_pwd, $cmd_ls) or
            ($cmd_cat_etc and any of ($cmd_passwd, $cmd_hosts)) or
            any of ($cmd_ifconfig, $cmd_ip, $cmd_ps)
            // Very short single-command probes like "<?php system('id'); ?>"
            or (filesize < 256 and 1 of ($cmd_id, $cmd_whoami, $cmd_uname))
        ) and
        
        // At least one recon command appears within ~150 bytes after an exec function
        for any i in (1..#exec_func) : (
            any of ($cmd_*) in (@exec_func[i] .. @exec_func[i] + 150)
        )
}

rule ANTT_PHP_Webshell_Phpinfo {
    meta:
        description = "Detects PHP webshells that contain phpinfo()"
        author      = "ANTT"

    strings:
        $php_tag   = /<\?php|<script language="php">/i
        $phpinfo1  = "phpinfo" ascii nocase
        $phpinfo2  = "phpinfo(" ascii nocase
        $phpinfo3  = "phpinfo()" ascii nocase

        // Common keywords found in legitimate PHP code (used for false-positive reduction)
        $legit1 = "function" ascii nocase
        $legit2 = "class" ascii nocase
        $legit3 = "extends" ascii nocase
        $legit4 = "implements" ascii nocase
        $legit5 = "namespace" ascii nocase
        $legit6 = "use " ascii nocase
        $legit7 = "new " ascii nocase

    condition:
        // 1. Must be a PHP file
        any of ($php_tag) and

        // 2. Contains phpinfo() anywhere in the file
        any of ($phpinfo*) and

        // 3. Strong false-positive mitigation
        (
            // Case 1: Very small file → phpinfo() presence is almost certainly malicious
            filesize < 3000

            or

            // Case 2: Medium-sized file but contains very little legitimate code structure
            (
                filesize < 15000 and
                // Too few legitimate PHP keywords → highly suspicious
                #legit1 + #legit2 + #legit3 + #legit4 + #legit5 + #legit6 + #legit7 < 6
            )
        ) and

        not (uint32(0) == 0x3f3c3f3e)
}

rule ANTT_PHP_Obfuscated_Webshell {
    meta:
        description = "Detects obfuscated PHP webshells"
        author = "ANTT"

    strings:
        // PHP tags
        $php_tag = /<\?php|<script language="php">/i
        
        // High-confidence obfuscation patterns (malicious indicators)
        $eval_direct = /@?eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $eval_base64 = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $eval_gzinflate = /eval\s*\(\s*gzinflate\s*\(/ nocase
        $eval_str_rot13 = /eval\s*\(\s*str_rot13\s*\(/ nocase
        $preg_replace_eval = /preg_replace\s*\([^)]*\/e[^)]*\)/ nocase
        $assert_user_input = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $system_user_input = /system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $exec_user_input = /exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $shell_exec_user_input = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        
        // Obfuscation techniques combined with dangerous functions
        $chr_obfuscation = /(chr\([\d]+\)\.){10,}/  // More than 10 chr() concatenations
        $var_func_call = /\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]+\]\s*\(/  // Variable function call from user input
        $double_var = /\$\{\s*\$\{/  // Variable variables
        $b374k_pattern = /'ev'\.'al'|'sys'\.'tem'|'ex'\.'ec'/  // String concatenation obfuscation
        
        // Base64 decode with eval/exec pattern
        $base64_eval = /base64_decode\s*\([^)]+\)\s*[,;]\s*(eval|exec|system|assert|preg_replace)/ nocase
        
        // Legitimate code indicators (exclusion patterns)
        $legit_class = /class\s+\w+\s*(extends|implements)/ nocase
        $legit_function = /function\s+\w+\s*\(/ nocase
        
        // Database operations (common in legitimate code)
        $db_operations = /(mysqli|PDO|mysql_connect|new\s+clsDB)/ nocase

    condition:
        // Must be PHP file
        any of ($php_tag) and
        
        // Require at least ONE high-confidence malicious pattern
        (
            // Direct eval/exec with user input (highest confidence)
            any of ($eval_direct, $eval_base64, $eval_gzinflate, $eval_str_rot13) or
            any of ($preg_replace_eval, $assert_user_input, $system_user_input, $exec_user_input, $shell_exec_user_input) or
            
            // Obfuscation + dangerous function combination
            ($chr_obfuscation and any of ($eval_direct, $system_user_input, $exec_user_input)) or
            ($var_func_call and any of ($eval_direct, $system_user_input)) or
            ($double_var and any of ($eval_direct, $system_user_input)) or
            ($b374k_pattern and any of ($eval_direct, $system_user_input)) or
            $base64_eval
        ) and
        
        // Exclude files with strong legitimate code structure
        (
            // Small files without class/function structure are suspicious
            (filesize < 5000 and #legit_class + #legit_function < 2)
            
            or
            
            // Larger files but with obfuscation + dangerous patterns
            (
                filesize >= 5000 and
                // Must have multiple obfuscation indicators
                (
                    (#chr_obfuscation > 0 and #var_func_call > 0) or
                    (#eval_direct > 0 and #base64_eval > 0) or
                    (#legit_class + #legit_function < 3 and any of ($eval_direct, $system_user_input, $exec_user_input))
                )
            )
        ) and
        
        // Additional exclusion: files with database operations and proper structure are likely legitimate
        not (
            #db_operations > 0 and 
            #legit_class > 0 and 
            #legit_function > 2 and
            filesize > 10000
        )
}

rule ANTT_PHP_Remote_Fetch_Netutil {
    meta:
        description = "Detects tiny PHP droppers that call system/exec to wget/curl net utilities (e.g. nc) to temp paths"
        author = "ANTT"
        date = "2025-12-08"

    strings:
        $php_tag   = /<\?(php)?/ nocase
        $exec_func = /(system|shell_exec|exec|passthru|popen|proc_open)\s*\(/ nocase

        // Remote fetch of binaries using wget/curl over HTTP(S)
        $wget_http = /(wget|curl)\s+http[s]?:\/\// nocase

        // Typical landing paths / tools for quick backdoors
        $net_bins  = /(\/tmp|\/dev\/shm|\/var\/tmp)\/(nc|netcat|bash|sh|python|perl)/ nocase
        $nc_name   = /(nc|netcat)\b/ nocase

    condition:
        // Must be a PHP file
        ($php_tag at 0) and

        // Contains command-exec function and wget/curl fetch close together
        for any i in (1..#exec_func) : (
            $wget_http in (@exec_func[i] .. @exec_func[i] + 120)
        ) and

        // Targeting downloads of network/remote-access tools
        ($net_bins or $nc_name) and

        // Keep focused on short dropper-style files to avoid FP in larger apps
        filesize < 4096
}