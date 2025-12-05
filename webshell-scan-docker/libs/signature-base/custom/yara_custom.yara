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