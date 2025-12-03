rule Webshell_Detection_1
{
    strings:
        // Strings from Cat.java
        $cat1 = "class Cat"
        $cat2 = "public static String exec"
        $cat3 = "Runtime.getRuntime().exec"
        $cat4 = "shell"
        $cat5 = "download"

        // Strings from CaiDao-Webshell-Password-LandGrey.jsp
        $caidao1 = "LandGrey"
        $caidao2 = "EC"
        $caidao3 = "GC"
        $caidao4 = "AA"
        $caidao5 = "BB"

        // Strings from back.java
        $back1 = "b4tm4n_rs"
        $back2 = "pt"
        $back3 = "b4tm4n shell : connected"
        $back4 = "Runtime.getRuntime().exec"

        // Strings from hideShell.jsp
        $hide1 = "hiddenWrappers"
        $hide2 = "SpyClassLoader"
        $hide3 = "AttachingWrapper"
        $hide4 = "UploadBean"

        // General strings for command execution in JSP
        $general1 = "Runtime.getRuntime().exec"
        $general2 = "request.getParameter"
        $jsp_tag = "<%"

    condition:
        (2 of ($cat*)) or
        (2 of ($caidao*)) or
        (2 of ($back*)) or
        (2 of ($hide*)) or
        ( $general1 and $general2 and $jsp_tag )
}

rule Webshell_Detection_2
{
    strings:
        // From 2021052101.jsp
        $base64_signature = "yv66vgAAADIA4QgARgcAn"

        // From Cat.java
        $cat_class = "class Cat"
        $cat_exec = "public static String exec"
        $cat_download = "download"
        $cat_shell = "shell"
        $runtime_exec = "Runtime.getRuntime().exec"

        // From CaiDao-Webshell-Password-LandGrey.jsp
        $password = "LandGrey"
        $ec_function = "EC("
        $gc_function = "GC("
        $aa_function = "AA("

        // From back.java
        $back_class = "b4tm4n_rs"
        $back_string = "b4tm4n shell : connected"

        // From hideShell.jsp
        $hide_class1 = "class AttachingWrapper"
        $hide_class2 = "class SpyClassLoader"
        $hide_string = "the hidden JspServletWrapper doesn't exist"

        // From WsCmd.java
        $ws_cmd = "/cmd"
        $ws_cmd_exe = "cmd.exe"
        $ws_bash = "/bin/bash"
        $ws_define = "defineClass"

        // General strings
        $jsp_tag = "<%"
        $request_param = "request.getParameter"

    condition:
        $base64_signature or
        (2 of ($cat_class, $cat_exec, $cat_download, $cat_shell, $runtime_exec)) or
        ($password and ($ec_function or $gc_function or $aa_function)) or
        ($back_class or $back_string) or
        ($hide_class1 or $hide_class2 or $hide_string) or
        ($ws_cmd and ($ws_cmd_exe or $ws_bash) and $ws_define) or
        ($jsp_tag and $runtime_exec and $request_param)
}