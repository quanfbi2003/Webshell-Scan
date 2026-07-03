/*
  Java/JSP memory-shell rules.
  Focus: Base64-embedded Java bytecode and Resin/Caucho servlet filter backdoors.
*/

rule ANTT_JSP_Base64_Java_Class_Payload {
    meta:
        description = "JSP/Java file embeds Base64 Java class bytecode (CAFEBABE), common memory-shell loader pattern"
        author = "ANTT"
        score = 70
    strings:
        $b64_class = "yv66vgAA" ascii
        $java_str = "String " ascii
        $assign = /[A-Za-z0-9_]{3,64}\s*=\s*\"yv66vgAA[A-Za-z0-9+\/=]{512,}\"/ ascii
    condition:
        filesize < 1048576 and
        ($b64_class and ($assign or $java_str))
}

rule ANTT_Java_MemoryShell_Filter_DynamicClass_AES {
    meta:
        description = "Java servlet filter memory-shell using dynamic defineClass and AES encrypted request payload"
        author = "ANTT"
        score = 90
    strings:
        $filter = "javax/servlet/Filter" ascii
        $request = "javax/servlet/http/HttpServletRequest" ascii
        $response = "javax/servlet/http/HttpServletResponse" ascii
        $define = "defineClass" ascii
        $cipher = "javax/crypto/Cipher" ascii
        $key = "javax/crypto/spec/SecretKeySpec" ascii
        $dofinal = "doFinal" ascii
        $get_header = "getHeader" ascii
        $get_input = "getInputStream" ascii
        $get_session = "getSession" ascii
    condition:
        uint32be(0) == 0xcafebabe and
        $filter and $request and $response and $define and
        ($cipher or $key or $dofinal) and
        2 of ($get_header, $get_input, $get_session)
}

rule ANTT_Java_ZKM_Reflective_ClassLoader_Dropper {
    meta:
        description = "Obfuscated Java class uses reflection/classloader/file staging, often used by JSP memory-shell installers"
        author = "ANTT"
        score = 75
    strings:
        $zkm = "ZKM15.0.0" ascii
        $reflect_method = "java/lang/reflect/Method" ascii
        $reflect_field = "java/lang/reflect/Field" ascii
        $load_class = "loadClass" ascii
        $set_accessible = "setAccessible" ascii
        $declared_field = "getDeclaredField" ascii
        $declared_ctor = "getDeclaredConstructor" ascii
        $system_loader = "getSystemClassLoader" ascii
        $url = "java/net/URL" ascii
        $tmp_file1 = "createNewFile" ascii
        $tmp_file2 = "delete" ascii
    condition:
        uint32be(0) == 0xcafebabe and
        $zkm and $load_class and $set_accessible and
        3 of ($reflect_method, $reflect_field, $declared_field, $declared_ctor, $system_loader, $url) and
        any of ($tmp_file*)
}

rule ANTT_Java_MemoryShell_Caucho_Resin_Filter {
    meta:
        description = "Resin/Caucho memory-shell filter artifacts"
        author = "ANTT"
        score = 95
    strings:
        $caucho_filter = "com/caucho/filters/" ascii
        $servlet_filter = "javax/servlet/Filter" ascii
        $filter_name = "PseudodramaticallyFilter" ascii
        $ua = "User-Agent" ascii
        $aes = "AES" ascii
        $key = "7b35dabef09e402b" ascii
        $define = "defineClass" ascii
    condition:
        uint32be(0) == 0xcafebabe and
        $caucho_filter and $servlet_filter and $define and
        2 of ($filter_name, $ua, $aes, $key)
}
