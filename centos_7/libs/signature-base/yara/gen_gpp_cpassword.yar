

rule Neo23x0_gen_Groups_cpassword {
    meta:
        description = "Groups XML contains cpassword value, which is decrypted password - key is in MSDN http://goo.gl/mHrC8P"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://www.grouppolicy.biz/2013/11/why-passwords-in-group-policy-preference-are-very-bad/"
        date = "2015-09-08"
        score = 50
        id = "37036df9-871f-5ecd-acac-6a064d298115"
    strings:
        $s1 = / cpassword=\"[^\"]/ ascii
        $s2 = " changeLogon=" ascii
        $s3 = " description=" ascii
        $s4 = " acctDisabled=" ascii
    condition:
        uint32be(0) == 0x3C3F786D  /* <?xm */
        and filesize < 1000KB
        and all of ($s*)  
}
