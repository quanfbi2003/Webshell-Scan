import "pe"
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/



//===SUCCESS===
rule DarkenCode_MacControl_MacControlCode : MacControl Family 
{
    meta:
        description = "MacControl code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-17"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_Accept = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 3A 20 }
        $L4_AcceptLang = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 2D 4C }
        $L4_Pragma = { C7 ?? 50 72 61 67 C7 ?? 04 6D 61 3A 20 }
        $L4_Connection = { C7 ?? 43 6F 6E 6E C7 ?? 04 65 63 74 69 }
        $GEThgif = { C7 ?? 47 45 54 20 C7 ?? 04 2F 68 2E 67 }
        
    condition:
        all of ($L4*) or $GEThgif
}
//===SUCCESS===
rule DarkenCode_MacControl_MacControlStrings : MacControl Family
{
    meta:
        description = "MacControl Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-17"
        
    strings:
        $ = "HTTPHeadGet"
        $ = "/Library/launched"
        $ = "My connect error with no ip!"
        $ = "Send File is Failed"
        $ = "****************************You Have got it!****************************"
        
    condition:
        any of them
}
//===SUCCESS===
rule DarkenCode_MacControl_MacControl : Family
{
    meta:
        description = "MacControl"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    condition:
        DarkenCode_MacControl_MacControlCode or DarkenCode_MacControl_MacControlStrings
}
