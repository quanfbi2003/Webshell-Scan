import "pe"
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/



//===SUCCESS===
rule DarkenCode_Yayih_YayihCode : Yayih Family 
{
    meta:
        description = "Yayih code features"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
    
    strings:
        //  encryption
        $ = { 80 04 08 7A 03 C1 8B 45 FC 80 34 08 19 03 C1 41 3B 0A 7C E9 }
    
    condition:
        any of them
}
//===SUCCESS===
rule DarkenCode_Yayih_YayihStrings : Yayih Family
{
    meta:
        description = "Yayih Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
        
    strings:
        $ = "/bbs/info.asp"
        $ = "\\msinfo.exe"
        $ = "%s\\%srcs.pdf"
        $ = "\\aumLib.ini"

    condition:
       any of them
}
//===SUCCESS===
rule DarkenCode_Yayih_Yayih : Family
{
    meta:
        description = "Yayih"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
        
    condition:
        DarkenCode_Yayih_YayihCode or DarkenCode_Yayih_YayihStrings
}
