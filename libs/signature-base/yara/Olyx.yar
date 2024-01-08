import "pe"

rule DarkenCode_Oly_OlyxCode : Olyx Family 
{
    meta:
        description = "Olyx code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $six = { C7 40 04 36 36 36 36 C7 40 08 36 36 36 36 }
        $slash = { C7 40 04 5C 5C 5C 5C C7 40 08 5C 5C 5C 5C }
        
    condition:
        any of them
}

rule DarkenCode_Oly_OlyxStrings : Olyx Family
{
    meta:
        description = "Olyx Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "/Applications/Automator.app/Contents/MacOS/DockLight"
       
    condition:
        any of them
}
