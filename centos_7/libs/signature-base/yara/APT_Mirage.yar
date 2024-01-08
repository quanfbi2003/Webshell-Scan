import "pe"

rule DarkenCode_APT_MirageStrings : Mirage Family
{
    meta:
        description = "Mirage Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "Neo,welcome to the desert of real." wide ascii
        $ = "/result?hl=en&id=%s"
        
    condition:
       any of them
}

rule DarkenCode_APT_Mirage_APT : APT Backdoor Rat
{
    meta:
        Author      = "Silas Cutler"
        Date        = "yyyy/mm/dd"
        Description = "Malware related to APT campaign"
        Reference   = "Useful link"
    
    strings:
        $a1 = "welcome to the desert of the real"
        $a2 = "Mirage"
        $b = "Encoding: gzip"
        $c = /\/[A-Za-z]*\?hl=en/

    condition: 
        (($a1 or $a2) or $b) and $c
}
