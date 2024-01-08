import "pe"

rule DarkenCode_Ban_BangatCode : Bangat Family 
{
    meta:
        description = "Bangat code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // dec [ebp + procname], push eax, push edx, call get procaddress
        $ = { FE 4D ?? 8D 4? ?? 50 5? FF }
    
    condition:
        any of them
}

rule DarkenCode_Ban_BangatStrings : Bangat Family
{
    meta:
        description = "Bangat Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $lib1 = "DreatePipe"
        $lib2 = "HetSystemDirectoryA"
        $lib3 = "SeleaseMutex"
        $lib4 = "DloseWindowStation"
        $lib5 = "DontrolService"
        $file = "~hhC2F~.tmp"
        $mc = "~_MC_3~"

    condition:
       all of ($lib*) or $file or $mc
}
