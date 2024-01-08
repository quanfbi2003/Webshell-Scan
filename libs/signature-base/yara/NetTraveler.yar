import "pe"

rule DarkenCode_Net_NetpassStrings : NetPass Variant {

        meta:
                description = "Identifiers for netpass variant"
                author = "Katie Kleemola"
                last_updated = "2014-05-29"

        strings:
                $exif1 = "Device Protect ApplicatioN" wide
                $exif2 = "beep.sys" wide //embedded exe name
                $exif3 = "BEEP Driver" wide //embedded exe description

                $string1 = "\x00NetPass Update\x00"
                $string2 = "\x00%s:DOWNLOAD\x00"
                $string3 = "\x00%s:UPDATE\x00"
                $string4 = "\x00%s:uNINSTALL\x00"

        condition:
                all of ($exif*) or any of ($string*)

}

rule DarkenCode_Net_NetTravStrings : NetTraveler Family {


	meta:
        	description = "Identifiers for NetTraveler DLL"
		author = "Katie Kleemola"
        	last_updated = "2014-05-20"

	strings:
		//network strings
		$ = "?action=updated&hostid="
		$ = "travlerbackinfo"
		$ = "?action=getcmd&hostid="
		$ = "%s?action=gotcmd&hostid="
		$ = "%s?hostid=%s&hostname=%s&hostip=%s&filename=%s&filestart=%u&filetext="

		//debugging strings
		$ = "\x00Method1 Fail!!!!!\x00"
		$ = "\x00Method3 Fail!!!!!\x00"
		$ = "\x00method currect:\x00"
		$ = /\x00\x00[\w\-]+ is Running!\x00\x00/
		$ = "\x00OtherTwo\x00"

	condition:
		any of them

}

rule DarkenCode_Net_NetTravExports : NetTraveler Family {

	meta:
		description = "Export names for dll component"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
	
	strings:
		//dll component exports
		$ = "?InjectDll@@YAHPAUHWND__@@K@Z"
		$ = "?UnmapDll@@YAHXZ"
		$ = "?g_bSubclassed@@3HA"
		
	condition:
		any of them
}
