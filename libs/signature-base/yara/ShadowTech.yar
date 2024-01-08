import "pe"

rule DarkenCode_Sha_ShadowTech_2
{
    meta:
        description = "ShadowTech RAT"
	author = "botherder https://github.com/botherder"

    strings:
        $string1 = /\#(S)trings/
        $string2 = /\#(G)UID/
        $string3 = /\#(B)lob/
        $string4 = /(S)hadowTech Rat\.exe/
        $string5 = /(S)hadowTech_Rat/

    condition:
        all of them
}

rule DarkenCode_Sha_ShadowTech
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/ShadowTech"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "ShadowTech" nocase
		$b = "DownloadContainer"
		$c = "MySettings"
		$d = "System.Configuration"
		$newline = "#-@NewLine@-#" wide
		$split = "pSIL" wide
		$key = "ESIL" wide

	condition:
		4 of them
}
