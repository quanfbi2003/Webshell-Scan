import "pe"

rule DarkenCode_Ura_urausy_skype_dat {
	meta:
		author = "AlienVault Labs"
		description = "Yara rule to match against memory of processes infected by Urausy skype.dat"
	strings:
		$a = "skype.dat" ascii wide
		$b = "skype.ini" ascii wide
		$win1 = "CreateWindow"
		$win2 = "YIWEFHIWQ" ascii wide
		$desk1 = "CreateDesktop"
		$desk2 = "MyDesktop" ascii wide
	condition:
		$a and $b and (all of ($win*) or all of ($desk*))
}
