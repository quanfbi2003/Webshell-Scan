

rule Neo23x0_gen_TempRacer {
	meta:
		description = "Detects privilege escalation tool - file TempRacer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.darknet.org.uk/2016/03/tempracer-windows-privilege-escalation-tool/"
		date = "2016-03-30"
		hash = "e17d80c4822d16371d75e1440b6ac44af490b71fbee1010a3e8a5eca94d22bb3"
		id = "edba6471-9720-5aad-8c15-386197700c83"
	strings:
		$s1 = "\\obj\\Release\\TempRacer.pdb" ascii
		$s2 = "[+] Injecting into " fullword wide
		$s3 = "net localgroup administrators alex /add" fullword wide
		$s4 = "[+] File: {0} renamed to {1}" fullword wide
		$s5 = "[+] Blocking " fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 25KB and 1 of them ) or ( 4 of them )
}
