

rule Neo23x0_cri_ce_enfal_cmstar_debug_msg {
	meta:
		author = "rfalcone"
		description = "Detects the static debug strings within CMSTAR"
		reference = "http://goo.gl/JucrP9"
		hash = "9b9cc7e2a2481b0472721e6b87f1eba4faf2d419d1e2c115a91ab7e7e6fc7f7c"
		date = "5/10/2015"
		id = "2c483f20-4fa8-5246-9dcb-8868db64b6e3"
	strings:
		$d1 = "EEE\x0d\x0a" fullword
		$d2 = "TKE\x0d\x0a" fullword
		$d3 = "VPE\x0d\x0a" fullword
		$d4 = "VPS\x0d\x0a" fullword
		$d5 = "WFSE\x0d\x0a" fullword
		$d6 = "WFSS\x0d\x0a" fullword
		$d7 = "CM**\x0d\x0a" fullword
	condition:
		uint16(0) == 0x5a4d and all of ($d*)
}
