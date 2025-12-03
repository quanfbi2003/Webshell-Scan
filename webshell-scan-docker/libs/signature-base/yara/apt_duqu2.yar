/*
<<<<<<< Updated upstream:libs/signature-base/yara/apt_duqu2.yar
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-07-02
	Identifier: Duqu2
=======
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
>>>>>>> Stashed changes:webshell-scan-docker/libs/signature-base/yara/apt_duqu2.yar
*/

/* Rule Set ----------------------------------------------------------------- */

<<<<<<< Updated upstream:libs/signature-base/yara/apt_duqu2.yar
rule Duqu2_Sample1 {
	meta:
		description = "Detects malware - Duqu2 (cross-matches with IronTiger malware and Derusbi)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "6b146e3a59025d7085127b552494e8aaf76450a19c249bfed0b4c09f328e564f"
		hash2 = "8e97c371633d285cd8fc842f4582705052a9409149ee67d97de545030787a192"
		hash3 = "2796a119171328e91648a73d95eb297edc220e8768f4bbba5fb7237122a988fc"
		hash4 = "5559fcc93eef38a1c22db66a3e0f9e9f026c99e741cc8b1a4980d166f2696188"
		id = "39ba04f1-df45-5513-ab8f-12097a79cdc7"
	strings:
		$x1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
		$s2 = "MSI.dll" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 40KB and $x1 ) or ( all of them )
}

rule Duqu2_Sample2 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
		hash2 = "5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0"
		hash3 = "6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9"
		hash4 = "c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
		hash5 = "2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b"
		hash6 = "2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da"
		id = "a32f54a3-8656-5592-ac40-17330bfca319"
	strings:
		$s1 = "=<=Q=W=a=g=p=v=|=" fullword ascii
		$s2 = ">#>(>.>3>=>]>d>p>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of ($s*)
}

rule Duqu2_Sample3 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
		id = "c558445f-fbe3-57db-80f7-09a87b097921"
	strings:
		$s1 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and $s1 )
}

rule Duqu2_Sample4 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3"
		id = "8c5ca68d-762c-5d2e-8d37-f58dc66bcae2"
	strings:
		$x1 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s2 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide
		$s3 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide
		$s4 = "ProcessUserAccounts" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 30KB and 1 of ($x*) ) or ( all of them )
}
rule Duqu2_UAs {
	meta:
		description = "Detects Duqu2 Executable based on the specific UAs in the file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "52fe506928b0262f10de31e783af8540b6a0b232b15749d647847488acd0e17a"
		hash2 = "81cdbe905392155a1ba8b687a02e65d611b60aac938e470a76ef518e8cffd74d"
		id = "d82f6351-fab0-5324-850f-dd40a172fceb"
	strings:
		$x1 = "Mozilla/5.0 (Windows NT 6.1; U; ru; rv:5.0.1.6) Gecko/20110501 Firefox/5.0.1 Firefox/5.0.1" fullword wide
		$x2 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.63 Safari/535.7xs5D9rRDFpg2g" fullword wide
		$x3 = "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; FDM; .NET CLR 1.1.4322)" fullword wide
		$x4 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110612 Firefox/6.0a2" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 800KB and all of them )
=======
//===SUCCESS===
rule DarkenCode_APT_Duqu2_apt_duqu2_loaders {

meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect Duqu 2.0 samples"
	last_modified = "2015-06-09"
	version = "1.0"

strings:
	$a1="{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
	$a2="\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
	$a4="\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" wide
	$a5="Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" wide
	$a8="SELECT `Data` FROM `Binary` WHERE `Name`=’%s%i'" wide
	$a9="SELECT `Data` FROM `Binary` WHERE `Name`=’CryptHash%i'" wide
	$a7="SELECT `%s` FROM `%s` WHERE `%s`=’CAData%i'" wide
	
	$b1="MSI.dll"
	$b2="msi.dll"
	$b3="StartAction"

	$c1="msisvc_32@" wide
	$c2="PROP=" wide
	$c3="-Embedding" wide
	$c4="S:(ML;;NW;;;LW)" wide

	$d1 = "NameTypeBinaryDataCustomActionActionSourceTargetInstallExecuteSequenceConditionSequencePropertyValueMicrosoftManufacturer" nocase
	$d2 = {2E 3F 41 56 3F 24 5F 42 69 6E 64 40 24 30 30 58 55 3F 24 5F 50 6D 66 5F 77 72 61 70 40 50 38 43 4C 52 ?? 40 40 41 45 58 58 5A 58 56 31 40 24 24 24 56 40 73 74 64 40 40 51 41 56 43 4C 52 ?? 40 40 40 73 74 64 40 40}

condition:
	( (uint16(0) == 0x5a4d) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) ) and filesize < 100000 )

	or 

	( (uint32(0) == 0xe011cfd0) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) or (any of ($d*)) ) and filesize < 20000000 )
}
//===SUCCESS===
rule DarkenCode_APT_Duqu2_apt_duqu2_drivers {

meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect Duqu 2.0 drivers"
	last_modified = "2015-06-09"
	version = "1.0"

strings:
	$a1="\\DosDevices\\port_optimizer" wide nocase
	$a2="romanian.antihacker"
	$a3="PortOptimizerTermSrv" wide
	$a4="ugly.gorilla1"

	$b1="NdisIMCopySendCompletePerPacketInfo"
	$b2="NdisReEnumerateProtocolBindings"
	$b3="NdisOpenProtocolConfiguration"

condition:
	uint16(0) == 0x5A4D and (any of ($a*) ) and (2 of ($b*)) and filesize < 100000
>>>>>>> Stashed changes:webshell-scan-docker/libs/signature-base/yara/apt_duqu2.yar
}
