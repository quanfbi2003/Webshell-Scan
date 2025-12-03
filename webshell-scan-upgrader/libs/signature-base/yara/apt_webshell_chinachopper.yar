<<<<<<< Updated upstream:libs/signature-base/yara/apt_webshell_chinachopper.yar

rule ChinaChopper_Generic {
=======
//===SUCCESS===
rule Neo23x0_apt_webshell_chinachopper_ChinaChopper_Generic {
>>>>>>> Stashed changes:webshell-scan-upgrader/libs/signature-base/yara/apt_webshell_chinachopper.yar
	meta:
		description = "China Chopper Webshells - PHP and ASPX"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
		date = "2015/03/10"
		modified = "2022-10-27"
		id = "2473cef1-88cf-5b76-a87a-2978e6780b4f"
	strings:
		$x_aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe/
		$x_php = /<?php.\@eval\(\$_POST./

		$fp1 = "GET /"
		$fp2 = "POST /"
	condition:
		filesize < 300KB and 1 of ($x*) and not 1 of ($fp*)
}
