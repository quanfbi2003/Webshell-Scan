import "pe"

rule DarkenCode_Dar_DarkComet_2
{
    meta:
        description = "DarkComet RAT"
	author = "botherder https://github.com/botherder"

    strings:
        $bot1 = /(#)BOT#OpenUrl/ wide ascii
        $bot2 = /(#)BOT#Ping/ wide ascii
        $bot3 = /(#)BOT#RunPrompt/ wide ascii
        $bot4 = /(#)BOT#SvrUninstall/ wide ascii
        $bot5 = /(#)BOT#URLDownload/ wide ascii
        $bot6 = /(#)BOT#URLUpdate/ wide ascii
        $bot7 = /(#)BOT#VisitUrl/ wide ascii
        $bot8 = /(#)BOT#CloseServer/ wide ascii

        $ddos1 = /(D)DOSHTTPFLOOD/ wide ascii
        $ddos2 = /(D)DOSSYNFLOOD/ wide ascii
        $ddos3 = /(D)DOSUDPFLOOD/ wide ascii

        $keylogger1 = /(A)ctiveOnlineKeylogger/ wide ascii
        $keylogger2 = /(U)nActiveOnlineKeylogger/ wide ascii
        $keylogger3 = /(A)ctiveOfflineKeylogger/ wide ascii
        $keylogger4 = /(U)nActiveOfflineKeylogger/ wide ascii

        $shell1 = /(A)CTIVEREMOTESHELL/ wide ascii
        $shell2 = /(S)UBMREMOTESHELL/ wide ascii
        $shell3 = /(K)ILLREMOTESHELL/ wide ascii

    condition:
        4 of ($bot*) or all of ($ddos*) or all of ($keylogger*) or all of ($shell*)
}

rule DarkenCode_Dar_DarkComet : rat
{
	meta:
		description = "DarkComet" 
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0" 

	strings:
		$a = "#BEGIN DARKCOMET DATA --"
		$b = "#EOF DARKCOMET DATA --"
		$c = "DC_MUTEX-"
		$k1 = "#KCMDDC5#-890"
		$k2 = "#KCMDDC51#-890"

	condition:
		any of them
}

rule DarkenCode_Dar_DarkComet_3
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/DarkComet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		// Versions 2x
		$a1 = "#BOT#URLUpdate"
		$a2 = "Command successfully executed!"
		$a3 = "MUTEXNAME" wide
		$a4 = "NETDATA" wide
		// Versions 3x & 4x & 5x
		$b1 = "FastMM Borland Edition"
		$b2 = "%s, ClassID: %s"
		$b3 = "I wasn't able to open the hosts file"
		$b4 = "#BOT#VisitUrl"
		$b5 = "#KCMDDC"
	condition:
		all of ($a*) or all of ($b*)
}

rule DarkenCode_Dar_DarkComet_Keylogger_File
{
	meta:
		author = "Florian Roth"
		description = "Looks like a keylogger file created by DarkComet Malware"
		date = "25.07.14"
		reference = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		score = 50
	strings:
		$magic = "::"
		$entry = /\n:: [A-Z]/
		$timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/
	condition:
		($magic at 0) and #entry > 10 and #timestamp > 10
}
