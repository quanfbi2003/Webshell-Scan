import "pe"

rule DarkenCode_Mis_tran_duy_linh
{
meta:
	author = "@patrickrolsen"
	maltype = "Misc."
	version = "0.2"
	reference = "8fa804105b1e514e1998e543cd2ca4ea, 872876cfc9c1535cd2a5977568716ae1, etc." 
	date = "01/03/2014"
strings:
	$doc = {D0 CF 11 E0} //DOCFILE0
	$string1 = "Tran Duy Linh" fullword
	$string2 = "DLC Corporation" fullword
condition:
    ($doc at 0) and (all of ($string*))
}

rule DarkenCode_Mis_misc_iocs
{
meta:
	author = "@patrickrolsen"
	maltype = "Misc."
	version = "0.1"
	reference = "N/A" 
strings:
	$doc = {D0 CF 11 E0} //DOCFILE0
	$s1 = "dw20.exe"
	$s2 = "cmd /"
condition:
    ($doc at 0) and (1 of ($s*))
}

rule DarkenCode_Mis_malicious_LNK_files
{
meta:
	author = "@patrickrolsen"
strings:
	$magic = {4C 00 00 00 01 14 02 00} // L.......
	$s1 = "\\RECYCLER\\" wide
	$s2 = "%temp%" wide
	$s3 = "%systemroot%\\system32\\cmd.exe" wide
	//$s4 = "./start" wide
	$s5 = "svchost.exe" wide
	$s6 = "lsass.exe" wide
	$s7 = "csrss.exe" wide
	$s8 = "winlogon.exe" wide
	//$s9 = "%cd%" wide
	$s10 = "%appdata%" wide
	$s11 = "%programdata%" wide
	$s12 = "%localappdata%" wide
	$s13 = ".cpl" wide
condition:
	($magic at 0) and any of ($s*)
}

rule DarkenCode_Mis_memory_pivy

{
   meta:
	  author = "https://github.com/jackcr/"
   strings:
      $a = {00 00 00 00 00 00 00 00 00 00 00 53 74 75 62 50 61 74 68 00} // presence of pivy in memory

   condition: 
      any of them

}

rule DarkenCode_Mis_memory_shylock

{
   meta:
	  author = "https://github.com/jackcr/"

   strings:
      $a = /pipe\\[A-F0-9]{32}/     //Named pipe created by the malware
      $b = /id=[A-F0-9]{32}/     //Portion or the uri beacon
      $c = /MASTER_[A-F0-9]{32}/     //Mutex created by the malware
      $d = "***Load injects by PIPE (%s)" //String found in binary
      $e = "***Load injects url=%s (%s)" //String found in binary
      $f = "*********************** Ping Ok ************************" //String found in binary
      $g = "*** LOG INJECTS *** %s"     //String found in binary

   condition: 
      any of them

}

rule DarkenCode_Mis_TrojanDownloader {
	meta:
		description = "Trojan Downloader - Flash Exploit Feb15"
		author = "Florian Roth"
		reference = "http://goo.gl/wJ8V1I"
		date = "2015/02/11"
		hash = "5b8d4280ff6fc9c8e1b9593cbaeb04a29e64a81e"
		score = 60
	strings:
		$x1 = "Hello World!" fullword ascii
		$x2 = "CONIN$" fullword ascii
			
		$s6 = "GetCommandLineA" fullword ascii
		$s7 = "ExitProcess" fullword ascii
		$s8 = "CreateFileA" fullword ascii						

		$s5 = "SetConsoleMode" fullword ascii		
		$s9 = "TerminateProcess" fullword ascii	
		$s10 = "GetCurrentProcess" fullword ascii
		$s11 = "UnhandledExceptionFilter" fullword ascii
		$s3 = "user32.dll" fullword ascii
		$s16 = "GetEnvironmentStrings" fullword ascii
		$s2 = "GetLastActivePopup" fullword ascii		
		$s17 = "GetFileType" fullword ascii
		$s19 = "HeapCreate" fullword ascii
		$s20 = "VirtualFree" fullword ascii
		$s21 = "WriteFile" fullword ascii
		$s22 = "GetOEMCP" fullword ascii
		$s23 = "VirtualAlloc" fullword ascii
		$s24 = "GetProcAddress" fullword ascii
		$s26 = "FlushFileBuffers" fullword ascii
		$s27 = "SetStdHandle" fullword ascii
		$s28 = "KERNEL32.dll" fullword ascii
	condition:
		$x1 and $x2 and ( all of ($s*) ) and filesize < 35000
}

rule DarkenCode_Mis_Embedded_EXE_Cloaking {
        meta:
                description = "Detects an embedded executable in a non-executable file"
                author = "Florian Roth"
                date = "2015/02/27"
                score = 80
        strings:
                $noex_png = { 89 50 4E 47 }
                $noex_pdf = { 25 50 44 46 }
                $noex_rtf = { 7B 5C 72 74 66 31 }
                $noex_jpg = { FF D8 FF E0 }
                $noex_gif = { 47 49 46 38 }
                $mz  = { 4D 5A }
                $a1 = "This program cannot be run in DOS mode"
                $a2 = "This program must be run under Win32"
        condition:
                (
                        ( $noex_png at 0 ) or
                        ( $noex_pdf at 0 ) or
                        ( $noex_rtf at 0 ) or
                        ( $noex_jpg at 0 ) or
                        ( $noex_gif at 0 )
                )
                and
                for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}

rule DarkenCode_Mis_Cloaked_as_JPG {
        meta:
                description = "Detects a cloaked file as JPG"
                author = "Florian Roth (eval section from Didier Stevens)"
                date = "2015/02/29"
                score = 70
        strings:
                $ext = "extension: .jpg"
        condition:
                $ext and uint16be(0x00) != 0xFFD8
}

rule DarkenCode_Mis_WindowsCredentialEditor
{
    meta: 
    	description = "Windows Credential Editor" threat_level = 10 score = 90
    strings:
		$a = "extract the TGT session key"
		$b = "Windows Credentials Editor"
    condition: 
    	$a or $b
}

rule DarkenCode_Mis_Amplia_Security_Tool
{
    meta: 
		description = "Amplia Security Tool" 
		score = 60
		nodeepdive = 1
    strings:
		$a = "Amplia Security"
		$b = "Hernan Ochoa"
		$c = "getlsasrvaddr.exe"
		$d = "Cannot get PID of LSASS.EXE"
		$e = "extract the TGT session key"
		$f = "PPWDUMP_DATA"
    condition: 1 of them
}

rule DarkenCode_Mis_perlbot_pl {
	meta:
		description = "Semi-Auto-generated  - file perlbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7e4deb9884ffffa5d82c22f8dc533a45"
	strings:
		$s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")"
		$s1 = "#Acesso a Shel - 1 ON 0 OFF"
	condition:
		1 of them
}

rule DarkenCode_Mis_php_backdoor_php {
	meta:
		description = "Semi-Auto-generated  - file php-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
	strings:
		$s0 = "http://michaeldaw.org   2006"
		$s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
		$s3 = "coded by z0mbie"
	condition:
		1 of them
}

rule DarkenCode_Mis_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_php {
	meta:
		description = "Semi-Auto-generated  - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"
	strings:
		$s0 = "<option value=\"cat /var/cpanel/accounting.log\">/var/cpanel/accounting.log</opt"
		$s1 = "Liz0ziM Private Safe Mode Command Execuriton Bypass"
		$s2 = "echo \"<b><font color=red>Kimim Ben :=)</font></b>:$uid<br>\";" fullword
	condition:
		1 of them
}

rule DarkenCode_Mis_Nshell__1__php_php {
	meta:
		description = "Semi-Auto-generated  - file Nshell (1).php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "973fc89694097a41e684b43a21b1b099"
	strings:
		$s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($"
		$s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword
	condition:
		1 of them
}

rule DarkenCode_Mis_shankar_php_php {
	meta:
		description = "Semi-Auto-generated  - file shankar.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "6eb9db6a3974e511b7951b8f7e7136bb"
	strings:
		$sAuthor = "ShAnKaR"
		$s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input"
		$s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b"
	condition:
		1 of ($s*) and $sAuthor
}

rule DarkenCode_Mis_Casus15_php_php {
	meta:
		description = "Semi-Auto-generated  - file Casus15.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"
	strings:
		$s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
		$s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
		$s3 = "value='Calistirmak istediginiz "
	condition:
		1 of them
}

rule DarkenCode_Mis_small_php_php {
	meta:
		description = "Semi-Auto-generated  - file small.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "fcee6226d09d150bfa5f103bee61fbde"
	strings:
		$s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
		$s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1"
		$s4 = "@ini_set('error_log',NULL);" fullword
	condition:
		2 of them
}

rule DarkenCode_Mis_shellbot_pl {
	meta:
		description = "Semi-Auto-generated  - file shellbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b2a883bc3c03a35cfd020dd2ace4bab8"
	strings:
		$s0 = "ShellBOT"
		$s1 = "PacktsGr0up"
		$s2 = "CoRpOrAtIoN"
		$s3 = "# Servidor de irc que vai ser usado "
		$s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"
	condition:
		2 of them
}

rule DarkenCode_Mis_fuckphpshell_php {
	meta:
		description = "Semi-Auto-generated  - file fuckphpshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "554e50c1265bb0934fcc8247ec3b9052"
	strings:
		$s0 = "$succ = \"Warning! "
		$s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!"
		$s2 = "\\*=-- MEMBERS AREA --=*/"
		$s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o"
	condition:
		2 of them
}

rule DarkenCode_Mis_ngh_php_php {
	meta:
		description = "Semi-Auto-generated  - file ngh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c372b725419cdfd3f8a6371cfeebc2fd"
	strings:
		$s0 = "Cr4sh_aka_RKL"
		$s1 = "NGH edition"
		$s2 = "/* connectback-backdoor on perl"
		$s3 = "<form action=<?=$script?>?act=bindshell method=POST>"
		$s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r"
	condition:
		1 of them
}

rule DarkenCode_Mis_jsp_reverse_jsp {
	meta:
		description = "Semi-Auto-generated  - file jsp-reverse.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8b0e6779f25a17f0ffb3df14122ba594"
	strings:
		$s0 = "// backdoor.jsp"
		$s1 = "JSP Backdoor Reverse Shell" 
		$s2 = "http://michaeldaw.org" 
	condition:
		1 of them
}

rule DarkenCode_Mis_Tool_asp {
	meta:
		description = "Semi-Auto-generated  - file Tool.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8febea6ca6051ae5e2ad4c78f4b9c1f2"
	strings:
		$s0 = "mailto:rhfactor@antisocial.com"
		$s2 = "?raiz=root"
		$s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE"
		$s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0"
	condition:
		2 of them
}

rule DarkenCode_Mis_NT_Addy_asp {
	meta:
		description = "Semi-Auto-generated  - file NT Addy.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2e0d1bae844c9a8e6e351297d77a1fec"
	strings:
		$s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
		$s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
		$s4 = "RAW D.O.S. COMMAND INTERFACE"
	condition:
		1 of them
}

rule DarkenCode_Mis_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php {
	meta:
		description = "Semi-Auto-generated  - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "089ff24d978aeff2b4b2869f0c7d38a3"
	strings:
		$s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend"
		$s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
		$s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora"
	condition:
		1 of them
}

rule DarkenCode_Mis_RemExp_asp {
	meta:
		description = "Semi-Auto-generated  - file RemExp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"
	strings:
		$s0 = "<title>Remote Explorer</title>"
		$s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi"
		$s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
	condition:
		2 of them
}

rule DarkenCode_Mis_phvayvv_php_php {
	meta:
		description = "Semi-Auto-generated  - file phvayvv.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "35fb37f3c806718545d97c6559abd262"
	strings:
		$s0 = "{mkdir(\"$dizin/$duzenx2\",777)"
		$s1 = "$baglan=fopen($duzkaydet,'w');"
		$s2 = "PHVayv 1.0"
	condition:
		1 of them
}

rule DarkenCode_Mis_klasvayv_asp {
	meta:
		description = "Semi-Auto-generated  - file klasvayv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b3e64bf8462fc3d008a3d1012da64ef"
	strings:
		$s1 = "set aktifklas=request.querystring(\"aktifklas\")"
		$s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>"
		$s3 = "<font color=\"#858585\">www.aventgrup.net"
		$s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT"
	condition:
		1 of them
}

rule DarkenCode_Mis_r57shell_php_php {
	meta:
		description = "Semi-Auto-generated  - file r57shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d28445de424594a5f14d0fe2a7c4e94f"
	strings:
		$s0 = "r57shell" fullword 
		$s1 = " else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx "
		$s2 = "RusH security team"
		$s3 = "'ru_text12' => 'back-connect"
	condition:
		1 of them
}

rule DarkenCode_Mis_rst_sql_php_php {
	meta:
		description = "Semi-Auto-generated  - file rst_sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0961641a4ab2b8cb4d2beca593a92010"
	strings:
		$s0 = "C:\\tmp\\dump_"
		$s1 = "RST MySQL"
		$s2 = "http://rst.void.ru"
		$s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';"
	condition:
		2 of them
}

rule DarkenCode_Mis_wh_bindshell_py {
	meta:
		description = "Semi-Auto-generated  - file wh_bindshell.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "fab20902862736e24aaae275af5e049c"
	strings:
		$s0 = "#Use: python wh_bindshell.py [port] [password]"
		$s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
		$s3 = "#bugz: ctrl+c etc =script stoped=" fullword
	condition:
		1 of them
}

rule DarkenCode_Mis_lurm_safemod_on_cgi {
	meta:
		description = "Semi-Auto-generated  - file lurm_safemod_on.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5ea4f901ce1abdf20870c214b3231db3"
	strings:
		$s0 = "Network security team :: CGI Shell" fullword
		$s1 = "#########################<<KONEC>>#####################################" fullword
		$s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
	condition:
		1 of them
}

rule DarkenCode_Mis_c99madshell_v2_0_php_php {
	meta:
		description = "Semi-Auto-generated  - file c99madshell_v2.0.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d27292895da9afa5b60b9d3014f39294"
	strings:
		$s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef"
	condition:
		all of them
}

rule DarkenCode_Mis_backupsql_php_often_with_c99shell {
	meta:
		description = "Semi-Auto-generated  - file backupsql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ab1a06ab1a1fe94e3f3b7f80eedbc12f"
	strings:
		$s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ."
		$s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
	condition:
		all of them
}

rule DarkenCode_Mis_uploader_php_php {
	meta:
		description = "Semi-Auto-generated  - file uploader.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0b53b67bb3b004a8681e1458dd1895d0"
	strings:
		$s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
		$s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
		$s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
	condition:
		2 of them
}

rule DarkenCode_Mis_telnet_pl {
	meta:
		description = "Semi-Auto-generated  - file telnet.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "dd9dba14383064e219e29396e242c1ec"
	strings:
		$s0 = "W A R N I N G: Private Server"
		$s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   "
	condition:
		all of them
}

rule DarkenCode_Mis_w3d_php_php {
	meta:
		description = "Semi-Auto-generated  - file w3d.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "987f66b29bfb209a0b4f097f84f57c3b"
	strings:
		$s0 = "W3D Shell"
		$s1 = "By: Warpboy"
		$s2 = "No Query Executed"
	condition:
		2 of them
}

rule DarkenCode_Mis_rtf_yahoo_ken
{
meta:
	author = "@patrickrolsen"
	maltype = "Yahoo Ken"
	filetype = "RTF"
	version = "0.1"
	description = "Test rule"
	date = "2013-12-14"
strings:
	$magic1 = { 7b 5c 72 74 30 31 } // {\rt01
	$magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
	$magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
	$author1 = { 79 61 68 6f 6f 20 6b 65 63 } // "yahoo ken"
condition:
	($magic1 or $magic2 or $magic3 at 0) and $author1
}

rule DarkenCode_Mis_ZXProxy
{
meta:
	author = "ThreatConnect Intelligence Research Team"
	
strings:
	$C = "\\Control\\zxplug" nocase wide ascii
	$h = "http://www.facebook.com/comment/update.exe" wide ascii
	$S = "Shared a shell to %s:%s Successfully" nocase wide ascii
condition:
	any of them
}

rule DarkenCode_Mis_OrcaRAT
{
    meta:
        Author      = "PwC Cyber Threat Operations"
        Date        = "2014/10/20" 
        Description = "Strings inside"
        Reference   = "http://pwc.blogs.com/cyber_security_updates/2014/10/orcarat-a-whale-of-a-tale.html"

    strings:
        $MZ = "MZ"
        $apptype1 = "application/x-ms-application"
        $apptype2 = "application/x-ms-xbap"
        $apptype3 = "application/vnd.ms-xpsdocument"
        $apptype4 = "application/xaml+xml"
        $apptype5 = "application/x-shockwave-flash"
        $apptype6 = "image/pjpeg"
        $err1 = "Set return time error =   %d!"
        $err2 = "Set return time   success!"
        $err3 = "Quit success!"

    condition:
        $MZ at 0 and filesize < 500KB and (all of ($apptype*) and 1 of ($err*))
}

rule DarkenCode_Mis_mimikatz
{
	meta:
		description		= "mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Benjamin DELPY (gentilkiwi)"
	strings:
		$exe_x86_1		= { 89 71 04 89 [0-3] 30 8d 04 bd }
		$exe_x86_2		= { 89 79 04 89 [0-3] 38 8d 04 b5 }
		
		$exe_x64_1		= { 4c 03 d8 49 [0-3] 8b 03 48 89 }
		$exe_x64_2		= { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

		$dll_1			= {	c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2			= { c7 0? 10 02 00 00 ?? 89 4? }
		
		$sys_x86		= { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64		= { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }
	condition:
		(all of ($exe_x86_*)) or (all of ($exe_x64_*)) or (all of ($dll_*)) or (any of ($sys_*))
}

rule DarkenCode_Mis_mimikatz_lsass_mdmp
{
	meta:
		description		= "LSASS minidump file for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
	strings:
		$lsass			= "System32\\lsass.exe"	wide nocase
	condition:
		(uint32(0) == 0x504d444d) and $lsass
}

rule DarkenCode_Mis_mimikatz_kirbi_ticket
{
	meta:
		description		= "KiRBi ticket for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
	strings:
		$asn1			= { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }
	condition:
		$asn1 at 0
}

rule DarkenCode_Mis_wce
{
	meta:
		description		= "wce"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Hernan Ochoa (hernano)"
	strings:
		$hex_legacy		= { 8b ff 55 8b ec 6a 00 ff 75 0c ff 75 08 e8 [0-3] 5d c2 08 00 }
		$hex_x86		= { 8d 45 f0 50 8d 45 f8 50 8d 45 e8 50 6a 00 8d 45 fc 50 [0-8] 50 72 69 6d 61 72 79 00 }
		$hex_x64		= { ff f3 48 83 ec 30 48 8b d9 48 8d 15 [0-16] 50 72 69 6d 61 72 79 00 }
	condition:
		any of them
}

rule DarkenCode_Mis_EmiratesStatement 
{
	meta:
		Author 		= "Christiaan Beek"
		Date 		= "2013-06-30"
		Description = "Credentials Stealing Attack"
		Reference 	= "https://blogs.mcafee.com/mcafee-labs/targeted-campaign-steals-credentials-in-gulf-states-and-caribbean"
		
		hash0 = "0e37b6efe5de1cc9236017e003b1fc37"
		hash1 = "a28b22acf2358e6aced43a6260af9170"
		hash2 = "6f506d7adfcc2288631ed2da37b0db04"
		hash3 = "8aebade47dc1aa9ac4b5625acf5ade8f"
	
	strings:
		$string0 = "msn.klm"
		$string1 = "wmsn.klm"
		$string2 = "bms.klm"
	
	condition:
		all of them
}

rule DarkenCode_Mis_PUP_InstallRex_AntiFWb {
	meta:
		description = "Malware InstallRex / AntiFW"
		author = "Florian Roth"
		date = "2015-05-13"
		hash = "bb5607cd2ee51f039f60e32cf7edc4e21a2d95cd"
		score = 65
	strings:
		$s4 = "Error %u while loading TSU.DLL %ls" fullword ascii
		$s7 = "GetModuleFileName() failed => %u" fullword ascii
		$s8 = "TSULoader.exe" fullword wide
		$s15 = "\\StringFileInfo\\%04x%04x\\Arguments" fullword wide
		$s17 = "Tsu%08lX.dll" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule DarkenCode_Mis_Win7Elevatev2 {
	meta:
		description = "Detects Win7Elevate - Windows UAC bypass utility"
		author = "Florian Roth"
		reference = "http://www.pretentiousname.com/misc/W7E_Source/Win7Elevate_Inject.cpp.html"
		date = "2015-05-14"
		hash1 = "4f53ff6a04e46eda92b403faf42219a545c06c29" /* x64 */
		hash2 = "808d04c187a524db402c5b2be17ce799d2654bd1" /* x86 */
		score = 60
	strings:
		$x1 = "This program attempts to bypass Windows 7's default UAC settings to run " wide
		$x2 = "Win7ElevateV2\\x64\\Release\\" ascii
		$x3 = "Run the command normally (without code injection)" wide	
		$x4 = "Inject file copy && elevate command" fullword wide
		$x5 = "http://www.pretentiousname.com/misc/win7_uac_whitelist2.html" fullword wide
		$x6 = "For injection, pick any unelevated Windows process with ASLR on:" fullword wide
		
		$s1 = "\\cmd.exe" wide
		$s2 = "runas" wide
		$s3 = "explorer.exe" wide
		$s4 = "Couldn't load kernel32.dll" wide
		$s5 = "CRYPTBASE.dll" wide
		$s6 = "shell32.dll" wide
		$s7 = "ShellExecuteEx" ascii
		$s8 = "COMCTL32.dll" ascii 
		$s9 = "ShellExecuteEx" ascii
		$s10 = "HeapAlloc" ascii
	condition:
		uint16(0) == 0x5a4d and ( 1 of ($x*) or all of ($s*) )
}

rule DarkenCode_Mis_UACME_Akagi {
	meta:
		description = "Rule to detect UACMe - abusing built-in Windows AutoElevate backdoor"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/UACME"
		date = "2015-05-14"
		hash1 = "edd2138bbd9e76c343051c6dc898054607f2040a"
		hash2 = "e3a919ccc2e759e618208ededa8a543954d49f8a"
		score = 60
	strings:
		$x1 = "UACMe injected, Fubuki at your service." wide fullword
		$x3 = "%temp%\\Hibiki.dll" fullword wide
		$x4 = "[UCM] Cannot write to the target process memory." fullword wide
		
		$s1 = "%systemroot%\\system32\\cmd.exe" wide
		$s2 = "D:(A;;GA;;;WD)" wide
		$s3 = "%systemroot%\\system32\\sysprep\\sysprep.exe" fullword wide
		$s4 = "/c wusa %ws /extract:%%windir%%\\system32" fullword wide
		$s5 = "Fubuki.dll" ascii fullword
		
		$l1 = "ntdll.dll" ascii
		$l2 = "Cabinet.dll" ascii
		$l3 = "GetProcessHeap" ascii
		$l4 = "WriteProcessMemory" ascii
		$l5 = "ShellExecuteEx" ascii
	condition:
		( 1 of ($x*) ) or ( 3 of ($s*) and all of ($l*) ) 
}

rule DarkenCode_Mis_LightFTP_fftp_x86_64 {
	meta:
		description = "Detects a light FTP server"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
		hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"
		score = 50
	strings:
		$s1 = "fftp.cfg" fullword wide
		$s2 = "220 LightFTP server v1.0 ready" fullword ascii
		$s3 = "*FTP thread exit*" fullword wide
		$s4 = "PASS->logon successful" fullword ascii
		$s5 = "250 Requested file action okay, completed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and 4 of them
}

rule DarkenCode_Mis_LightFTP_Config {
	meta:
		description = "Detects a light FTP server - config file"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash = "ce9821213538d39775af4a48550eefa3908323c5"
	strings:
		$s2 = "maxusers=" wide
		$s6 = "[ftpconfig]" fullword wide
		$s8 = "accs=readonly" fullword wide
		$s9 = "[anonymous]" fullword wide
		$s10 = "accs=" fullword wide
		$s11 = "pswd=" fullword wide
	condition:
		uint16(0) == 0xfeff and filesize < 1KB and all of them
}

rule DarkenCode_Mis_SpyGate_v2_9
{
	meta:
		date = "2014/09"
		maltype = "Spygate v2.9 Remote Access Trojan"
		filetype = "exe"
		reference = "https://blogs.mcafee.com/mcafee-labs/middle-east-developer-spygate-struts-stuff-online"
	strings:
		$1 = "shutdowncomputer" wide
		$2 = "shutdown -r -t 00" wide
		$3 = "blockmouseandkeyboard" wide
		$4 = "ProcessHacker"
		$5 = "FileManagerSplit" wide
	condition:
		all of them
}

rule DarkenCode_Mis_PythoRAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/PythoRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "TKeylogger"
		$b = "uFileTransfer"
		$c = "TTDownload"
		$d = "SETTINGS"
		$e = "Unknown" wide
		$f = "#@#@#"
		$g = "PluginData"
		$i = "OnPluginMessage"

	condition:
		all of them
}

rule DarkenCode_Mis_CN_Toolset_sig_1433_135_sqlr {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
	strings:
		$s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
		$s11 = ";DATABASE=master" fullword ascii
		$s12 = "xp_cmdshell '" fullword ascii
		$s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
	condition:
		all of them
}

rule DarkenCode_Mis_VirusRat
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/VirusRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string0 = "virustotal"
		$string1 = "virusscan"
		$string2 = "abccba"
		$string3 = "pronoip"
		$string4 = "streamWebcam"
		$string5 = "DOMAIN_PASSWORD"
		$string6 = "Stub.Form1.resources"
		$string7 = "ftp://{0}@{1}" wide
		$string8 = "SELECT * FROM moz_logins" wide
		$string9 = "SELECT * FROM moz_disabledHosts" wide
		$string10 = "DynDNS\\Updater\\config.dyndns" wide
		$string11 = "|BawaneH|" wide

	condition:
		all of them
}

rule DarkenCode_Mis_ice_ix_12xy : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "ICE-IX 1.2.x.y trojan banker"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0" 
	
	strings:
		$regexp1= /bn1=.{32}&sk1=[0-9a-zA-Z]{32}/
		$a = "bn1="
		$b = "&sk1="
		$c = "mario"								//HardDrive GUID artifact
		$d = "FIXME"
		$e = "RFB 003.003"							//VNC artifact
		$ggurl = "http://www.google.com/webhp"

	condition:
		$regexp1 or ($a and $b) or all of ($c,$d,$e,$ggurl) 
}

rule DarkenCode_Mis_qadars : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Qadars - Mobile part. Maybe Perkele."
		version = "1.0" 
		filetype = "memory"
		ref1 = "http://www.lexsi-leblog.fr/cert/qadars-nouveau-malware-bancaire-composant-mobile.html"

	strings:
		$cmd1 = "m?D"
		$cmd2 = "m?S"
		$cmd3 = "ALL"
		$cmd4 = "FILTER"
		$cmd5 = "NONE"
		$cmd6 = "KILL"
		$cmd7 = "CANCEL"
		$cmd8 = "SMS"
		$cmd9 = "DIVERT"
		$cmd10 = "MESS"
		$nofilter = "nofilter1111111"
		$botherderphonenumber1 = "+380678409210"

	condition:
		all of ($cmd*) or $nofilter or any of ($botherderphonenumber*)
}

rule DarkenCode_Mis_shylock :  banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Shylock Banker"
		date = "2013-12-12" 
		version = "1.0" 
		ref1 = "http://iocbucket.com/iocs/1b4660d57928df5ca843c21df0b2adb117026cba"
		ref2 = "http://www.trusteer.com/blog/merchant-fraud-returns-%E2%80%93-shylock-polymorphic-financial-malware-infections-rise"
		ref3 = "https://www.csis.dk/en/csis/blog/3811/"

	strings:
		$process1 = "MASTER"
		$process2 = "_SHUTDOWN"
		$process3 = "EVT_VNC"
		$process4 = "EVT_BACK"
		$process5 = "EVT_VNC"
		$process6 = "IE_Hook::GetRequestInfo"
		$process7 = "FF_Hook::getRequestInfo"
		$process8 = "EX_Hook::CreateProcess"
		$process9 = "hijackdll.dll"
		$process10 = "MTX_"
		$process11 = "FF::PR_WriteHook entry"
		$process12 = "FF::PR_WriteHook exit"
		$process13 = "HijackProcessAttach::*** MASTER *** MASTER *** MASTER *** %s PID=%u"
		$process14 = "HijackProcessAttach::entry"
		$process15 = "FF::BEFORE INJECT"
		$process16 = "FF::AFTER INJECT"
		$process17 = "IE::AFTER INJECT"
		$process18 = "IE::BEFORE INJECT"
		$process19 = "*** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** %s"
		$process20 = "*** LOG INJECTS *** %s"
		$process21 = "*** inject to process %s not allowed"
		$process22 = "*** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** %s"
		$process23 = ".?AVFF_Hook@@"
		$process24 = ".?AVIE_Hook@@"
		$process25 = "Inject::InjectDllFromMemory"
		$process26 = "BadSocks.dll"	
		$domain1 = "extensadv.cc"
		$domain2 = "topbeat.cc"
		$domain3 = "brainsphere.cc"
		$domain4 = "commonworldme.cc"
		$domain5 = "gigacat.cc"
		$domain6 = "nw-serv.cc"
		$domain7 = "paragua-analyst.cc"
		
	condition:
		3 of ($process*) or any of ($domain*)
}

rule DarkenCode_Mis_spyeye : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "SpyEye X.Y memory"
		date = "2012-05-23" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$spyeye = "SpyEye"
		$a = "%BOTNAME%"
		$b = "globplugins"
		$c = "data_inject"
		$d = "data_before"
		$e = "data_after"
		$f = "data_end"
		$g = "bot_version"
		$h = "bot_guid"
		$i = "TakeBotGuid"
		$j = "TakeGateToCollector"
		$k = "[ERROR] : Omfg! Process is still active? Lets kill that mazafaka!"
		$l = "[ERROR] : Update is not successfull for some reason"
		$m = "[ERROR] : dwErr == %u"
		$n = "GRABBED DATA"
		
	condition:
		$spyeye or (any of ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n))
}

rule DarkenCode_Mis_spyeye_plugins : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "SpyEye X.Y Plugins memory"
		date = "2012-05-23" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$a = "webfakes.dll"
		$b = "config.dat"			//may raise some FP
		$c = "collectors.txt"
		$d = "webinjects.txt"
		$e = "screenshots.txt"
		$f = "billinghammer.dll"
		$g = "block.dll"			//may raise some FP
		$h = "bugreport.dll"		//may raise some FP
		$i = "ccgrabber.dll"
		$j = "connector2.dll"
		$k = "creditgrab.dll"
		$l = "customconnector.dll"
		$m = "ffcertgrabber.dll"
		$n = "ftpbc.dll"
		$o = "rdp.dll"				//may raise some FP
		$p = "rt_2_4.dll"
		$q = "socks5.dll"			//may raise some FP
		$r = "spySpread.dll"
		$s = "w2chek4_4.dll"
		$t = "w2chek4_6.dll"
	
	condition:
		any of them
}

rule DarkenCode_Mis_callTogether_certificate
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/03" 
        Description = "detects binaries signed with the CallTogether certificate"
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

    strings:
        $serial = { 45 21 56 C3 B3 FB 01 76 36 5B DB 5B 77 15 BC 4C }
        $o = "CallTogether, Inc."

    condition:
        $serial and $o
}

rule DarkenCode_Mis_qti_certificate
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/03" 
        Description = "detects binaries signed with the QTI International Inc certificate"
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

    strings:
        $cn = "QTI International Inc"
        $serial = { 2e df b9 fd cf a0 0c cb 5a b0 09 ee 3a db 97 b9 }

    condition:
        $cn and $serial
}

rule DarkenCode_Mis_DownExecute_A
{
	meta:
        Author      = "PwC Cyber Threat Operations :: @tlansec"
        Date        = "2015/04/27"
        Description = "Malware is often wrapped/protected, best to run on memory"
        Reference   = "http://pwc.blogs.com/cyber_security_updates/2015/04/attacks-against-israeli-palestinian-interests.html"

    strings:
        $winver1 = "win 8.1"
        $winver2 = "win Server 2012 R2"
        $winver3 = "win Srv 2012"
        $winver4 = "win srv 2008 R2"
        $winver5 = "win srv 2008"
        $winver6 = "win vsta"
        $winver7 = "win srv 2003 R2"
        $winver8 = "win hm srv"
        $winver9 = "win Strg srv 2003"
        $winver10 = "win srv 2003"
        $winver11 = "win XP prof x64 edt"
        $winver12 = "win XP"
        $winver13 = "win 2000"

        $pdb1 = "D:\\Acms\\2\\docs\\Visual Studio 2013\\Projects\\DownloadExcute\\DownloadExcute\\Release\\DownExecute.pdb"
        $pdb2 = "d:\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\writer.h"
        $pdb3 = ":\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\internal/stack.h"
        $pdb4 = "\\downloadexcute\\downexecute\\"

        $magic1 = "<Win Get Version Info Name Error"
        $magic2 = "P@$sw0rd$nd"
        $magic3 = "$t@k0v2rF10w"
        $magic4 = "|*|123xXx(Mutex)xXx321|*|6-21-2014-03:06PM" wide

		$str1 = "Download Excute" ascii wide fullword
        $str2 = "EncryptorFunctionPointer %d"
        $str3 = "%s\\%s.lnk"
        $str4 = "Mac:%s-Cpu:%s-HD:%s"
        $str5 = "feed back responce of host"
        $str6 = "GET Token at host"
        $str7 = "dwn md5 err"

    condition:
        all of ($winver*) or any of ($pdb*) or any of ($magic*) or 2 of ($str*)
}

rule DarkenCode_Mis_CN_Toolset__XScanLib_XScanLib_XScanLib {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - from files XScanLib.dll, XScanLib.dll, XScanLib.dll"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		super_rule = 1
		hash0 = "af419603ac28257134e39683419966ab3d600ed2"
		hash1 = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
		hash2 = "135f6a28e958c8f6a275d8677cfa7cb502c8a822"
	strings:
		$s1 = "Plug-in thread causes an exception, failed to alert user." fullword
		$s2 = "PlugGetUdpPort" fullword
		$s3 = "XScanLib.dll" fullword
		$s4 = "PlugGetTcpPort" fullword
		$s11 = "PlugGetVulnNum" fullword
	condition:
		all of them
}

rule DarkenCode_Mis_CN_Toolset_NTscan_PipeCmd {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file PipeCmd.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "a931d65de66e1468fe2362f7f2e0ee546f225c4e"
	strings:
		$s2 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s3 = "PipeCmd.exe" fullword wide
		$s4 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s5 = "%s\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "%s\\ADMIN$\\System32\\%s" fullword ascii
		$s9 = "PipeCmdSrv.exe" fullword ascii
		$s10 = "This is a service executable! Couldn't start directly." fullword ascii
		$s13 = "\\\\.\\pipe\\PipeCmd_communicaton" fullword ascii
		$s14 = "PIPECMDSRV" fullword wide
		$s15 = "PipeCmd Service" fullword ascii
	condition:
		4 of them
}

rule DarkenCode_Mis_CN_Toolset_LScanPortss_2 {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "4631ec57756466072d83d49fbc14105e230631a0"
	strings:
		$s1 = "LScanPort.EXE" fullword wide
		$s3 = "www.honker8.com" fullword wide
		$s4 = "DefaultPort.lst" fullword ascii
		$s5 = "Scan over.Used %dms!" fullword ascii
		$s6 = "www.hf110.com" fullword wide
		$s15 = "LScanPort Microsoft " fullword wide
		$s18 = "L-ScanPort2.0 CooFly" fullword wide
	condition:
		4 of them
}

rule DarkenCode_Mis_CVE_2015_1674_CNGSYS {
	meta:
		description = "Detects exploits for CVE-2015-1674"
		author = "Florian Roth"
		reference = "http://www.binvul.com/viewthread.php?tid=508"
		reference2 = "https://github.com/Neo23x0/Loki/blob/master/signatures/exploit_cve_2015_1674.yar"
		date = "2015-05-14"
		hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"
	strings:
		$s1 = "\\Device\\CNG" fullword wide
		
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "LoadLibrary" ascii
		$s4 = "KERNEL32.dll" fullword ascii
		$s5 = "ntdll.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule DarkenCode_Mis_Ap0calypse
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Ap0calypse"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Ap0calypse"
		$b = "Sifre"
		$c = "MsgGoster"
		$d = "Baslik"
		$e = "Dosyalars"
		$f = "Injecsiyon"

	condition:
		all of them
}

rule DarkenCode_Mis_Arcom
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Arcom"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
        $a1 = "CVu3388fnek3W(3ij3fkp0930di"
        $a2 = "ZINGAWI2"
        $a3 = "clWebLightGoldenrodYellow"
        $a4 = "Ancestor for '%s' not found" wide
        $a5 = "Control-C hit" wide
        $a6 = {A3 24 25 21}
        
    condition:
        all of them
}

rule DarkenCode_Mis_Bandook
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/bandook"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
    		$a = "aaaaaa1|"
            $b = "aaaaaa2|"
            $c = "aaaaaa3|"
            $d = "aaaaaa4|"
			$e = "aaaaaa5|"
			$f = "%s%d.exe"
			$g = "astalavista"
			$h = "givemecache"
			$i = "%s\\system32\\drivers\\blogs\\*"
			$j = "bndk13me"
			

        
    condition:
    		all of them
}

rule DarkenCode_Mis_Bozok
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Bozok"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "getVer" nocase
		$b = "StartVNC" nocase
		$c = "SendCamList" nocase
		$d = "untPlugin" nocase
		$e = "gethostbyname" nocase
	
	condition:
		all of them
}

rule DarkenCode_Mis_CyberGate
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/CyberGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$string3 = "EditSvr"
		$string4 = "TLoader"
		$string5 = "Stroks"
		$string6 = "####@####"
		$res1 = "XX-XX-XX-XX"
		$res2 = "CG-CG-CG-CG"

	condition:
		all of ($string*) and any of ($res*)
}

rule DarkenCode_Mis_DarkRAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/DarkRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "@1906dark1996coder@"
		$b = "SHEmptyRecycleBinA"
		$c = "mciSendStringA"
		$d = "add_Shutdown"
		$e = "get_SaveMySettingsOnExit"
		$f = "get_SpecialDirectories"
		$g = "Client.My"

	condition:
		all of them
}

rule DarkenCode_Mis_Greame
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Greame"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		
	strings:
    		$a = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
            $b = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
            $c = "EditSvr"
            $d = "TLoader"
			$e = "Stroks"
            $f = "Avenger by NhT"
			$g = "####@####"
			$h = "GREAME"
			

        
    condition:
    		all of them
}

rule DarkenCode_Mis_LostDoor
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/LostDoor"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
    	$a0 = {0D 0A 2A 45 44 49 54 5F 53 45 52 56 45 52 2A 0D 0A}
        $a1 = "*mlt* = %"
        $a2 = "*ip* = %"
        $a3 = "*victimo* = %"
        $a4 = "*name* = %"
        $b5 = "[START]"
        $b6 = "[DATA]"
        $b7 = "We Control Your Digital World" wide ascii
        $b8 = "RC4Initialize" wide ascii
        $b9 = "RC4Decrypt" wide ascii
        
    condition:
    	all of ($a*) or all of ($b*)
}

rule DarkenCode_Mis_LuxNet
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/LuxNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "GetHashCode"
		$b = "Activator"
		$c = "WebClient"
		$d = "op_Equality"
		$e = "dickcursor.cur" wide
		$f = "{0}|{1}|{2}" wide

	condition:
		all of them
}

rule DarkenCode_Mis_Pandora
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Pandora"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Can't get the Windows version"
		$b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
		$c = "JPEG error #%d" wide
		$d = "Cannot assign a %s to a %s" wide
		$g = "%s, ProgID:"
		$h = "clave"
		$i = "Shell_TrayWnd"
		$j = "melt.bat"
		$k = "\\StubPath"
		$l = "\\logs.dat"
		$m = "1027|Operation has been canceled!"
		$n = "466|You need to plug-in! Double click to install... |"
		$0 = "33|[Keylogger Not Activated!]"

	condition:
		all of them
}

rule DarkenCode_Mis_Paradox
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Paradox"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "ParadoxRAT"
		$b = "Form1"
		$c = "StartRMCam"
		$d = "Flooders"
		$e = "SlowLaris"
		$f = "SHITEMID"
		$g = "set_Remote_Chat"

	condition:
		all of them
}

rule DarkenCode_Mis_Punisher
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Punisher"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "abccba"
		$b = {5C 00 68 00 66 00 68 00 2E 00 76 00 62 00 73}
		$c = {5C 00 73 00 63 00 2E 00 76 00 62 00 73}
		$d = "SpyTheSpy" wide ascii
		$e = "wireshark" wide
		$f = "apateDNS" wide
		$g = "abccbaDanabccb"

	condition:
		all of them
}

rule DarkenCode_Mis_SmallNet
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/SmallNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		
	strings:
		$split1 = "!!<3SAFIA<3!!"
		$split2 = "!!ElMattadorDz!!"
		$a1 = "stub_2.Properties"
		$a2 = "stub.exe" wide
		$a3 = "get_CurrentDomain"

	condition:
		($split1 or $split2) and (all of ($a*))
}

rule DarkenCode_Mis_Base64_encoded_Executable {
	meta:
		description = "Detects an base64 encoded executable (often embedded)"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 50
	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" // 14 samples in goodware archive
		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" // 26 samples in goodware archive
		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" // 75 samples in goodware archive
		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" // 168 samples in goodware archive
		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" // 28,529 samples in goodware archive
	condition:
		1 of them
}

rule DarkenCode_Mis_CredStealESY : For CredStealer
{
 meta:
description = "Generic Rule to detect the CredStealer Malware"
author = "IsecG – McAfee Labs"
date = "2015/05/08"
strings:
$my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide //malware trying to get keyboard layout
$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8} //specific decryption module
 condition:
$my_hex_string and $my_hex_string2
}

rule DarkenCode_Mis_Mimikatz_Logfile
{
	meta:
		description = "Detects a log file generated by malicious hack tool mimikatz"
		author = "Florian Roth"
		score = 80
		date = "2015/03/31"
		reference = "https://github.com/Neo23x0/Loki/blob/master/signatures/thor-hacktools.yar"
	strings:
		$s1 = "SID :" ascii fullword
		$s2 = "* NTLM :" ascii fullword
		$s3 = "Authentication Id :" ascii fullword
		$s4 = "wdigest :" ascii fullword
	condition:
		all of them
}

rule DarkenCode_Mis_lsadump
{
	meta:
		description = "LSA dump programe (bootkey/syskey) - pwdump and others"
		author = "Benjamin DELPY (gentilkiwi)"
		reference = "https://github.com/Neo23x0/Loki/blob/master/signatures/thor-hacktools.yar"
	strings:
		$str_sam_inc = "\\Domains\\Account" ascii nocase
		$str_sam_exc = "\\Domains\\Account\\Users\\Names\\" ascii nocase
		$hex_api_call = {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
		$str_msv_lsa = { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
		$hex_bkey = { 4b 53 53 4d [20-70] 05 00 01 00}
	condition:
		($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey
}
