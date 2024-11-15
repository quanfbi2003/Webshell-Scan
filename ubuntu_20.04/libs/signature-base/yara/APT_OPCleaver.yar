import "pe"

rule DarkenCode_APT_ZhoupinExploitCrew
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
  	$s1 = "zhoupin exploit crew" nocase
    $s2 = "zhopin exploit crew" nocase
  condition:
  	1 of them
}

rule DarkenCode_APT_BackDoorLogger
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "BackDoorLogger"
    $s2 = "zhuAddress"
  condition:
    all of them
}

rule DarkenCode_APT_Jasus
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "pcap_dump_open"
    $s2 = "Resolving IPs to poison..."
    $s3 = "WARNNING: Gateway IP can not be found"
  condition:
    all of them
}

rule DarkenCode_APT_LoggerModule
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "%s-%02d%02d%02d%02d%02d.r"
    $s2 = "C:\\Users\\%s\\AppData\\Cookies\\"
  condition:
    all of them
}

rule DarkenCode_APT_NetC
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "NetC.exe" wide
    $s2 = "Net Service"
  condition:
    all of them
}

rule DarkenCode_APT_ShellCreator2
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "ShellCreator2.Properties"
    $s2 = "set_IV"
  condition:
    all of them
}

rule DarkenCode_APT_SmartCopy2
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "SmartCopy2.Properties"
    $s2 = "ZhuFrameWork"
  condition:
    all of them
}

rule DarkenCode_APT_SynFlooder
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "Unable to resolve [ %s ]. ErrorCode %d"
    $s2 = "your target's IP is : %s"
    $s3 = "Raw TCP Socket Created successfully."
  condition:
    all of them
}

rule DarkenCode_APT_TinyZBot
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "NetScp" wide
    $s2 = "TinyZBot.Properties.Resources.resources"

    $s3 = "Aoao WaterMark"
    $s4 = "Run_a_exe"
    $s5 = "netscp.exe"

    $s6 = "get_MainModule_WebReference_DefaultWS"
    $s7 = "remove_CheckFileMD5Completed"
    $s8 = "http://tempuri.org/"

    $s9 = "Zhoupin_Cleaver"
  condition:
    ($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or ($s9)
}

rule DarkenCode_APT_antivirusdetector
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
	strings:
		$s1 = "getShadyProcess"
		$s2 = "getSystemAntiviruses"
		$s3 = "AntiVirusDetector"
	condition:
		all of them
}

rule DarkenCode_APT_csext
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "COM+ System Extentions"
    $s2 = "csext.exe"
    $s3 = "COM_Extentions_bin"
  condition:
    all of them
}

rule DarkenCode_APT_kagent
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "kill command is in last machine, going back"
    $s2 = "message data length in B64: %d Bytes"
  condition:
    all of them
}

rule DarkenCode_APT_mimikatzWrapper
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "mimikatzWrapper"
    $s2 = "get_mimikatz"
  condition:
    all of them
}

rule DarkenCode_APT_pvz_in
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "LAST_TIME=00/00/0000:00:00PM$"
    $s2 = "if %%ERRORLEVEL%% == 1 GOTO line"
  condition:
    all of them
}

rule DarkenCode_APT_pvz_out
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "Network Connectivity Module" wide
    $s2 = "OSPPSVC" wide
  condition:
    all of them
}

rule DarkenCode_APT_wndTest
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "[Alt]" wide
    $s2 = "<< %s >>:" wide
    $s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"
  condition:
    all of them
}

rule DarkenCode_APT_zhCat
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "zhCat -l -h -tp 1234"
    $s2 = "ABC ( A Big Company )" wide
  condition:
    all of them
}

rule DarkenCode_APT_zhLookUp
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "zhLookUp.Properties"
  condition:
    all of them
}

rule DarkenCode_APT_zhmimikatz
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "MimikatzRunner"
    $s2 = "zhmimikatz"
  condition:
    all of them
}

rule DarkenCode_APT_Zh0uSh311
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
  	$s1 = "Zh0uSh311"
  condition:
  	all of them
}
