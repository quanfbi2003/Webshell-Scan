
/*
https://twitter.com/VK_Intel/status/1247058432223477760
*/

import "pe"

<<<<<<< Updated upstream:libs/signature-base/yara/crime_evilcorp_dridex_banker.yar
rule crime_win32_dridex_socks5_mod {
=======
/*
https://twitter.com/VK_Intel/status/1247058432223477760
*/



//===SUCCESS===
rule Neo23x0_crime_evilcorp_dridex_banker_crime_win32_dridex_socks5_mod {
>>>>>>> Stashed changes:webshell-scan-docker/libs/signature-base/yara/crime_evilcorp_dridex_banker.yar
    meta:
        description = "Detects Dridex socks5 module"
        author = "@VK_Intel"
        date = "2020-04-06"
        reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
        id = "cee256b1-ad80-55dd-bbd3-0d3f7bc49664"
    strings:
        $s0 = "socks5_2_x32.dll"
        $s1 = "socks5_2_x64.dll"
    condition:
        any of ($s*) and pe.exports("start")
}
<<<<<<< Updated upstream:libs/signature-base/yara/crime_evilcorp_dridex_banker.yar

rule crime_win32_hvnc_banker_gen {
=======
//===SUCCESS===
rule Neo23x0_crime_evilcorp_dridex_banker_crime_win32_hvnc_banker_gen {
>>>>>>> Stashed changes:webshell-scan-docker/libs/signature-base/yara/crime_evilcorp_dridex_banker.yar
    meta:
        description = "Detects malware banker hidden VNC"
        author = "@VK_Intel"
        reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
        date = "2020-04-06"
        id = "5e13f4a9-2231-524f-82b2-fbc6d6a43b6f"
    condition:
        pe.exports("VncStartServer") and pe.exports("VncStopServer")
}