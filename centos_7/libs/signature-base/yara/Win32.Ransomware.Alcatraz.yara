

rule reversinglabs_Win_Win32_Ransomware_Alcatraz : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "ALCATRAZ"
        description         = "Yara rule that detects Alcatraz ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Alcatraz"
        tc_detection_factor = 5

    strings:

        $encrypt_files = {
            55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A 
            ?? 68 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 
            ?? ?? ?? ?? 8B 4D ?? 51 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 83 C8 ?? E9 
            ?? ?? ?? ?? 6A ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? 
            ?? ?? ?? ?? 75 ?? 83 C8 ?? E9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 89 85 ?? ?? ?? ?? 83 
            BD ?? ?? ?? ?? ?? 75 ?? 83 C8 ?? E9 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 8B 8D ?? 
            ?? ?? ?? 51 8B 95 ?? ?? ?? ?? 52 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 8D ?? ?? 
            ?? ?? 51 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 
            ?? 83 C8 ?? E9 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? 
            ?? ?? 8B 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? 
            ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 0F B6 D0 85 D2 75 ?? 83 7D ?? ?? 74 ?? 6A 
            ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? EB ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 
            68 ?? ?? ?? ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 
            75 ?? 83 C8 ?? EB ?? 6A ?? 8D 95 ?? ?? ?? ?? 52 8B 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? 
            ?? 51 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 85 ?? ?? ?? ?? 8B 4D ?? 
            33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }
        
        $remote_server = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 
            68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 6A ?? 6A ?? 68 ?? ?? ?? 
            ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 68 ?? ?? ?? ?? 6A ?? 6A 
            ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 68 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D 
            ?? ?? 74 ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 
            ?? 83 7D ?? ?? 74 ?? 6A ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 0F 84 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 
            ?? 83 C8 ?? E9 ?? ?? ?? ?? 8B 4D ?? 83 C1 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 
            7D ?? ?? 75 ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 55 ?? 83 C2 ?? 52 6A ?? 8B 45 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 FF 15 
            ?? ?? ?? ?? 85 C0 75 ?? 83 C8 ?? E9 ?? ?? ?? ?? EB ?? C7 45 ?? ?? ?? ?? ?? EB ?? 8B 
            55 ?? 83 C2 ?? 89 55 ?? 8B 45 ?? 3B 45 ?? 73 ?? 8B 4D ?? 03 4D ?? 0F BE 11 83 FA ?? 
            74 ?? 8B 45 ?? 03 45 ?? 0F BE 08 83 F9 ?? 74 ?? 8B 55 ?? 03 55 ?? 8B 45 ?? 03 45 ?? 
            8A 08 88 0A EB ?? 8B 55 ?? 03 55 ?? C6 02 ?? EB ?? EB ?? EB ?? 83 7D ?? ?? 0F 87 ?? 
            ?? ?? ?? 83 7D ?? ?? 75 ?? 83 C8 ?? EB ?? 83 7D ?? ?? 74 ?? 8B 45 ?? 50 FF 15 ?? ?? 
            ?? ?? 83 7D ?? ?? 74 ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 8B 55 ?? 52 
            FF 15 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $remote_server_2 = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 83 C4 ?? 89 45 ?? A1 ?? ?? ?? ?? 50 8B 0D ?? ?? ?? ?? 51 8B 15 ?? ?? ?? ?? 52 
            A1 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 50 8B 0D ?? ?? ?? ?? 51 68 
            ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 
            68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 68 ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 
            52 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 
            89 45 ?? 83 7D ?? ?? 74 ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? 
            ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8B 4D ?? 51 68 
            ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 45 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? 
            ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 6A ?? 6A ?? 6A ?? 6A ?? 
            6A ?? 6A ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 6A ?? 8B 55 ?? 
            52 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 
            45 ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 33 C0 E9 ?? ?? ?? ?? 8B 55 ?? 83 
            C2 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? ?? 75 ?? C7 45 ?? ?? ?? ?? ?? 33 
            C0 E9 ?? ?? ?? ?? EB ?? 8B 45 ?? 83 C0 ?? 50 6A ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 
            ?? 8D 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 33 
            C0 EB ?? EB ?? 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 68 ?? ?? ?? ?? 8B 4D ?? 
            51 E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 74 ?? B8 ?? ?? ?? ?? EB ?? 83 7D ?? ?? 0F 87 ?? 
            ?? ?? ?? 83 7D ?? ?? 75 ?? 83 C8 ?? EB ?? 83 7D ?? ?? 74 ?? 8B 55 ?? 52 FF 15 ?? ?? 
            ?? ?? 83 7D ?? ?? 74 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 8B 4D ?? 51 
            FF 15 ?? ?? ?? ?? 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and $encrypt_files and $remote_server and $remote_server_2
}