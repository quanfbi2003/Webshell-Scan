

rule reversinglabs_Win_Win32_Ransomware_Skystars : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "SKYSTARS"
        description         = "Yara rule that detects Skystars ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Skystars"
        tc_detection_factor = 5

    strings:

        $search_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            8B 5D ?? FF 33 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 50 
            6A ?? 6A ?? FF 75 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8B 5D ?? 85 DB 
            74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 
            83 C4 ?? 58 89 45 ?? 68 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 84 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 84 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? B8 ?? 
            ?? ?? ?? EB ?? B8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? 8B 5D 
            ?? FF 33 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 
            8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 6A 
            ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8B 45 ?? 50 8B 5D ?? 85 DB 74 ?? 
            53 E8 ?? ?? ?? ?? 83 C4 ?? 58 89 45 ?? E9 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 5D ?? FF 33
        }

        $search_files_p2 = {
            B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 68 ?? ?? 
            ?? ?? FF 75 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8B 5D ?? 85 DB 74 ?? 
            53 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 
            ?? 58 89 45 ?? 68 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 84 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? B8 ?? ?? ?? 
            ?? EB ?? B8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? 8B 5D ?? FF 
            33 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 8B 5D 
            ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 68 ?? ?? ?? ?? 
            6A ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8B 45 ?? 50 8B 5D ?? 85 DB 74 
            ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 58 89 45 ?? E9 ?? ?? ?? ?? FF 75 ?? B8 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B E5 5D C2
        }

        $encrypt_files = {
            55 8B EC 81 EC ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8B 5D ?? 8B 03 
            85 C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 
            89 45 ?? 8B 45 ?? 50 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 58 89 45 ?? 68 
            ?? ?? ?? ?? 6A ?? 8B 5D ?? 8B 03 85 C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? BB ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 5D ?? FF 
            33 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? FF 75 ?? 68 ?? ?? 
            ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8B 5D ?? 85 DB 74 ?? 53 E8 ?? 
            ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 
            85 C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 85 C0 75 ?? B8 ?? ?? ?? 
            ?? 50 68 ?? ?? ?? ?? BB ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 
            8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 85 C0 
            75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 85 C0 75 ?? B8 ?? ?? ?? ?? 50 
            68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 5D ?? 85 DB 74 ?? 53 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B 5D ?? 85 DB 74 
            ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B E5 5D C2
        }

        $main_routine = {
            68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? BB ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 8B 5D ?? 85 DB 74 ?? 53 E8 
            ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? BB ?? ?? ?? 
            ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 8B 5D 
            ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? BB ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8D 45 ?? 50 
            E8 ?? ?? ?? ?? 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? B8 ?? ?? ?? ?? 89 45 
            ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? 
            ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 
            89 45 ?? 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 85 C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 5D ?? 
            85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 83 C4 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $main_routine
        ) and 
        (
            all of ($search_files_p*)
        ) and 
        (
            $encrypt_files
        )
}