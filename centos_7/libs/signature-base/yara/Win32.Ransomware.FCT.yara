

rule reversinglabs_Win_Win32_Ransomware_FCT : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "FCT"
        description         = "Yara rule that detects FCT ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "FCT"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            6A ?? 68 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D 4D ?? FF B5 ?? ?? ?? ?? 6A ?? E8 ?? ?? 
            ?? ?? 83 7D ?? ?? 8D 8D ?? ?? ?? ?? 8D 45 ?? 0F 43 45 ?? 51 50 FF 15 ?? ?? ?? ?? 89 
            85 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 6A ?? 51 8D 4D ?? C7 45 ?? ?? ?? ?? ?? C7 
            45 ?? ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 33 DB 8B 55 ?? 33 C9 8B 75 
            ?? 89 9D ?? ?? ?? ?? 85 D2 74 ?? 66 90 83 7D ?? ?? 8D 45 ?? 0F 43 C6 0F BE 04 08 41 
            03 D8 3B CA 72 ?? 89 9D ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? F6 85 ?? ?? ?? ?? ?? 0F 84 ?? 
            ?? ?? ?? 66 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B CF C7 45 ?? ?? ?? ?? ?? 33 C0 
            C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 8D 51 ?? 66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B CA D1 
            F9 51 57 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8B 75 ?? 8B C6 8B 55 ?? 2B C2 83 F8 ?? 
            72 ?? 83 FE ?? 8D 45 ?? 8D 4A ?? BB ?? ?? ?? ?? 0F 43 45 ?? 89 4D ?? 66 89 1C 50 33 
            D2 66 89 14 48 EB ?? 6A ?? 68 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D 4D ?? FF B5 ?? ?? 
            ?? ?? 6A ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8D 51
        }

        $find_files_p2 = {
            52 51 E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 8D 14 55 
            ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 
            0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 9D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            50 53 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B BD ?? ?? ?? ?? E9 ?? ?? ?? ?? 53 FF 15 ?? ?? 
            ?? ?? 8B 45 ?? 83 F8 ?? 72 ?? 8B 55 ?? 8D 48 ?? 8B C2 81 F9 ?? ?? ?? ?? 72 ?? 8B 52 
            ?? 83 C1 ?? 2B C2 83 C0 ?? 83 F8 ?? 77 ?? 51 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 83 
            FA ?? 72 ?? 8B 4D ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 
            C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 64 89 0D 
            ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 E8
        }

        $encrypt_files_p1 = {
            66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 51 57 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? 
            ?? 8B 75 ?? 8B C6 8B 55 ?? 2B C2 83 F8 ?? 72 ?? 83 FE ?? 8D 45 ?? 8D 4A ?? BB ?? ?? 
            ?? ?? 0F 43 45 ?? 89 4D ?? 66 89 1C 50 33 D2 66 89 14 48 EB ?? 6A ?? 68 ?? ?? ?? ?? 
            C6 85 ?? ?? ?? ?? ?? 8D 4D ?? FF B5 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? 8D 51 ?? 66 8B 01 83 C1 ?? 66 85 C0 75 ?? 8B 5D ?? 2B CA 8B 55 ?? 8B C3 D1 F9 2B 
            C2 3B C8 77 ?? 83 FB ?? 8D 04 09 50 8D 75 ?? 0F 43 75 ?? 8D 85 ?? ?? ?? ?? 50 8D 3C 
            0A 89 7D ?? 8D 04 56 50 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 66 89 04 7E EB ?? 51 8D 85 ?? 
            ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 81 BD 
            ?? ?? ?? ?? ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 6A ?? 0F 43 45 ?? 68 
            ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F8 83 FF ?? 0F 
            84 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B F2 85 F6 74
        }

        $encrypt_files_p2 = {
            6A ?? 8D 45 ?? 50 A1 ?? ?? ?? ?? 2B C6 56 03 C1 50 57 FF 15 ?? ?? ?? ?? 2B 75 ?? 74 
            ?? 8B 8D ?? ?? ?? ?? EB ?? 57 FF 15 ?? ?? ?? ?? C6 45 ?? ?? 33 C0 8B 9D ?? ?? ?? ?? 
            BA ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 83 CB ?? 8B 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            89 95 ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 8D 48 ?? 3B CA 76 ?? C6 85 ?? ?? ?? ?? ?? FF B5 
            ?? ?? ?? ?? 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 8B 95 ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? 83 7D ?? ?? 8D 4D ?? 0F 43 4D ?? 3B C2 77 ?? 8D 34 00 89 85 ?? 
            ?? ?? ?? 83 FA ?? 8D BD ?? ?? ?? ?? 56 0F 43 BD ?? ?? ?? ?? 51 57 E8 ?? ?? ?? ?? 83 
            C4 ?? 33 C0 66 89 04 37 EB ?? 50 51 C6 85 ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? FF B5 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B C2 8B 8D ?? ?? ?? ?? 2B C1 83 F8 ?? 
            72 ?? 83 FA ?? 8D B5 ?? ?? ?? ?? 6A ?? 0F 43 B5 ?? ?? ?? ?? 8D 79 ?? 68 ?? ?? ?? ?? 
            89 BD ?? ?? ?? ?? 8D 04 4E 50 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 66 89 04 7E EB ?? 6A ?? 
            68 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 6A ?? E8 ?? 
            ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8D 45 ?? 0F 43 8D ?? ?? ?? ?? 83 7D 
            ?? ?? 51 0F 43 45 ?? 50 FF 15
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            all of ($encrypt_files_p*)
        )
}