

rule reversinglabs_Win_Win32_Ransomware_Gomer : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "GOMER"
        description         = "Yara rule that detects Gomer ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Gomer"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            8B FF 55 8B EC 51 8B 4D ?? 53 57 33 DB 8D 51 ?? 66 8B 01 83 C1 ?? 66 3B C3 75 ?? 8B 
            7D ?? 2B CA D1 F9 83 C8 ?? 41 2B C7 89 4D ?? 3B C8 76 ?? 6A ?? 58 EB ?? 56 8D 5F ?? 
            03 D9 6A ?? 53 E8 ?? ?? ?? ?? 8B F0 59 59 85 FF 74 ?? 57 FF 75 ?? 53 56 E8 ?? ?? ?? 
            ?? 83 C4 ?? 85 C0 75 ?? FF 75 ?? 2B DF 8D 04 7E FF 75 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 85 C0 75 ?? 8B 4D ?? 56 E8 ?? ?? ?? ?? 6A ?? 8B F0 E8 ?? ?? ?? ?? 59 8B C6 5E 5F 
            5B 8B E5 5D C3 33 C0 50 50 50 50 50 E8 ?? ?? ?? ?? CC 8B FF 55 8B EC 81 EC ?? ?? ?? 
            ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 8B 55 ?? 8B 4D ?? 53 8B 5D ?? 56 57 6A ?? 5E 6A ?? 
            89 95 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 5F EB ?? 0F B7 01 66 3B 85 ?? ?? ?? 
            ?? 74 ?? 66 3B C6 74 ?? 66 3B C7 74 ?? 83 E9 ?? 3B CB 75 ?? 0F B7 31 66 3B F7 75 ?? 
            8D 43 ?? 3B C8 74 ?? 52 33 FF 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 6A ?? 
            8B C6 33 FF 5A 66 3B C2 74 ?? 6A ?? 5A 66 3B C2 74 ?? 6A ?? 5A 66 3B C2 74 ?? 8B C7
        }

        $find_files_p2 = {
            EB ?? 33 C0 40 2B CB 0F B6 C0 D1 F9 41 F7 D8 68 ?? ?? ?? ?? 1B C0 23 C1 89 85 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 57 57 57 50 
            57 53 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 75 ?? 8B 85 ?? ?? ?? ?? 50 57 57 53 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8B F8 83 FE ?? 74 ?? 56 FF 15 ?? ?? ?? ?? 8B C7 8B 4D ?? 5F 5E 33 CD 
            5B E8 ?? ?? ?? ?? 8B E5 5D C3 8B 8D ?? ?? ?? ?? 6A ?? 8B 41 ?? 2B 01 C1 F8 ?? 89 85 
            ?? ?? ?? ?? 58 66 39 85 ?? ?? ?? ?? 75 ?? 66 39 BD ?? ?? ?? ?? 74 ?? 66 39 85 ?? ?? 
            ?? ?? 75 ?? 66 39 BD ?? ?? ?? ?? 74 ?? 51 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 53 50 
            E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 8B 8D 
            ?? ?? ?? ?? 85 C0 6A ?? 58 75 ?? 8B C1 8B 8D ?? ?? ?? ?? 8B 10 8B 40 ?? 2B C2 C1 F8 
            ?? 3B C8 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 
            83 C4 ?? E9
        }

        $encrypt_files = {
            55 8B EC 51 8B 45 ?? 53 56 57 8B F9 8B 4F ?? 89 4D ?? 3B C1 77 ?? 8B DF 83 F9 ?? 72 
            ?? 8B 1F 8D 34 00 89 47 ?? 56 FF 75 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 66 89 04 1E 
            8B C7 5F 5E 5B 8B E5 5D C2 ?? ?? 3D ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 8B F0 83 CE ?? 81 
            FE ?? ?? ?? ?? 76 ?? BE ?? ?? ?? ?? EB ?? 8B D1 B8 ?? ?? ?? ?? D1 EA 2B C2 3B C8 76 
            ?? BE ?? ?? ?? ?? EB ?? 8D 04 0A 3B F0 0F 42 F0 8D 46 ?? 8D 0C 00 3D ?? ?? ?? ?? 76 
            ?? 83 C9 ?? EB ?? 81 F9 ?? ?? ?? ?? 72 ?? 8D 41 ?? 83 CA ?? 3B C1 0F 46 C2 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8D 58 ?? 83 E3 ?? 89 43 ?? EB ?? 85 C9 74 ?? 51 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8B D8 EB ?? 33 DB 8B 45 ?? 89 77 ?? 89 47 ?? 8D 34 00 56 FF 75 ?? 
            53 E8 ?? ?? ?? ?? 33 C0 83 C4 ?? 66 89 04 1E 8B 45 ?? 83 F8 ?? 72 ?? 8D 0C 45 ?? ?? 
            ?? ?? 8B 07 81 F9 ?? ?? ?? ?? 72 ?? 8B 50 ?? 83 C1 ?? 2B C2 83 C0 ?? 83 F8 ?? 77 ?? 
            8B C2 51 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 1F 8B C7 5F 5E 5B 8B E5 5D C2 ?? ?? E8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? CC CC CC CC CC B8 ?? ?? ?? ?? C3
        }

        $enum_drives_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 
            45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 89 4D ?? 68 ?? ?? ?? ?? C7 45 ?? ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? FF 15 ?? ?? ?? ?? 89 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? C7 45 ?? ?? ?? ?? ?? 8D 4D ?? 6A ?? 33 C0 C7 
            45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? E8 ?? ?? ?? ?? C6 
            45 ?? ?? BF ?? ?? ?? ?? 8D 45 ?? 0F A3 38 0F 83 ?? ?? ?? ?? 83 7D ?? ?? 8D 4D ?? 8D 
            47 ?? 0F 43 4D ?? 66 89 01 8D 45 ?? 83 7D ?? ?? 0F 43 45 ?? 50 FF 15 ?? ?? ?? ?? 83 
            F8 ?? 74 ?? 83 F8 ?? 74 ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 33 C9 C7 45 ?? ?? ?? ?? ?? C7 
            45 ?? ?? ?? ?? ?? 66 89 4D ?? C6 45 ?? ?? 83 F8 ?? 75 ?? 6A ?? 68 ?? ?? ?? ?? EB ?? 
            83 F8 ?? 75 ?? 6A ?? 68 ?? ?? ?? ?? EB ?? 83 F8 ?? 75 ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D 
            ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 55 ?? 56 8D 4D ?? E8 ?? ?? 
            ?? ?? 8B 4D ?? B8 ?? ?? ?? ?? 2B CE C6 45 ?? ?? F7 E9 83 C4 ?? C1 FA ?? 8B DA C1 EB 
            ?? 03 DA 8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? 
            ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? FF 35 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 55 ?? 56 8D 4D ?? E8 ?? ?? ?? 
            ?? 8B 4D ?? B8 ?? ?? ?? ?? 2B CE 89 7D ?? F7 E9 83 C4 ?? 89 5D ?? C1 FA ?? 8D 4D
        }

        $enum_drives_p2 = {
            8B C2 C1 E8 ?? 03 C2 89 45 ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 45 ?? FF 75 
            ?? 50 51 8D 45 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8B 55 ?? 83 FA ?? 72 ?? 8B 
            4D ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 
            C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 47 83 FF ?? 0F 8C ?? 
            ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C7 45 ?? ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? 8B D8 89 5D ?? C6 45 ?? ?? 8B 4D ?? 8B 31 
            3B F1 0F 84 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? FF 75 ?? 8B C8 C6 45 
            ?? ?? 6A ?? E8 ?? ?? ?? ?? 8B F8 C6 45 ?? ?? 8B 4E ?? 89 4F ?? 8B 4E ?? 89 4F ?? 8D 
            4F ?? 8B 46 ?? 89 47 ?? 8D 46 ?? 3B C8 74 ?? 83 78 ?? ?? 8B D0 72 ?? 8B 10 FF 70 ?? 
            52 E8 ?? ?? ?? ?? 8D 45 ?? 50 6A ?? 57 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($enum_drives_p*)
        ) and
        (
            all of ($find_files_p*)
        ) and
        (
            $encrypt_files
        )
}