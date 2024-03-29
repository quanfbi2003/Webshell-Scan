

rule Neo23x0_cri_MAL_crime_win32_loader_guloader_1_experimental {
   meta:
      description = "Detects injected GuLoader shellcode bin"
      author = "@VK_Intel"
      reference = "https://twitter.com/VK_Intel/status/1257206565146370050"
      tlp = "white"
      date = "2020-05-04"
      id = "c37882c6-15dc-54dc-8c10-7e91ea0fc6bd"
   strings:
      $djib2_hash = { f8 8b ?? ?? ?? ba 05 15 00 00 89 d3 39 c0 c1 e2 05 81 ff f6 62 f1 87 01 da 0f ?? ?? d9 d0 01 da 83 c6 02 66 ?? ?? ?? 75 ?? c2 04 00}
      $nt_inject_loader = {8b ?? ?? ba 44 1a 0e 9e 39 d2 e8 ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? f8 ba d0 e0 8b 30 e8 ?? ?? ?? ?? d9 d0 89 ?? ?? d9 d0 81 fb 20 af 00 00 8b ?? ?? 39 c9 ba 92 a7 f3 95 e8 ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? 39 d2 ba d0 20 2e d0 e8 ?? ?? ?? ?? 89 ?? ?? f8 8b ?? ?? ba 6a 19 1f 23 d9 d0 e8 ?? ?? ?? ?? d9 d0 89 ?? ?? 81 fb e4 8c 00 00 39 c9 8b ?? ?? ba 19 50 9c c2 e8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 39 d2 8b ?? ?? fc ba 3d 13 8e 8b e8 ?? ?? ?? ?? d9 d0 89 ?? ?? f8 8b ?? ?? ba 30 3d 7b 2c e8 ?? ?? ?? ??}
   condition:
      uint16(0) == 0x5a4d and all of them 
}
