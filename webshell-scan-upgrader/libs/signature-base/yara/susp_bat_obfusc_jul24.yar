<<<<<<< Updated upstream:centos_7/libs/signature-base/yara/susp_bat_obfusc_jul24.yar


rule Neo23x0_sus_SUSP_BAT_OBFUSC_Jul24_1 {
=======
<<<<<<<< Updated upstream:libs/signature-base/yara/susp_bat_obfusc_jul24.yar

rule SUSP_BAT_OBFUSC_Jul24_1 {
========
//===SUCCESS===
rule Neo23x0_susp_bat_obfusc_jul24_SUSP_BAT_OBFUSC_Jul24_1 {
>>>>>>>> Stashed changes:webshell-scan-upgrader/libs/signature-base/yara/susp_bat_obfusc_jul24.yar
>>>>>>> Stashed changes:webshell-scan-upgrader/libs/signature-base/yara/susp_bat_obfusc_jul24.yar
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
      score = 70
      id = "801e7efc-2c31-5590-afcd-9e11072c9c65"
   strings:
      $s1 = "&&set "
   condition:
      filesize < 300KB  
      and uint32(0) == 0x20746573 // "set " at the beginning of the file
      and $s1 in (0..32) // "&&set " in the first 32 bytes
}
<<<<<<< Updated upstream:centos_7/libs/signature-base/yara/susp_bat_obfusc_jul24.yar

rule Neo23x0_sus_SUSP_BAT_OBFUSC_Jul24_2 {
=======
<<<<<<<< Updated upstream:libs/signature-base/yara/susp_bat_obfusc_jul24.yar

rule SUSP_BAT_OBFUSC_Jul24_2 {
========
//===SUCCESS===
rule Neo23x0_susp_bat_obfusc_jul24_SUSP_BAT_OBFUSC_Jul24_2 {
>>>>>>>> Stashed changes:webshell-scan-upgrader/libs/signature-base/yara/susp_bat_obfusc_jul24.yar
>>>>>>> Stashed changes:webshell-scan-upgrader/libs/signature-base/yara/susp_bat_obfusc_jul24.yar
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
      score = 70
      id = "999cd365-2862-5618-b0b6-ee45dea1e9cf"
   strings:
      $s1 = "&&set "
   condition:
      filesize < 300KB
      // number of occurrences of the string "&&set " in the file
      and #s1 > 30
      // it's the "%\n" at the very end of the file
      and uint16(filesize-2) == 0x0a0d
      and uint8(filesize-3) == 0x25
}
<<<<<<< Updated upstream:centos_7/libs/signature-base/yara/susp_bat_obfusc_jul24.yar

rule Neo23x0_sus_SUSP_BAT_OBFUSC_Jul24_3 {
=======
<<<<<<<< Updated upstream:libs/signature-base/yara/susp_bat_obfusc_jul24.yar

rule SUSP_BAT_OBFUSC_Jul24_3 {
========
//===SUCCESS===
rule Neo23x0_susp_bat_obfusc_jul24_SUSP_BAT_OBFUSC_Jul24_3 {
>>>>>>>> Stashed changes:webshell-scan-upgrader/libs/signature-base/yara/susp_bat_obfusc_jul24.yar
>>>>>>> Stashed changes:webshell-scan-upgrader/libs/signature-base/yara/susp_bat_obfusc_jul24.yar
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
      score = 70
      id = "a484ed03-8588-55e7-9674-b1208e14eb3f"
   strings:
      $s1 = "% \\\\%" // part of the UNC path for the SMB connection
      // It detects the set pattern with a single character value in front of the %%
      // we use ?? to wildcard the character
      // =?&&set 
      $s2 = { 3D ?? 26 26 73 65 74 20 } 
   condition:
      filesize < 300KB
      and all of them
}
