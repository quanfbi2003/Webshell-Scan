<<<<<<< Updated upstream:libs/signature-base/yara/mixed_open_source_export.yar

rule SUSP_LNK_Suspicious_Folders_Jan25 {
=======
//===SUCCESS===
rule Neo23x0_mixed_open_source_export_SUSP_LNK_Suspicious_Folders_Jan25 {
>>>>>>> Stashed changes:webshell-scan-docker/libs/signature-base/yara/mixed_open_source_export.yar
   meta:
      description = "Detects link files (.LNK) with suspicious folders mentioned in the target path"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-01-24"
      score = 65
      id = "5f1bcd18-abec-5831-b24f-519c92a2454e"
   strings:
      $x1 = "RECYCLER.BIN\\" wide
      $x2 = "Perflogs\\" wide
   condition:
      uint16(0) == 0x004c
      and 1 of them
}
