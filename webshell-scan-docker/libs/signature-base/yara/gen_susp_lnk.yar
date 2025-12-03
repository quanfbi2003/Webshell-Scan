<<<<<<< Updated upstream:libs/signature-base/yara/gen_susp_lnk.yar

rule SUSP_LNK_Big_Link_File {
=======
//===SUCCESS===
rule Neo23x0_gen_susp_lnk_SUSP_LNK_Big_Link_File {
>>>>>>> Stashed changes:webshell-scan-docker/libs/signature-base/yara/gen_susp_lnk.yar
   meta:
      description = "Detects a suspiciously big LNK file - maybe with embedded content"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-05-15"
      score = 65
      id = "e130f213-53fc-56d6-b1d5-0508a7e18e61"
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and filesize > 200KB
}
