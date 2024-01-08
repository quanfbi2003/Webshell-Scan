

rule Neo23x0_gen_Office_DDEAUTO_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 60
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.{1,1000}?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.{1,1000}?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}

rule Neo23x0_gen_Office_DDE_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 40
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}

rule Neo23x0_gen_Office_OLE_DDEAUTO {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 30
      id = "2ead3cc9-f517-5916-93c9-1393362aa45d"
   strings:
      $a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase
   condition:
      uint32be(0) == 0xD0CF11E0 and $a
}

rule Neo23x0_gen_Office_OLE_DDE {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 50
      id = "2ead3cc9-f517-5916-93c9-1393362aa45d"
   strings:
      $a = /\x13\s*DDE\b[^\x14]+/ nocase

      $r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
      $r2 = "Adobe ARM Installer"
   condition:
      uint32be(0) == 0xD0CF11E0 and $a and not 1 of ($r*)
}
