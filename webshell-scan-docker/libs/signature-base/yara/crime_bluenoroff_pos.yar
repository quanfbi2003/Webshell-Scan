<<<<<<< Updated upstream:libs/signature-base/yara/crime_bluenoroff_pos.yar

rule BluenoroffPoS_DLL {
=======
//===SUCCESS===
rule Neo23x0_crime_bluenoroff_pos_BluenoroffPoS_DLL {
>>>>>>> Stashed changes:webshell-scan-docker/libs/signature-base/yara/crime_bluenoroff_pos.yar
   meta:
      description = "Bluenoroff POS malware - hkp.dll"
      author = "http://blog.trex.re.kr/"
      reference = "http://blog.trex.re.kr/3?category=737685"
      date = "2018-06-07"
      id = "d2b34b50-c7eb-5852-ba5d-734dd5038c2e"
   strings:
      $dll = "ksnetadsl.dll" ascii wide fullword nocase
      $exe = "xplatform.exe" ascii wide fullword nocase
      $agent = "Nimo Software HTTP Retriever 1.0" ascii wide nocase
      $log_file = "c:\\windows\\temp\\log.tmp" ascii wide nocase
      $base_addr = "%d-BaseAddr:0x%x" ascii wide nocase
      $func_addr = "%d-FuncAddr:0x%x" ascii wide nocase
      $HF_S = "HF-S(%d)" ascii wide
      $HF_T = "HF-T(%d)" ascii wide
   condition:
      5 of them
}
