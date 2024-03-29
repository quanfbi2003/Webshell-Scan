

rule Neo23x0_gen_SUSP_GObfuscate_May21 {
   meta:
      description = "Identifies binaries obfuscated with gobfuscate"
      author = "James Quinn"
      reference = "https://github.com/unixpickle/gobfuscate"
      date = "2021-05-14"
      score = 70
      id = "ae518296-b1c3-568c-bae0-3e0a6f7600ba"
   strings:
      $s1 = { 0f b6 ?? ?? ?? 0f b6 ?? ?? ?? 31 D1 88 ?? ?? ?? 48 FF C0 48 83 f8 ?? 7c E7 48 C7 }
      $s2 = { 0F b6 ?? ?? ?? 31 DA 88 ?? ?? ?? 40 83 ?? ?? 7D 09 0F B6 }
   condition:
      filesize < 50MB and any of them
}
