

rule Neo23x0_apt_MiniRAT_Gen_1 {
   meta:
      description = "Detects Mini RAT malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.eff.org/deeplinks/2018/01/dark-caracal-good-news-and-bad-news"
      date = "2018-01-22"
      hash1 = "091ae8d5649c4e040d25550f2cdf7f1ddfc9c698e672318eb1ab6303aa1cf85b"
      hash2 = "b6ac374f79860ae99736aaa190cce5922a969ab060d7ae367dbfa094bfe4777d"
      hash3 = "ba4e063472a2559b4baa82d5272304a1cdae6968145c5ef221295c90e88458e2"
      hash4 = "ed97719c008422925ae21ff34448a8c35ee270a428b0478e24669396761d0790"
      hash5 = "675c3d96070dc9a0e437f3e1b653b90dbc6700b0ec57379d4139e65f7d2799cd"
      id = "65d89762-2fd0-5c6a-b706-92d77a03089a"
   strings:
      $x1 = "\\Mini rat\\" ascii
      $x2 = "\\Projects\\ali\\Clever Components v7\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and 1 of them
}
