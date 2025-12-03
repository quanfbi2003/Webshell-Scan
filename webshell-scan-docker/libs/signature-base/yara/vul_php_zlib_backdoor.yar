<<<<<<< Updated upstream:libs/signature-base/yara/vul_php_zlib_backdoor.yar

rule VULN_PHP_Hack_Backdoored_Zlib_Zerodium_Mar21_1 {
=======
//===SUCCESS===
rule Neo23x0_vul_php_zlib_backdoor_VULN_PHP_Hack_Backdoored_Zlib_Zerodium_Mar21_1 {
>>>>>>> Stashed changes:webshell-scan-docker/libs/signature-base/yara/vul_php_zlib_backdoor.yar
   meta:
      description = "Detects backdoored PHP zlib version"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.bleepingcomputer.com/news/security/phps-git-server-hacked-to-add-backdoors-to-php-source-code/"
      date = "2021-03-29"
      id = "5e0ab8f8-776a-52b0-b5be-ff1d34bccfd1"
   strings:
      $x1 = "REMOVETHIS: sold to zerodium, mid 2017" fullword ascii
      $x2 = "HTTP_USER_AGENTT" ascii fullword
   condition:
      filesize < 3000KB and
      all of them
}
