<<<<<<< Updated upstream:centos_7/libs/signature-base/yara/susp_office_template_injection.yar


rule Neo23x0_sus_EXPL_Office_TemplateInjection_Aug19 {
=======
//===SUCCESS===
rule Neo23x0_susp_office_template_injection_EXPL_Office_TemplateInjection_Aug19 {
>>>>>>> Stashed changes:webshell-scan-upgrader/libs/signature-base/yara/susp_office_template_injection.yar
   meta:
      old_rule_name = "EXPL_Office_TemplateInjection"
      description = "Detects possible template injections in Office documents, particularly those that load content from external sources"
      author = "Florian Roth"
      reference = "https://attack.mitre.org/techniques/T1221/"
      date = "2019-08-22"
      modified = "2025-03-20"
      score = 75
      hash = "f2bdf3716b39d29a9c6c3b7b3355e935594b8d8e9149a784a59dc2381fa1628a"
   strings:
      $x1 = /attachedTemplate" Target="http[s]?:\/\/[^"]{4,60}/ ascii

      $fp1 = ".sharepoint.com"  // this could cause false negatives if the malicious template is hosted on sharepoint
      $fp2 = ".office.com"  // this could cause false negatives if the malicious template is hosted on office.com
   condition:
      filesize < 20MB
      and $x1
      and not 1 of ($fp*)
}
