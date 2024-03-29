

rule Neo23x0_cri_Cobaltgang_PDF_Metadata_Rev_A {
   meta:
      description = "Find documents saved from the same potential Cobalt Gang PDF template"
      author = "Palo Alto Networks Unit 42"
      date = "2018-10-25"
      reference = "https://researchcenter.paloaltonetworks.com/2018/10/unit42-new-techniques-uncover-attribute-cobalt-gang-commodity-builders-infrastructure-revealed/"
      id = "bcf5bf6e-c786-5f78-bf58-e0631a17e62e"
   strings:
      $ = "<xmpMM:DocumentID>uuid:31ac3688-619c-4fd4-8e3f-e59d0354a338" ascii wide
   condition:
      any of them
}
