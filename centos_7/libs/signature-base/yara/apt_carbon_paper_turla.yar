import "pe"

rule Neo23x0_apt_generic_carbon
{
  meta:
    author      = "ESET Research"
    date        = "2017-03-30"
    description = "Turla Carbon malware"
    reference   = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

    id = "efdc0d16-a974-5c00-a401-391d60f3081e"
  strings:
    $s1 = "ModStart"
    $t1 = "STOP|OK"
    $t2 = "STOP|KILL"

  condition:
    (uint16(0) == 0x5a4d) and (1 of ($s*)) and (1 of ($t*))
}

rule Neo23x0_apt_carbon_metadata
{
  meta:
    author      = "ESET Research"
    date        = "2017-03-30"
    description = "Turla Carbon malware"
    reference   = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

    id = "976b6a7d-00bf-5d0f-baf9-84fc5dbd21a2"
   condition:
      (pe.version_info["InternalName"] contains "SERVICE.EXE" or
       pe.version_info["InternalName"] contains "MSIMGHLP.DLL" or
       pe.version_info["InternalName"] contains "MSXIML.DLL")
       and pe.version_info["CompanyName"] contains "Microsoft Corporation"
}
