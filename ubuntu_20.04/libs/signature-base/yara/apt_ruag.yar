

rule Neo23x0_apt_RUAG_Tavdig_Malformed_Executable {
  meta:
    description = "Detects an embedded executable with a malformed header - known from Tavdig malware"
    author = "Florian Roth (Nextron Systems)"
    reference = "https://goo.gl/N5MEj0"
    score = 60
    id = "da6357d4-0cdb-5f30-9919-59858963cc41"
  condition:
    uint16(0) == 0x5a4d and /* MZ Header */
    uint32(uint32(0x3C)) == 0x0000AD0B /* malformed PE header > 0x0bad */
}

rule Neo23x0_apt_RUAG_Bot_Config_File {
  meta:
    description = "Detects a specific config file used by malware in RUAG APT case"
    author = "Florian Roth (Nextron Systems)"
    reference = "https://goo.gl/N5MEj0"
    score = 60
    id = "aa3d5f9e-0b23-5180-9e52-a7d705712747"
  strings:
    $s1 = "[CONFIG]" ascii
    $s2 = "name = " ascii
    $s3 = "exe = cmd.exe" ascii
  condition:
    uint32(0) == 0x4e4f435b and $s1 at 0 and $s2 and $s3 and filesize < 160
}

rule Neo23x0_apt_RUAG_Cobra_Malware {
  meta:
    description = "Detects a malware mentioned in the RUAG Case called Carbon/Cobra"
    author = "Florian Roth (Nextron Systems)"
    reference = "https://goo.gl/N5MEj0"
    score = 60
    id = "dd2d591f-6f56-5c31-9f3c-3aa7d174c9a0"
  strings:
    $s1 = "\\Cobra\\Release\\Cobra.pdb" ascii
  condition:
    uint16(0) == 0x5a4d and $s1
}

rule Neo23x0_apt_RUAG_Cobra_Config_File {
  meta:
    description = "Detects a config text file used by malware Cobra in RUAG case"
    author = "Florian Roth (Nextron Systems)"
    reference = "https://goo.gl/N5MEj0"
    score = 60
    id = "b3899d95-acc9-55ca-9025-edecce755ca6"
  strings:
    $h1 = "[NAME]" ascii

    $s1 = "object_id=" ascii
    $s2 = "[TIME]" ascii fullword
    $s3 = "lastconnect" ascii
    $s4 = "[CW_LOCAL]" ascii fullword
    $s5 = "system_pipe" ascii
    $s6 = "user_pipe" ascii
    $s7 = "[TRANSPORT]" ascii
    $s8 = "run_task_system" ascii
    $s9 = "[WORKDATA]" ascii
    $s10 = "address1" ascii
  condition:
    uint32(0) == 0x4d414e5b and $h1 at 0 and 8 of ($s*) and filesize < 5KB
}

rule Neo23x0_apt_RUAG_Exfil_Config_File {
  meta:
    description = "Detects a config text file used in data exfiltration in RUAG case"
    author = "Florian Roth (Nextron Systems)"
    reference = "https://goo.gl/N5MEj0"
    score = 60
    id = "7057bc7b-7f8c-5db8-b7f3-f6c33487b122"
  strings:
    $h1 = "[TRANSPORT]" ascii

    $s1 = "system_pipe" ascii
    $s2 = "spstatus" ascii
    $s3 = "adaptable" ascii
    $s4 = "post_frag" ascii
    $s5 = "pfsgrowperiod" ascii
  condition:
    uint32(0) == 0x4152545b and $h1 at 0 and all of ($s*) and filesize < 1KB
}
