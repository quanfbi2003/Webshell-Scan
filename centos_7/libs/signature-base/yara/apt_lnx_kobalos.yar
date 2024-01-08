

rule Neo23x0_apt_APT_MAL_LNX_Kobalos {
    meta:
        description = "Kobalos malware"
        author = "Marc-Etienne M.Leveille"
        date = "2020-11-02"
        reference = "https://www.welivesecurity.com/2021/02/02/kobalos-complex-linux-threat-high-performance-computing-infrastructure/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

        id = "dfa47e30-c093-57f6-af01-72a2534cc6f4"
    strings:
        $encrypted_strings_sizes = {
            05 00 00 00 09 00 00 00  04 00 00 00 06 00 00 00
            08 00 00 00 08 00 00 00  02 00 00 00 02 00 00 00
            01 00 00 00 01 00 00 00  05 00 00 00 07 00 00 00
            05 00 00 00 05 00 00 00  05 00 00 00 0A 00 00 00
        }
        $password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
        $rsa_512_mod_header = { 10 11 02 00 09 02 00 }
        $strings_rc4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }

    condition:
        uint16(0) == 0x457f and /* modification by Florian Roth to avoid false posirives */
        any of them
}

rule Neo23x0_apt_APT_MAL_LNX_Kobalos_SSH_Credential_Stealer {
    meta:
        description = "Kobalos SSH credential stealer seen in OpenSSH client"
        author = "Marc-Etienne M.Leveille"
        date = "2020-11-02"
        reference = "https://www.welivesecurity.com/2021/02/02/kobalos-complex-linux-threat-high-performance-computing-infrastructure/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

        id = "0f923f92-c5d8-500d-9a2e-634ca7945c5c"
    strings:
        $ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

    condition:
        uint16(0) == 0x457f and /* modification by Florian Roth to avoid false posirives */
        any of them
}
