

rule Neo23x0_apt_PrikormkaDropper
{
    strings:
        $kd1 = "KDSTORAGE" wide
        $kd2 = "KDSTORAGE_64" wide
        $kd3 = "KDRUNDRV32" wide
        $kd4 = "KDRAR" wide

        $bin1 = {69 65 04 15 00 14 1E 4A 16 42 08 6C 21 61 24 0F}
        $bin2 = {76 6F 05 04 16 1B 0D 5E 0D 42 08 6C 20 45 18 16}
        $bin3 = {4D 00 4D 00 43 00 00 00 67 00 75 00 69 00 64 00 56 00 47 00 41 00 00 00 5F 00 73 00 76 00 67 00}

        $inj1 = "?AVCinj2008Dlg@@" ascii
        $inj2 = "?AVCinj2008App@@" ascii
    condition:
        uint16(0) == 0x5a4d and ((any of ($bin*)) or (3 of ($kd*)) or (all of ($inj*)))
}

rule Neo23x0_apt_PrikormkaModule
{
    strings:
        // binary
        $str1 = {6D 70 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
        $str2 = {68 6C 70 75 63 74 66 2E 64 6C 6C 00 43 79 63 6C 65}
        $str3 = {00 6B 6C 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
        $str4 = {69 6F 6D 75 73 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67}
        $str5 = {61 74 69 6D 6C 2E 64 6C 6C 00 4B 69 63 6B 49 6E 50 6F 69 6E 74}
        $str6 = {73 6E 6D 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}
        $str7 = {73 63 72 73 68 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}

        // encrypted
        $str8 = {50 52 55 5C 17 51 58 17 5E 4A}
        $str9 = {60 4A 55 55 4E 53 58 4B 17 52 57 17 5E 4A}
        $str10 = {55 52 5D 4E 5B 4A 5D 17 51 58 17 5E 4A}
        $str11 = {60 4A 55 55 4E 61 17 51 58 17 5E 4A}
        $str12 = {39 5D 17 1D 1C 0A 3C 57 59 3B 1C 1E 57 58 4C 54 0F}

        // mutex
        $str13 = "ZxWinDeffContex" ascii wide
        $str14 = "Paramore756Contex43" wide
        $str15 = "Zw_&one@ldrContext43" wide

        // other
        $str16 = "A95BL765MNG2GPRS"

        // dll names
        $str17 = "helpldr.dll" wide fullword
        $str18 = "swma.dll" wide fullword
        $str19 = "iomus.dll" wide fullword
        $str20 = "atiml.dll"  wide fullword
        $str21 = "hlpuctf.dll" wide fullword
        $str22 = "hauthuid.dll" ascii wide fullword

        // rbcon
        $str23 = "[roboconid][%s]" ascii fullword
        $str24 = "[objectset][%s]" ascii fullword
        $str25 = "rbcon.ini" wide fullword

        // files and logs
        $str26 = "%s%02d.%02d.%02d_%02d.%02d.%02d.skw" ascii fullword
        $str27 = "%02d.%02d.%02d_%02d.%02d.%02d.%02d.rem" wide fullword

        // pdb strings
        $str28 = ":\\!PROJECTS!\\Mina\\2015\\" ascii
        $str29 = "\\PZZ\\RMO\\" ascii
        $str30 = ":\\work\\PZZ" ascii
        $str31 = "C:\\Users\\mlk\\" ascii
        $str32 = ":\\W o r k S p a c e\\" ascii
        $str33 = "D:\\My\\Projects_All\\2015\\" ascii
        $str34 = "\\TOOLS PZZ\\Bezzahod\\" ascii

    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule Neo23x0_apt_PrikormkaEarlyVersion
{
    strings:
        $str1 = "IntelRestore" ascii fullword
        $str2 = "Resent" wide fullword
        $str3 = "ocp8.1" wide fullword
        $str4 = "rsfvxd.dat" ascii fullword
        $str5 = "tsb386.dat" ascii fullword
        $str6 = "frmmlg.dat" ascii fullword
        $str7 = "smdhost.dll" ascii fullword
        $str8 = "KDLLCFX" wide fullword
        $str9 = "KDLLRUNDRV" wide fullword
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}
