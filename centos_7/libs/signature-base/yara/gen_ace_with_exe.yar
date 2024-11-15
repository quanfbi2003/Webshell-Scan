

rule Neo23x0_gen_ACE_Containing_EXE {
    meta:
        author = "Florian Roth (Nextron Systems) - based on Nick Hoffman' rule - Morphick Inc"
        description = "Looks for ACE Archives containing an exe/scr file"
        date = "2015-09-09"
        score = 50
        id = "0756f0e7-39f1-572d-a77d-1f7826332360"
    strings:
        $header = { 2a 2a 41 43 45 2a 2a }
        $extensions1 = ".exe" 
        $extensions2 = ".EXE"
        $extensions3 = ".scr"
        $extensions4 = ".SCR"
    condition:
        $header at 7 and for
        any of ($extensions*): (
            $ in (81..(81+uint16(79)))
        )
}
