/*
   Example YARA rules for Symbol Hunter.
   Add this file (or a folder of your own .yar files) in Tools > Options, or copy it into a
   folder named "rules" next to SymbolHunter.exe. Every file Symbol Hunter finds - also inside
   archives, disk images and CHDs - is checked against your rules.

   meta: strength = "strong" | "medium" | "weak"  sets how a match is ranked (default medium)
   meta: description = "..."                      is shown in the results
*/

rule Borland_Copyright_In_DOS_EXE : borland
{
    meta:
        description = "DOS executable built with a Borland compiler (copyright string in the runtime)"
        strength = "weak"
    strings:
        $b = "Borland" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $b
}

rule Developer_Source_Path
{
    meta:
        description = "Absolute path of a C/C++/Pascal/assembler source file left in the binary"
        strength = "medium"
    strings:
        $p = /[A-Za-z]:\\[A-Za-z0-9_~\\.-]{2,80}\.(c|cpp|asm|pas|h|inc)\x00/ nocase
    condition:
        $p
}

rule Debug_Build_Strings
{
    meta:
        description = "Text that usually only appears in debug or beta builds"
        strength = "medium"
    strings:
        $a = "DEBUG MODE" ascii nocase
        $b = "cheat mode" ascii nocase
        $c = "BETA VERSION" ascii nocase
        $d = "internal use only" ascii nocase
    condition:
        any of them
}
