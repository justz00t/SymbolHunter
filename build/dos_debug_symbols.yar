/*
   Symbol Hunter - YARA rules for DOS-era debug information (1985-1999)
   Exported by Symbol Hunter. These rules work on loose files. Symbol Hunter itself also
   looks inside archives (ZIP, ARJ, LZH, ARC, ZOO, RAR, CAB...) and disk images, and checks
   each structure more strictly than YARA can, so treat a YARA hit as "worth a look".
   Strength: strong = real symbol table, medium = developer leftover, weak = hint only.
*/

rule CodeView_NBxx_Symbols
{
    meta:
        description = "Microsoft CodeView symbols (NB00-NB11 signature and back-pointer at end of file): MS LINK /CO, QuickC, QuickBASIC, Watcom -d2 with CodeView, Zortech"
        strength = "strong"
    condition:
        filesize > 32 and
        uint16(filesize - 8) == 0x424E and
        uint8(filesize - 6) >= 0x30 and uint8(filesize - 6) <= 0x31 and
        uint8(filesize - 5) >= 0x30 and uint8(filesize - 5) <= 0x39 and
        uint32(filesize - 4) >= 16 and uint32(filesize - 4) <= filesize and
        uint32(filesize - uint32(filesize - 4)) == uint32(filesize - 8)
}

rule Borland_TD32_Symbols
{
    meta:
        description = "Borland 32-bit Turbo Debugger symbols (FB0x signature and back-pointer at end of file)"
        strength = "strong"
    condition:
        filesize > 32 and
        uint16(filesize - 8) == 0x4246 and uint8(filesize - 6) == 0x30 and
        uint32(filesize - 4) >= 16 and uint32(filesize - 4) <= filesize and
        uint32(filesize - uint32(filesize - 4)) == uint32(filesize - 8)
}

rule Borland_TurboDebugger_Symbols_In_EXE
{
    meta:
        description = "Borland Turbo Debugger symbols (magic FB 52) right after the DOS EXE image: Turbo C/C++, Borland C++, Turbo Pascal, TASM + TLINK /v"
        strength = "strong"
    condition:
        uint16(0) == 0x5A4D and uint16(4) > 0 and
        (
            (uint16(2) == 0 and uint16(uint16(4) * 512) == 0x52FB and uint8(uint16(4) * 512 + 3) <= 4) or
            (uint16(2) != 0 and uint16(2) < 512 and uint16((uint16(4) - 1) * 512 + uint16(2)) == 0x52FB and uint8((uint16(4) - 1) * 512 + uint16(2) + 3) <= 4)
        )
}

rule Borland_TurboDebugger_TDS_File
{
    meta:
        description = "Borland Turbo Debugger symbol file (.TDS, magic FB 52 at offset 0)"
        strength = "strong"
    condition:
        uint16(0) == 0x52FB and filesize > 48 and uint8(3) <= 4
}

rule Watcom_Debug_Info
{
    meta:
        description = "Watcom debug information (master header 0x8386 at end of file): Watcom C/C++, FORTRAN, wlink DEBUG ALL"
        strength = "strong"
    condition:
        filesize > 64 and uint16(filesize - 14) == 0x8386 and
        uint32(filesize - 4) >= 14 and uint32(filesize - 4) <= filesize
}

rule DJGPP_COFF_Symbol_Table
{
    meta:
        description = "COFF executable with a symbol table (DJGPP go32 stub + COFF, or plain COFF): gcc without -s"
        strength = "strong"
    condition:
        (uint16(0) == 0x014C and uint32(8) != 0 and uint32(12) > 0 and uint32(8) < filesize) or
        (uint16(0) == 0x5A4D and uint16(2) == 0 and uint16(uint16(4) * 512) == 0x014C and
            uint32(uint16(4) * 512 + 8) != 0 and uint32(uint16(4) * 512 + 12) > 0) or
        (uint16(0) == 0x5A4D and uint16(2) != 0 and uint16(2) < 512 and uint16((uint16(4) - 1) * 512 + uint16(2)) == 0x014C and
            uint32((uint16(4) - 1) * 512 + uint16(2) + 8) != 0 and uint32((uint16(4) - 1) * 512 + uint16(2) + 12) > 0)
}

rule DWARF_Or_Stabs_Sections
{
    meta:
        description = "DWARF or stabs debug sections (gcc -g; DJGPP, EMX, Watcom -hd)"
        strength = "strong"
    strings:
        $d1 = ".debug_info" ascii
        $d2 = ".debug_line" ascii
        $d3 = ".debug_abbrev" ascii
        $s1 = ".stabstr" ascii
    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x014C or uint32(0) == 0x464C457F) and (2 of ($d*) or $s1)
}

rule LE_LX_Debug_Section
{
    meta:
        description = "DOS extender / OS/2 LE or LX executable whose header points to debug information (DOS/4GW, PMODE/W, OS/2)"
        strength = "strong"
    condition:
        uint16(0) == 0x5A4D and uint32(0x3C) > 0x40 and uint32(0x3C) < filesize - 0xA0 and
        (uint16(uint32(0x3C)) == 0x454C or uint16(uint32(0x3C)) == 0x584C) and
        uint32(uint32(0x3C) + 0x98) != 0 and uint32(uint32(0x3C) + 0x9C) != 0 and
        uint32(uint32(0x3C) + 0x98) < filesize
}

rule Turbo_Pascal_Unit
{
    meta:
        description = "Turbo/Borland Pascal compiled unit (.TPU/.TPP/.TPW): symbol names of the unit's interface, plus line numbers when compiled with $D+"
        strength = "medium"
    strings:
        $tpu = /^TP[UPW][0-9A-Z]/
    condition:
        $tpu at 0 and filesize > 64
}

rule OMF_Object_With_CodeView_Types
{
    meta:
        description = "OMF object or library compiled with debug information ($$SYMBOLS / $$TYPES segments)"
        strength = "strong"
    strings:
        $sym = "$$SYMBOLS" ascii
        $typ = "$$TYPES" ascii
        $dsym = "DEBSYM" ascii
        $dtyp = "DEBTYP" ascii
    condition:
        (uint8(0) == 0x80 or uint8(0) == 0xF0) and ($sym or $typ or ($dsym and $dtyp))
}

rule Linker_Map_File
{
    meta:
        description = "Linker MAP file with public symbols (MS LINK, TLINK, Turbo Pascal, Watcom wlink, GNU ld)"
        strength = "strong"
    strings:
        $ms1 = "Publics by Value" ascii nocase
        $ms2 = "Publics by Name" ascii nocase
        $ms3 = " Start  Stop   Length Name" ascii nocase
        $ms4 = "Address         Publics by" ascii nocase
        $wat1 = "Memory Map" ascii
        $wat2 = "Symbol                      Address" ascii
        $wat3 = "Watcom Linker" ascii nocase
        $gnu1 = "Linker script and memory map" ascii
        $gnu2 = "Memory Configuration" ascii
    condition:
        filesize < 20MB and uint8(0) != 0x4D and
        ( ($ms3 and ($ms1 or $ms2 or $ms4)) or ($wat3 and ($wat1 or $wat2)) or ($gnu1 and $gnu2) )
}

rule MAPSYM_SYM_File
{
    meta:
        description = "MAPSYM symbol file (.SYM) for SYMDEB/CodeView/WDEB386"
        strength = "strong"
    condition:
        filesize > 32 and filesize < 8MB and
        uint16(0) != 0 and uint16(0) * 16 + 4 <= filesize and
        uint16(uint16(0) * 16) == 0 and uint8(uint16(0) * 16 + 3) >= 3 and uint8(uint16(0) * 16 + 3) <= 7 and
        uint16(8) >= 1 and uint16(8) <= 4096 and uint16(10) != 0 and uint16(10) * 16 < filesize and
        uint8(15) >= 1 and uint8(15) <= 64 and
        for all i in (0 .. uint8(15) - 1) : ( uint8(16 + i) > 0x20 and uint8(16 + i) < 0x7F )
}

rule Borland_OMF_Object_With_Debug_Info
{
    meta:
        description = "OMF object compiled by Borland tools with Turbo Debugger information (COMENT classes E0-E7): tcc/bcc -v, tasm /zi"
        strength = "strong"
    strings:
        $c = { 88 ?? 00 (00|40|80|C0) (E0|E1|E2|E3|E4|E5|E6|E7) }
    condition:
        uint8(0) == 0x80 and #c >= 2
}

rule PE_Debug_Reference_To_PDB
{
    meta:
        description = "Win32 executable referring to a separate PDB/DBG symbol file (NB10/RSDS record)"
        strength = "medium"
    strings:
        $nb10 = /NB10.{8}[^\x00]{1,200}\.pdb\x00/ nocase
        $rsds = /RSDS.{20}[^\x00]{1,200}\.pdb\x00/ nocase
        $dbg = /[A-Za-z]:\\[^\x00]{1,200}\.dbg\x00/ nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Developer_Leftover_Strings
{
    meta:
        description = "Hints of a development build: assert messages, source paths, debugger checks (also found in some release builds)"
        strength = "weak"
    strings:
        $a1 = "Assertion failed" ascii
        $a2 = /[A-Za-z]:\\[A-Za-z0-9_~\\.-]{2,80}\.(c|cpp|asm|pas|bas|for|inc)\x00/ nocase
        $a3 = "__FILE__" ascii
        $a4 = "DEBUG BUILD" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
