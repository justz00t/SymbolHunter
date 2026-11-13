/*
   Symbol Hunter - YARA rules for debug information from the later 1990s and the 2000s
   (Windows 95-XP era PC software, PlayStation / PS2 / N64 / GameCube / Dreamcast / Xbox era console builds, Java).
   Symbol Hunter loads these automatically. They also work with plain YARA on loose files.
   Strength: strong = real symbol table, medium = developer leftover, weak = hint only.
*/

rule PDB_Program_Database_V2
{
    meta:
        description = "Microsoft PDB 2.0 symbol file (Visual C++ 4-6, 1995-2001): full function and variable names"
        strength = "strong"
    strings:
        $sig = "Microsoft C/C++ program database 2.00\r\n\x1aJG"
    condition:
        $sig at 0
}

rule PDB_Program_Database_V7
{
    meta:
        description = "Microsoft PDB 7.0 symbol file (Visual Studio .NET 2002 and later): full function and variable names"
        strength = "strong"
    strings:
        $sig = "Microsoft C/C++ MSF 7.00\r\n\x1aDS"
    condition:
        $sig at 0
}

rule Windows_DBG_Symbol_File
{
    meta:
        description = "Windows .DBG separate debug file (symbols split from an EXE/DLL with REBASE or SPLITSYM)"
        strength = "strong"
    condition:
        filesize > 48 and uint16(0) == 0x4944 and uint16(2) == 0 and
        (uint16(4) == 0x014C or uint16(4) == 0x0166 or uint16(4) == 0x0184 or uint16(4) == 0x01F0 or uint16(4) == 0x01A2 or uint16(4) == 0x01C0)
}

rule PE_With_COFF_Symbol_Table
{
    meta:
        description = "Windows EXE/DLL that still has its COFF symbol table (not stripped: MinGW, Cygwin, LCC, old Microsoft linkers, Xbox tools)"
        strength = "strong"
    condition:
        uint16(0) == 0x5A4D and uint32(0x3C) < filesize - 24 and
        uint32(uint32(0x3C)) == 0x00004550 and
        uint32(uint32(0x3C) + 12) > 0 and uint32(uint32(0x3C) + 12) < filesize and
        uint32(uint32(0x3C) + 16) > 8 and uint32(uint32(0x3C) + 16) < 0x200000
}

rule COFF_Object_With_CodeView_Sections
{
    meta:
        description = "Object file or library with Microsoft CodeView sections (.debug$S / .debug$T): compiled with /Zi or /Z7"
        strength = "strong"
    strings:
        $s = ".debug$S"
        $t = ".debug$T"
    condition:
        $s and $t and uint16(0) != 0x5A4D
}

rule Microsoft_Incremental_Link_File
{
    meta:
        description = "Microsoft .ILK incremental-link file: a build leftover that lists the linked objects and symbols"
        strength = "medium"
    strings:
        $sig = "Microsoft Linker Database"
    condition:
        $sig at 0
}

rule ELF_With_Symbol_Table
{
    meta:
        description = "ELF program that is not stripped (.symtab and .strtab present): PlayStation 2, PSP, GameCube/Wii, Dreamcast, N64 tool output, Linux"
        strength = "strong"
    strings:
        $a = ".symtab\x00"
        $b = ".strtab\x00"
    condition:
        uint32(0) == 0x464C457F and $a and $b
}

rule ELF_With_Debug_Sections
{
    meta:
        description = "ELF program with debug sections (DWARF .debug_info/.debug_line, stabs, or MIPS .mdebug): source lines and types"
        strength = "strong"
    strings:
        $d1 = ".debug_info\x00"
        $d2 = ".debug_line\x00"
        $d3 = ".stabstr\x00"
        $d4 = ".mdebug\x00"
        $d5 = ".debug_abbrev\x00"
        $d6 = ".line\x00.debug\x00"
    condition:
        uint32(0) == 0x464C457F and any of them
}

rule PlayStation_PsyQ_SYM_File
{
    meta:
        description = "PlayStation Psy-Q .SYM symbol file (MND header): function names, source files and line numbers of a PS1 game"
        strength = "strong"
    strings:
        $sig = { 4D 4E 44 01 }
    condition:
        $sig at 0 and filesize > 16
}

rule PlayStation_PsyQ_Map_Or_CPE
{
    meta:
        description = "Psy-Q linker leftover: CPE development executable or Psy-Q link map (PlayStation / Saturn)"
        strength = "medium"
    strings:
        $cpe = { 43 50 45 01 }
        $map1 = "Psy-Q Linker" nocase
        $map2 = "PSYLINK" nocase
        $map3 = "Start     Stop      Length      Obj Group"
    condition:
        ($cpe at 0 and filesize > 32) or any of ($map*)
}

rule Stabs_Type_Strings
{
    meta:
        description = "stabs debug strings (gcc -g): type and variable descriptions, found in a.out, COFF, ELF and console builds"
        strength = "strong"
    strings:
        $s1 = "int:t1=r1;"
        $s2 = "char:t2=r2;0;127;"
        $s3 = "int:t(0,1)=r(0,1);"
        $s4 = "long int:t(0,3)=r(0,3);"
        $s5 = "long int:t3=r1;"
        $s6 = "unsigned int:t4=r4;"
    condition:
        any of them
}

rule GCC_Compiled_Marker
{
    meta:
        description = "gcc2_compiled. marker or GNU C producer string: object code built by GCC with its symbols or DWARF producer record left in"
        strength = "medium"
    strings:
        $a = "gcc2_compiled."
        $b = /GNU C(\+\+)? [0-9]\.[0-9]{1,2}(\.[0-9]{1,2})?[ \x00(]/
        $c = "___gnu_compiled_c"
        $d = /GNU AS [0-9]\.[0-9]{1,2}/
    condition:
        any of them
}

rule DWARF_Producer_Other_Compilers
{
    meta:
        description = "Compiler producer string from debug info (Metrowerks CodeWarrior, SN Systems, Green Hills, ARM SDT/ADS, Hitachi SH)"
        strength = "medium"
    strings:
        $m1 = /Metrowerks (C\/C\+\+|CodeWarrior)[ -~]{0,40}(Version|version|v)[ ]?[0-9]/
        $m2 = "MW MIPS C Compiler"
        $m3 = "MW EABI PPC C-Compiler"
        $m4 = /SN Systems[ -~]{0,30}(Linker|Assembler|ProDG)/
        $m5 = /Green Hills (Software|C|C\+\+)/
        $m6 = /Norcroft[ -~]{0,20}ARM C/
        $m7 = /ARM (C|C\+\+) Compiler, (ADS|RVCT|SDT)/
        $m8 = "Hitachi SuperH"
    condition:
        any of them
}

rule GNU_Linker_Map_File
{
    meta:
        description = "GNU ld link map (-Map): every function and variable with its address; common with console SDKs and DJGPP/MinGW"
        strength = "strong"
    strings:
        $a = "Linker script and memory map"
        $b = "Archive member included"
        $c = "Memory Configuration"
        $d = "Allocating common symbols"
        $e = /\n \.text +0x[0-9a-f]{8,16} +0x[0-9a-f]+ [ -~]+\.o/
    condition:
        2 of them
}

rule CodeWarrior_Link_Map
{
    meta:
        description = "Metrowerks CodeWarrior link map (GameCube, Wii, PS2, Mac, Palm): symbol names with addresses"
        strength = "strong"
    strings:
        $a = "Link map of "
        $b = /\n  [0-9a-f]{8} [0-9a-f]{6} [0-9a-f]{8} +[0-9]+ [ -~]+\.o/
        $c = ".text section layout"
        $d = "Memory map:"
        $e = /found in [ -~]{1,60}\.(o|a|lib)/
    condition:
        ($a in (0..64)) or ($c and ($b or $d)) or ($a and $e)
}

rule MSVC_Linker_Map_File
{
    meta:
        description = "Microsoft Visual C++ linker map (/MAP): public names by address, with the build timestamp"
        strength = "strong"
    strings:
        $a = " Preferred load address is "
        $b = " Timestamp is "
        $c = "Publics by Value"
        $d = "Rva+Base"
        $e = " entry point at "
    condition:
        uint16(0) != 0x5A4D and ($a or $b or $d) and 2 of them
}

rule Delphi_CBuilder_Map_File
{
    meta:
        description = "Borland Delphi / C++Builder detailed map file: units, publics and line numbers"
        strength = "strong"
    strings:
        $a = "Detailed map of segments"
        $b = /Line numbers for [ -~]{1,80}\([ -~]{1,80}\) segment/
        $c = "Bound resource files"
    condition:
        uint16(0) != 0x5A4D and any of them
}

rule Delphi_Embedded_Debug_Info
{
    meta:
        description = "Debug info embedded by Delphi add-ons (JCL JDBG, madExcept, EurekaLog, TD32 'FB0A' block): unit, procedure and line names"
        strength = "medium"
    strings:
        $j = "JCLDEBUG"
        $m1 = "madExcept"
        $m2 = "MAD\x00EXCEPT"
        $e = "EurekaLog"
    condition:
        uint16(0) == 0x5A4D and ($j or $m1 or $m2 or $e)
}

rule Java_Class_With_Debug_Tables
{
    meta:
        description = "Java class compiled with -g: local variable names and line numbers are kept"
        strength = "medium"
    strings:
        $a = "LocalVariableTable"
        $b = "LineNumberTable"
        $c = "SourceFile"
    condition:
        uint32be(0) == 0xCAFEBABE and $a and $b and $c
}

rule Xbox_XBE_Debug_Build
{
    meta:
        description = "Xbox executable with a developer build path or debug-kit signs (debug pathname, PDB reference)"
        strength = "medium"
    strings:
        $p1 = /[A-Za-z]:\\[ -~]{3,160}\.(exe|pdb)\x00/ nocase
        $p2 = /RSDS.{20}[^\x00]{1,200}\.pdb\x00/ nocase
        $p3 = /NB10.{12}[^\x00]{1,200}\.pdb\x00/ nocase
    condition:
        uint32(0) == 0x48454258 and any of them
}

rule MSVC_Debug_Runtime_Build
{
    meta:
        description = "Debug build of a Visual C++ program (debug C runtime / MFC, CRT debug reports): often shipped with symbols nearby"
        strength = "medium"
    strings:
        $d1 = "MSVCRTD.dll" nocase
        $d2 = /MSVC[RP][0-9]{2}D\.dll/ nocase
        $d3 = /MFC(O)?[0-9]{2}U?D\.DLL/ nocase
        $c1 = "_CrtDbgReport"
        $c2 = "Debug Assertion Failed!"
        $c3 = "_BLOCK_TYPE_IS_VALID(pHead->nBlockUse)"
        $c4 = "DAMAGE: after %hs block (#%d) at 0x%08X."
        $c5 = "Run-Time Check Failure #%d - %s"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Function_Name_Leftovers_In_Asserts
{
    meta:
        description = "Assert and trace text with source file names and line numbers (assert macros, __FILE__/__FUNCTION__ leftovers)"
        strength = "weak"
    strings:
        $a1 = "Assertion failed: %s, file %s, line %d"
        $a2 = "%s:%d: failed assertion `%s'"
        $a3 = "Assertion failed: (%s), function %s, file %s, line %d."
        $a4 = "assertion \"%s\" failed: file \"%s\", line %d"
        $a5 = /ASSERT(ION)?( FAILED)?: ?[ -~]{0,40}[\\\/][A-Za-z0-9_]{1,30}\.(c|cpp|cc|h|hpp)[ ,:(]+[0-9]{1,5}/ nocase
    condition:
        any of them
}

rule Unix_Archive_With_Symbol_Index
{
    meta:
        description = "Static library (.a / .lib) with its symbol index: lists every public function in the linked code"
        strength = "medium"
    strings:
        $ar = "!<arch>\n"
        $gnu = "__.SYMDEF"
        $elf = { 7F 45 4C 46 }
    condition:
        $ar at 0 and ($gnu or $elf)
}

rule Nintendo_Sega_SDK_Symbol_Leftovers
{
    meta:
        description = "Console SDK debug leftovers: N64 libultra debug strings, Dreamcast/Katana and Saturn SDK map or debug text"
        strength = "weak"
    strings:
        $n1 = "osSyncPrintf"
        $n2 = "rmonPrintf"
        $k1 = "KATANA" fullword
        $k2 = "Shinobi" fullword
        $s1 = "SEGA SEGASATURN"
        $g1 = "gdb stub" nocase
    condition:
        ($n1 or $n2) or ($g1 and ($k1 or $k2 or $s1))
}
