SYMBOL HUNTER 1.0
Finds debug symbols in DOS-era software inside old archives and disk images
==========================================================================

Symbol Hunter scans a folder (and its subfolders) of old downloads: ZIP, ARJ, LZH, ARC,
ZOO, RAR, ACE, CAB and other archives, multi-part sets, and the floppy, hard-disk and CD images
inside them. It opens everything in memory, nested as deep as needed (a disk image inside
an ARJ set inside a ZIP, for example). Nothing is extracted to your disk unless you ask.
It then lists every archive that contains debug information and says what kind it is.


REQUIREMENTS
  Windows 10 or 11 (Windows 7 SP1 and 8.1 also work once .NET Framework 4.8 is installed).
  There is nothing to install: SymbolHunter.exe is a single file.

  The program is not code-signed, so the first time you run it Windows SmartScreen may
  show "Windows protected your PC". Click "More info", then "Run anyway". If you extracted
  it from a ZIP, you can also right-click the exe > Properties > tick "Unblock".


HOW TO USE
  1. Start SymbolHunter.exe, choose the folder with your archives (Browse..., or drag a
     folder onto the window) and press Scan.
  2. The "Debug symbols found" tab lists the archives that contain debug information,
     with the strongest evidence first.
     - Click an archive name (blue link) to open its folder in Explorer with the file
       selected. The "Open in Explorer" button does the same for the selected row.
     - Select a row to see each file inside the archive that has debug information. The
       path shows where it was found, e.g.  GAME.ZIP > DISK1.IMG > SETUP.ARJ > GAME.EXE
     - "Extract file..." saves that inner file, so you can load it into your tools.
  3. "All scanned files" lists every item and what it was. "Could not be fully read" lists
     damaged or unsupported files (double-click to open their folder). "Log" shows progress.
  4. File > Export Results saves the list as an HTML report, CSV (Excel), JSON or text.
  5. "Show" picks how much to list:
       Symbol tables only           real symbol tables only (Strong)
       Symbols and dev leftovers    adds MAP files, object files, Pascal units, source (default)
       Everything, including hints  adds weak hints such as assert() messages and build paths


WHAT THE STRENGTHS MEAN
  Strong  A real symbol table: function and variable names, usually also line numbers.
          CodeView (MS C, QuickC, QuickBASIC, MASM, Zortech, Watcom), Borland Turbo
          Debugger (Turbo C/C++, Borland C++, Turbo Pascal, TASM), Watcom, DWARF/stabs/COFF
          (DJGPP, EMX), linker MAP files, MAPSYM .SYM files, debug-compiled .OBJ/.LIB files.
  Medium  Developer leftovers: object files and libraries with public names, Turbo Pascal
          units, source code, assembler listings, PDB references.
  Weak    Hints only (also found in some release builds): assert messages, build paths.


MULTI-PART ARCHIVES
  Split sets are joined automatically, including:
    ARJ .ARJ/.A01/.A02 ...   RAR .RAR/.R00 ... and .part1.rar ...   ZIP .Z01/.ZIP splits
    ACE .ACE/.C00/.C01 ...
    PKZIP spanned disks      renamed sets such as GAME1.ZIP GAME2.ZIP or GAME1.ARJ GAME2.ARJ
    raw .001/.002 splits     parts kept on different floppy images (DISK1.IMG holds .ARJ,
                             DISK2.IMG holds .A01)
  The later parts are shown as "part of a set" and are not counted twice. If a part is
  missing, everything that can be read is still scanned and the problem is reported.


DAMAGED DOWNLOADS
  Truncated archives, CRC errors and bad sectors are reported under "Could not be fully
  read". Everything before the damage, and every sector that survived, is still scanned.


COMMAND LINE
  SymbolHunter "D:\Old Games" /html report.html /csv list.csv
      [/json out.json] [/txt list.txt] [/min strong|medium|weak] [/threads N] [/depth N] [/nosub]
      [/rules file.yar or folder] [/yaracontainers]
  SymbolHunter /yara dos_debug_symbols.yar     writes the built-in YARA rules


YOUR OWN YARA RULES
  Symbol Hunter has YARA built in (libyara 4.6). Your rules run on every file it finds,
  including files inside archives and disk images, so nothing has to be extracted.
  - Tools > Options > "Add files..." or "Add folder..." (folders are searched with their
    subfolders for .yar and .yara files). "Check rules" compiles them and lists any errors.
  - Or put rule files in a folder named "rules" next to SymbolHunter.exe; it is always used.
  - Command line: /rules file.yar or /rules folder (can be given several times).
  - A file with errors is skipped and the error (file and line) is shown in the Log tab;
    the other files still run. include "other.yar" works, relative to the including file.
  - Matches appear in the results as "YARA: <rule name>" with the rule's description and the
    matched strings and offsets. Rules rank as Medium unless they set
    meta: strength = "strong" (or "medium" / "weak").
  - Modules pe, elf, math, hash, dotnet, macho, dex, time, string and console are available.
  - "Also run YARA rules on the archive and disk image files themselves" (Options) runs them
    on the containers too, not only on the files inside. Files over 128 MB are scanned in
    64 MB windows, so filesize and offset conditions only see one window at a time.
  - Like before, File > Export YARA Rules saves the built-in rules as dos_debug_symbols.yar
    (also in this package). Add that file to the list if you want those rules to run too;
    the program's own checks already cover the same formats more strictly.
  - The YARA library is built in for 64-bit, 32-bit and ARM64 Windows. If YARA cannot start,
    the scan still runs and the Log tab says why.
  - yara-examples\example_rules.yar in this package shows the meta fields Symbol Hunter uses.


BUILT-IN RULES FOR THE 1990s AND 2000s
  Besides the DOS-era detectors, 24 YARA rules for later debug information are built in and
  used automatically: PDB 2.0/7.0, .DBG files, COFF symbols in Windows programs, ELF symbol
  tables with DWARF or stabs, PlayStation Psy-Q .SYM, GNU / CodeWarrior / Visual C++ / Delphi
  map files, Java debug tables and debug-runtime builds. They are also supplied as
  debug_symbols_90s_00s.yar for use with plain YARA.


SUPPORTED FORMATS
  Archives
    ZIP      PKZIP 0.9 to modern: Stored, Shrunk, Reduced 1-4, Imploded, Deflated,
             Deflate64, BZip2, LZMA, PPMd, XZ; ZIP64; self-extracting; split and spanned
    ARJ      methods 0-4, multi-volume, self-extracting
    LZH/LHA  -lh0- -lh1- -lh4- to -lh7- -lzs- -lz4- -lz5-, header levels 0-3, self-extracting
    ARC/PAK  SEA ARC, PKARC, PKPAK: stored, packed, squeezed, crunched, squashed
    ZOO      stored, LZW, LZH
    RAR      1.3/1.4, 1.5, 2.x, 3.x, 5.x, solid, multi-volume
    ACE      1.x and 2.0: stored, LZ77, blocked with delta/EXE/sound/picture filters, solid,
             multi-volume (.ACE/.C00/.C01 ...), self-extracting
    7-Zip    LZMA, LZMA2, PPMd, BZip2, Deflate, BCJ/BCJ2, Delta, solid
    CAB      stored, MSZIP, Quantum, LZX, cabinet sets, cabinets inside other files
    Others   MS-DOS COMPRESS/EXPAND (SZDD, KWAJ), InstallShield 3, PKWARE DCL, gzip,
             bzip2, xz, Unix compress, tar
  Disk images
    FAT12/16/32 floppies and hard disks (IMG IMA VFD DSK ...), DOS 1.x disks, MBR and
    extended partitions, VHD, deleted-file recovery, ISO 9660/Joliet/High Sierra CDs,
    BIN/MDF/NRG/CDI raw sectors, Teledisk TD0, ImageDisk IMD, CopyQM CQM
  Not supported (reported as "Unsupported"): HA, SQZ, password-protected entries,
    flux-level floppy images (HFE, SCP, IPF; convert those to IMG first).


HOW IT WAS TESTED
  Real compiler output. Debug and release builds of the same small game were made with
    Turbo C 2.0, Turbo C++ 1.0, Turbo Pascal 5.5 and 7.0, TASM, MASM 5, Microsoft C 5.1,
    QuickC 2.5, QuickBASIC 4.5, Zortech C 3.0, Watcom C (DOS, DOS/4GW, Win16) and DJGPP.
    Every debug build is found with the right type. Every release build is clean, or shows
    only a weak hint.
  Regression set: 109 of 109 test items give the expected result. They cover those builds
    packed in every supported archive and image type (now including ACE and RAR 1.3, single
    and multi-volume), multi-part sets with all the naming styles above, sets spread across
    floppy images, deleted files, nested containers, truncated
    downloads, CRC errors, bad sectors and random junk named like archives.
  Decompression: 113 of 113 reference archives (from the 7-Zip, SharpCompress, libmspack,
    acefile and patool test suites) extract with matching checksums, including a real
    5.6 MB solid ACE 2.0 archive with 247 files.
  YARA: the built-in libyara was checked on Windows (64-bit library under Wine) and Linux:
    rules with include, tags, meta and modules, broken rule files reported with file and line.
  Disk images: 48 of 48 real floppy images from the PCjs collection give file-for-file the
    same contents as 7-Zip. 20 more that 7-Zip cannot open (such as DOS 1.x disks) are read too.
  Real-world sweep: about 2,600 files (original compiler distribution disks, PCjs DOS
    software, archive test suites) scanned in under a minute. The 24 symbol-table hits were
    checked by hand and all are genuine; no false positives, crashes or hangs.
  Robustness: 38 fuzzing rounds, each
    damaging every test archive and image 8-9 ways (truncation, flipped bits, zeroed
    sectors, junk blocks, swapped blocks; about 30,000 damaged files in all). None crashed or
    hung the program, and every problem was reported. Two crashes in the bundled BZip2 decoder
    on damaged data were found this way and fixed.
  Not tested with real samples: ACE 2.0 sound and picture compression (no such archives were
    available; the code follows the reference decoder).


THIRD-PARTY CODE
  SharpCompress (MIT license) for RAR and 7-Zip decoding. libyara (BSD 3-Clause license,
  VirusTotal) for YARA, built with the mingw-w64 runtime and LLVM compiler-rt (permissive
  licenses). The ACE decoder follows acefile by Daniel Roethlisberger (BSD 2-Clause).
