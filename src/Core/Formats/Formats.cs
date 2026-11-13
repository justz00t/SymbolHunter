namespace SymbolHunter.Core
{
    public static class Formats
    {
        public const string SupportedText =
@"ARCHIVES
  ZIP          PKZIP 0.9-2.x and later: Stored, Shrunk, Reduced 1-4, Imploded, Deflated, Deflate64,
               BZip2, LZMA, PPMd, XZ; ZIP64; self-extracting (PKSFX); split (.Z01...) and spanned sets
               (also renamed sets such as GAME1.ZIP, GAME2.ZIP)
  ARJ          methods 0-4, multi-volume (.ARJ .A01 .A02 ... or GAME1.ARJ GAME2.ARJ), self-extracting
  LZH / LHA    LHarc and LHA: -lh0- -lh1- -lh4- -lh5- -lh6- -lh7- -lzs- -lz4- -lz5-, header levels 0-3,
               self-extracting
  ARC / PAK    SEA ARC, PKARC, PKPAK: stored, packed, squeezed, crunched (old and new), squashed
  ZOO          stored, LZW, LZH
  RAR          1.3/1.4 (old 'RE~^' format), 1.5, 2.x, 2.9/3.x, 5.x, solid, multi-volume
               (.RAR .R00 ... and .part1.rar ...)
  7-Zip        LZMA, LZMA2, PPMd, BZip2, Deflate, BCJ/BCJ2, Delta, solid
  CAB          stored, MSZIP, Quantum, LZX; cabinet sets; cabinets stored inside other files
  ACE          1.x and 2.0: stored, LZ77, blocked with delta/EXE/sound/picture filters, solid,
               multi-volume (.ACE .C00 .C01 ...), self-extracting
  Others       MS-DOS COMPRESS/EXPAND (SZDD, KWAJ), InstallShield 3 (.Z), PKWARE DCL,
               gzip, bzip2, xz, Unix compress (.Z), tar, raw split files (.001 .002 ...)

DISK IMAGES
  FAT12/16/32 floppy and hard-disk images (IMG, IMA, VFD, DSK, 360, 720, 144, DMF ...),
  DOS 1.x disks without a BPB, partitioned hard disks (MBR, extended partitions), VHD,
  deleted files are recovered when their clusters are still free
  ISO 9660 / Joliet / High Sierra CD images, raw 2352/2336/2448-byte sector images (BIN, IMG, MDF, NRG, CDI)
  Teledisk TD0 (normal and advanced compression), ImageDisk IMD, CopyQM CQM
  MAME CHD v3-v5 hard disks and CD-ROMs: zlib, LZMA, Huffman, FLAC, cdzl, cdlz, cdfl; clone CHDs
  are read together with their parent CHD when it is in the same or a neighbouring folder

DEBUG INFORMATION
  Microsoft CodeView NB00-NB11 (MS C, QuickC, QuickBASIC, MASM, Zortech, Watcom), PDB references
  Borland Turbo Debugger (Turbo C/C++, Borland C++, Turbo Pascal, TASM), TDS files, TD32
  Watcom debug info, DWARF, stabs, COFF and a.out symbol tables (DJGPP, EMX), LE/LX debug sections
  Linker MAP files (MS LINK, TLINK, WLINK, GNU ld), MAPSYM .SYM files, PDB and DBG files
  OMF objects and libraries with debug records, Turbo Pascal units, source code and listings
  Weak hints: assert() messages and build paths
  Your own YARA rules (Tools > Options, or a ""rules"" folder next to the program)

NOT SUPPORTED (reported in the problems list)
  HA, SQZ, encrypted entries, flux/bitstream floppy images (HFE, SCP, IPF),
  zstd-compressed CHDs, LaserDisc CHDs

DAMAGED FILES
  Truncated downloads, CRC errors and bad sectors are reported in the problems list; everything
  that can still be read (entries before the damage, sectors that survived) is scanned anyway.";
    }
}
