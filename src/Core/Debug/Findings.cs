using System;
using System.Collections.Generic;
using System.Linq;

namespace SymbolHunter.Core
{
    public enum Strength { None = 0, Weak = 1, Medium = 2, Strong = 3 }

    /// <summary>Catalogue of the kinds of debug evidence the scanner reports.</summary>
    public sealed class KindInfo
    {
        public string Id; public string Label; public Strength Strength; public string Category; public string Explain;
        public KindInfo(string id, string label, Strength s, string cat, string explain) { Id = id; Label = label; Strength = s; Category = cat; Explain = explain; }
    }

    public static class Kinds
    {
        public const string CodeView = "CODEVIEW", CodeViewPdb = "CV_PDBREF", BorlandTD = "BORLAND_TD", BorlandTDS = "BORLAND_TDS",
            BorlandTD32 = "BORLAND_TD32", Watcom = "WATCOM", Dwarf = "DWARF", Stabs = "STABS", Coff = "COFF_SYMS", Aout = "AOUT_SYMS",
            ElfSyms = "ELF_SYMS", PeDbgRef = "PE_DBGREF", LeDebug = "LE_DEBUG", Map = "MAP", MapSegs = "MAP_SEGS", Sym = "MAPSYM",
            Pdb = "PDB", Dbg = "DBG", OmfDebug = "OMF_DEBUG", OmfObj = "OMF_OBJ", CoffObj = "COFF_OBJ", Tpu = "TPU", Source = "SOURCE",
            Listing = "LISTING", Strings = "STRINGS", Hll = "HLL", NmSym = "NMSYM", Yara = "YARA";

        public static readonly Dictionary<string, KindInfo> All = new Dictionary<string, KindInfo>();
        static void Add(string id, string label, Strength s, string cat, string explain) { All[id] = new KindInfo(id, label, s, cat, explain); }

        static Kinds()
        {
            Add(CodeView, "Microsoft CodeView", Strength.Strong, "Symbols in EXE", "CodeView debug information appended to the executable (LINK /CO). Holds function, variable and type names, and usually source line numbers.");
            Add(CodeViewPdb, "CodeView PDB reference", Strength.Medium, "Symbol reference", "The executable points to a separate .PDB file that holds its symbols. Look for that PDB.");
            Add(BorlandTD, "Borland Turbo Debugger", Strength.Strong, "Symbols in EXE", "Turbo Debugger symbol table appended to the executable (TLINK /v, TPC /V). Holds symbol, module, type and line-number information.");
            Add(BorlandTDS, "Borland TDS symbol file", Strength.Strong, "Symbol file", "Separate Turbo Debugger symbol table (made by TDSTRIP or TLINK).");
            Add(BorlandTD32, "Borland TD32", Strength.Strong, "Symbols in EXE", "32-bit Borland debug information (FB09/FB0A).");
            Add(Watcom, "Watcom debug info", Strength.Strong, "Symbols in EXE", "Watcom debugging information appended to the executable (WLINK DEBUG ALL).");
            Add(Dwarf, "DWARF debug info", Strength.Strong, "Symbols in EXE", "DWARF debugging sections (gcc/DJGPP -g, Watcom DEBUG DWARF).");
            Add(Stabs, "stabs debug info", Strength.Strong, "Symbols in EXE", "stabs debugging sections (DJGPP/gcc -g).");
            Add(Coff, "COFF symbol table", Strength.Strong, "Symbols in EXE", "Unstripped COFF symbol table (DJGPP executables are not stripped by default).");
            Add(Aout, "a.out symbol table", Strength.Strong, "Symbols in EXE", "Unstripped a.out symbol table (DJGPP v1, EMX).");
            Add(ElfSyms, "ELF symbol table", Strength.Strong, "Symbols in EXE", "ELF .symtab with function names.");
            Add(PeDbgRef, "PE debug reference", Strength.Medium, "Symbol reference", "Windows executable that references a separate .DBG/.PDB symbol file.");
            Add(LeDebug, "LE/LX debug section", Strength.Strong, "Symbols in EXE", "Debug information declared in the LE/LX header (DOS/4GW or OS/2 executable).");
            Add(Hll, "IBM HLL debug info", Strength.Strong, "Symbols in EXE", "IBM HLL (CodeView-style NB04) debug information.");
            Add(Map, "Linker MAP file", Strength.Strong, "Symbol file", "Text map written by the linker: public symbol names with their addresses.");
            Add(MapSegs, "Linker MAP (segments only)", Strength.Medium, "Symbol file", "Linker map that lists segments but no public symbols.");
            Add(Sym, "MAPSYM .SYM file", Strength.Strong, "Symbol file", "Binary symbol file made by MAPSYM (SYMDEB, CodeView, WDEB386, Windows debug kernel).");
            Add(NmSym, "Symbol table file", Strength.Strong, "Symbol file", "Debugger symbol table file.");
            Add(Pdb, "Program database (PDB)", Strength.Strong, "Symbol file", "Microsoft Visual C++ program database.");
            Add(Dbg, "Separate debug file (DBG)", Strength.Strong, "Symbol file", "Windows NT style .DBG file with stripped symbols.");
            Add(OmfDebug, "Object/library with debug records", Strength.Strong, "Object code", "OMF object or library compiled with debug information (CodeView, Borland or Watcom records, line numbers).");
            Add(OmfObj, "Object/library (public names)", Strength.Medium, "Object code", "OMF object or library: contains public/external symbol names but no debug records.");
            Add(CoffObj, "COFF object with symbols", Strength.Medium, "Object code", "COFF object file with a symbol table.");
            Add(Yara, "YARA rule match", Strength.Medium, "Your YARA rules", "One of your own YARA rules matched this file. The rule's meta \"strength\" (strong/medium/weak) sets how it is ranked; \"description\" is shown in the details.");
            Add(Tpu, "Turbo Pascal unit", Strength.Medium, "Object code", "Compiled Turbo/Borland Pascal unit (symbol tables for the unit's interface and, with $D+, line numbers).");
            Add(Source, "Source code", Strength.Medium, "Source", "Program source code (C, C++, assembler, Pascal, BASIC, makefiles).");
            Add(Listing, "Compiler/assembler listing", Strength.Medium, "Source", "Listing file with code, addresses and usually a symbol table.");
            Add(Strings, "Debug strings", Strength.Weak, "Hints", "assert() messages or build-machine source paths left in the binary: a debug or development build is likely, but no symbol table was found.");
        }

        public static KindInfo Get(string id) { KindInfo k; return All.TryGetValue(id, out k) ? k : new KindInfo(id, id, Strength.Weak, "Other", ""); }
    }

    public sealed class Finding
    {
        public string Kind;
        public string Label;          // specific label, e.g. "Microsoft CodeView (NB09)"
        public Strength Strength;
        public string Detail = "";    // one-line summary: counts, versions
        public long Offset = -1;
        public long Size = -1;
        public List<string> Samples = new List<string>();   // sample names (modules, source files, symbols)

        public Finding(string kind, string detail, Strength? strength = null, string label = null)
        {
            Kind = kind;
            var k = Kinds.Get(kind);
            Strength = strength ?? k.Strength;
            Label = label ?? k.Label;
            Detail = detail ?? "";
        }

        public override string ToString()
        {
            var s = Label + (Detail.Length > 0 ? ": " + Detail : "");
            if (Samples.Count > 0) s += " [" + string.Join(", ", Samples.Take(8)) + (Samples.Count > 8 ? ", ..." : "") + "]";
            return s;
        }
    }
}
