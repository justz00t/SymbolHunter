using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SymbolHunter.Core
{
    public sealed class ScanResult
    {
        public List<Finding> Findings = new List<Finding>();
        public string FileType = "";       // "DOS MZ", "NE (Win16)", "Linker map" ...
        public string Packer;              // PKLITE, LZEXE ...
        public Strength Best { get { return Findings.Count == 0 ? Strength.None : Findings.Max(f => f.Strength); } }
    }

    /// <summary>Finds debug information in a single (already extracted) file.</summary>
    public static class DebugScanner
    {
        const int HeadSize = 256 * 1024, TailSize = 64 * 1024;

        public static ScanResult Scan(DataSource src, string name)
        {
            var r = new ScanResult();
            long len = src.Length;
            if (len < 4) return r;
            byte[] head = src.ReadBytes(0, (int)Math.Min(len, HeadSize));
            byte[] tail = len <= head.Length ? head : src.ReadBytes(len - TailSize, TailSize);
            string ext = PathUtil.Ext(name);
            var ctx = new Ctx { Src = src, Head = head, Tail = tail, Len = len, Name = name, Ext = ext, R = r };

            try
            {
                CheckCodeViewTrailer(ctx);
                CheckTd32Trailer(ctx);
                CheckWatcomTrailer(ctx);
                CheckTisTrailer(ctx);

                if (len >= 28 && (Bin.Match(head, 0, "MZ") || Bin.Match(head, 0, "ZM"))) ScanMz(ctx);
                else if (Bin.U16(head, 0) == 0x52FB) CheckTdAt(ctx, 0, true);
                else if (Bin.Match(head, 0, "\u007fELF")) ScanElf(ctx, 0, "ELF");
                else if (Bin.U16(head, 0) == 0x014C && LooksLikeCoff(ctx, 0)) ScanCoff(ctx, 0, false);
                else if (Bin.Match(head, 0, "Microsoft C/C++ program database") || Bin.Match(head, 0, "Microsoft C/C++ MSF 7.00"))
                { r.FileType = "PDB"; Add(ctx, new Finding(Kinds.Pdb, Bin.Match(head, 0, "Microsoft C/C++ MSF") ? "MSF 7.00 (VC++ 7+)" : "PDB 2.00 (VC++ 2-6)")); }
                else if (Bin.Match(head, 0, "DI") && ext == ".dbg") ScanDbg(ctx);
                else if (head[0] == 0x80 || head[0] == 0x82 || head[0] == 0xF0) ScanOmf(ctx);
                else if (Bin.Match(head, 0, "TPU") || Bin.Match(head, 0, "TPW") || Bin.Match(head, 0, "TPP")) ScanTpu(ctx);
                if (ext == ".sym" || ext == ".nms" || ext == ".map") CheckMapSym(ctx);

                if (IsText(head, len)) ScanText(ctx);
            }
            catch (Exception ex)
            {
                r.Findings.Add(new Finding(Kinds.Strings, "scanner error: " + ex.Message, Strength.None, "Scanner error"));
                r.Findings.RemoveAll(f => f.Strength == Strength.None);
            }

            // drop weak hints when real symbols were found
            if (r.Findings.Any(f => f.Strength == Strength.Strong)) r.Findings.RemoveAll(f => f.Kind == Kinds.Strings);
            return r;
        }

        sealed class Ctx
        {
            public DataSource Src; public byte[] Head, Tail; public long Len; public string Name, Ext; public ScanResult R;
            public long TailBase { get { return Len - Tail.Length; } }
        }

        static void Add(Ctx c, Finding f)
        {
            // one finding per kind; keep the more detailed one
            var old = c.R.Findings.FirstOrDefault(x => x.Kind == f.Kind);
            if (old != null)
            {
                if (old.Samples.Count >= f.Samples.Count && old.Detail.Length >= f.Detail.Length) return;
                c.R.Findings.Remove(old);
            }
            c.R.Findings.Add(f);
        }

        // ------------------------------------------------------------------ trailers

        static void CheckCodeViewTrailer(Ctx c)
        {
            var t = c.Tail; int tl = t.Length;
            if (tl < 16) return;
            if (t[tl - 8] != 'N' || t[tl - 7] != 'B' || !char.IsDigit((char)t[tl - 6]) || !char.IsDigit((char)t[tl - 5])) return;
            string sig = Bin.Ascii(t, tl - 8, 4);
            long off = Bin.U32(t, tl - 4);
            if (off < 16 || off > c.Len) return;
            long start = c.Len - off;
            var sh = c.Src.ReadBytes(start, 8);
            if (sh.Length < 8 || Bin.Ascii(sh, 0, 4) != sig) return;
            var f = new Finding(Kinds.CodeView, "", null, "Microsoft CodeView (" + sig + ")");
            f.Offset = start; f.Size = off;
            long lfoDir = Bin.U32(sh, 4);
            var info = ParseCvDirectory(c, start, lfoDir, off, sig, f);
            f.Detail = sig + " " + CvVersionName(sig) + ", " + Fmt.Size(off) + (info.Length > 0 ? ", " + info : "");
            if (sig == "NB10") { f.Kind = Kinds.CodeViewPdb; f.Strength = Strength.Medium; f.Label = "CodeView PDB reference"; }
            if (sig == "NB04") { f.Kind = Kinds.Hll; f.Label = "IBM HLL debug info (NB04)"; }
            Add(c, f);
        }

        static string CvVersionName(string sig)
        {
            switch (sig)
            {
                case "NB00": case "NB01": return "(CodeView 1-2, MS C 4/5 era)";
                case "NB02": return "(CodeView 3, LINK < 5.20)";
                case "NB04": return "(IBM HLL)";
                case "NB05": return "(CodeView 4, unpacked)";
                case "NB06": case "NB07": return "(QuickC for Windows)";
                case "NB08": return "(CodeView 4.00-4.05)";
                case "NB09": return "(CodeView 4.10, MS C 7 / VC 1.x)";
                case "NB10": return "(PDB reference)";
                case "NB11": return "(CodeView 5, VC 2-4 32-bit)";
                default: return "";
            }
        }

        static string ParseCvDirectory(Ctx c, long start, long lfoDir, long total, string sig, Finding f)
        {
            try
            {
                if (lfoDir <= 0 || lfoDir >= total) return "";
                var d = c.Src.ReadBytes(start + lfoDir, 16);
                if (d.Length < 4) return "";
                int modules = 0, entries = 0;
                var names = new List<string>();
                if (d.Length >= 16 && Bin.U16(d, 0) == 16 && Bin.U16(d, 2) == 12)
                {
                    // CV4 directory
                    long cDir = Bin.U32(d, 4);
                    if (cDir <= 0 || cDir > 200000) return "";
                    var ents = c.Src.ReadBytes(start + lfoDir + 16, (int)cDir * 12);
                    for (int i = 0; i + 12 <= ents.Length; i += 12)
                    {
                        int sst = Bin.U16(ents, i); long lfo = Bin.U32(ents, i + 4); long cb = Bin.U32(ents, i + 8);
                        entries++;
                        if (sst == 0x120)
                        {
                            modules++;
                            if (names.Count < 40 && cb < 65536 && lfo < total)
                            {
                                var m = c.Src.ReadBytes(start + lfo, (int)cb);
                                if (m.Length >= 8)
                                {
                                    int cSeg = Bin.U16(m, 4); int no = 8 + cSeg * 12;
                                    if (no < m.Length) { int nl = m[no]; if (nl > 0 && no + 1 + nl <= m.Length) names.Add(Bin.Ascii(m, no + 1, nl)); }
                                }
                            }
                        }
                    }
                }
                else
                {
                    // CodeView 1-3 directory: WORD count, entries { WORD sst, WORD module, DWORD lfo, WORD cb }
                    int cnt = Bin.U16(d, 0);
                    if (cnt <= 0 || cnt > 60000) return "";
                    var ents = c.Src.ReadBytes(start + lfoDir + 2, cnt * 10);
                    int good = 0;
                    for (int i = 0; i + 10 <= ents.Length; i += 10)
                    {
                        int sst = Bin.U16(ents, i); long lfo = Bin.U32(ents, i + 4); int cb = Bin.U16(ents, i + 8);
                        if (sst >= 0x101 && sst <= 0x10F && lfo < total) good++;
                        entries++;
                        if (sst == 0x101)
                        {
                            modules++;
                            if (names.Count < 40 && lfo + cb <= total && cb > 0)
                            {
                                var m = c.Src.ReadBytes(start + lfo, Math.Min(cb, 300));
                                // sstModules (old): WORD cs, WORD off, WORD cb, WORD ovl, then length-prefixed name at +8 (+10 for some)
                                foreach (int no in new[] { 8, 10, 12 })
                                    if (no < m.Length && m[no] > 0 && no + 1 + m[no] <= m.Length && Bin.IsPrintable(m, no + 1, m[no])) { names.Add(Bin.Ascii(m, no + 1, m[no])); break; }
                            }
                        }
                    }
                    if (good * 2 < entries) return "";
                }
                f.Samples.AddRange(PreferSourceNames(names));
                return modules > 0 ? modules + " modules" : entries + " subsections";
            }
            catch { return ""; }
        }

        static void CheckTd32Trailer(Ctx c)
        {
            var t = c.Tail; int tl = t.Length;
            if (tl < 16) return;
            if (t[tl - 8] != 'F' || t[tl - 7] != 'B' || t[tl - 6] != '0' || !IsHexDigit(t[tl - 5])) return;
            string sig = Bin.Ascii(t, tl - 8, 4);
            long off = Bin.U32(t, tl - 4);
            if (off < 16 || off > c.Len) return;
            var sh = c.Src.ReadBytes(c.Len - off, 4);
            if (Bin.Ascii(sh, 0, 4) != sig) return;
            var f = new Finding(Kinds.BorlandTD32, sig + ", " + Fmt.Size(off)) { Offset = c.Len - off, Size = off };
            Add(c, f);
        }

        static bool IsHexDigit(byte b) { return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F'); }

        static void CheckWatcomTrailer(Ctx c)
        {
            var t = c.Tail; int tl = t.Length;
            if (tl < 14) return;
            int o = tl - 14;
            if (Bin.U16(t, o) != 0x8386) return;
            int exeMaj = t[o + 2], exeMin = t[o + 3], objMaj = t[o + 4], objMin = t[o + 5];
            int langSize = Bin.U16(t, o + 6), segSize = Bin.U16(t, o + 8);
            long dbgSize = Bin.U32(t, o + 10);
            if (exeMaj < 1 || exeMaj > 9 || dbgSize < 14 + langSize + segSize || dbgSize > c.Len || langSize == 0 || langSize > 4096) return;
            long start = c.Len - dbgSize;
            var lang = c.Src.ReadBytes(start, langSize);
            var langs = new List<string>();
            int p = 0;
            while (p < lang.Length)
            {
                int e = Array.IndexOf(lang, (byte)0, p);
                if (e < 0) e = lang.Length;
                if (e > p) { if (!Bin.IsPrintable(lang, p, e - p)) return; langs.Add(Bin.Ascii(lang, p, e - p)); }
                p = e + 1;
            }
            if (langs.Count == 0) return;
            var f = new Finding(Kinds.Watcom, "version " + exeMaj + "." + exeMin + ", " + Fmt.Size(dbgSize) + ", languages: " + string.Join("/", langs)) { Offset = start, Size = dbgSize };
            Add(c, f);
        }

        static void CheckTisTrailer(Ctx c)
        {
            var t = c.Tail; int tl = t.Length;
            if (tl < 16) return;
            int o = tl - 16;
            if (!(t[o] == 'T' && t[o + 1] == 'I' && t[o + 2] == 'S' && t[o + 3] == 0)) return;
            long size = Bin.U32(t, o + 12);
            if (size < 16 || size > c.Len) return;
            long start = c.Len - size;
            var h = c.Src.ReadBytes(start, 4);
            if (Bin.Match(h, 0, "\u007fELF")) ScanElf(c, start, "Watcom TIS DWARF container");
            else Add(c, new Finding(Kinds.Dwarf, "TIS trailer, " + Fmt.Size(size)) { Offset = start, Size = size });
        }

        // ------------------------------------------------------------------ Borland TD

        /// <summary>Validates a Turbo Debugger symbol table header at pos. Returns true and adds a finding.</summary>
        static bool CheckTdAt(Ctx c, long pos, bool standalone, bool atImageEnd = false)
        {
            var h = c.Src.ReadBytes(pos, 48);
            if (h.Length < 48 || Bin.U16(h, 0) != 0x52FB) return false;
            int ver = Bin.U16(h, 2);
            int major = ver >> 8, minor = ver & 0xFF;
            if (major < 1 || major > 8) return false;
            long namesz = Bin.U32(h, 4);
            int names = Bin.U16(h, 8), types = Bin.U16(h, 10), members = Bin.U16(h, 12), symbols = Bin.U16(h, 14), globals = Bin.U16(h, 16),
                modules = Bin.U16(h, 18), locals = Bin.U16(h, 20), scopes = Bin.U16(h, 22), lines = Bin.U16(h, 24), srcfiles = Bin.U16(h, 26),
                segments = Bin.U16(h, 28);
            int extSize = Bin.U16(h, 46);
            long remain = c.Len - pos - 48;
            if (names < 1 || namesz < names * 2L || namesz > remain || modules < 1 || symbols < 1 || globals > symbols + 1000 || srcfiles > modules + 1000) return false;

            // strong check: the name pool sits at the end of the debug info (end of file) and holds 'names' strings
            bool poolOk = false; List<string> pool = null;
            if (namesz <= 8 * 1024 * 1024)
            {
                var pb = c.Src.ReadBytes(c.Len - namesz, (int)namesz);
                if (pb.Length == namesz && pb[pb.Length - 1] == 0)
                {
                    int cnt = 0; bool printable = true;
                    for (int i = 0; i < pb.Length; i++) { if (pb[i] == 0) cnt++; else if (pb[i] < 0x20 || pb[i] == 0x7F) { printable = false; break; } }
                    if (printable && cnt == names) { poolOk = true; pool = SplitNul(pb); }
                }
            }
            if (!poolOk && !atImageEnd && !standalone) return false;
            if (!poolOk && extSize > 8192) return false;

            var f = new Finding(standalone ? Kinds.BorlandTDS : Kinds.BorlandTD, "") { Offset = pos, Size = c.Len - pos };
            if (standalone) c.R.FileType = "Borland TDS symbol file";
            var sb = new StringBuilder();
            sb.Append("TD format " + major + "." + minor.ToString("00") + ": ");
            sb.Append(modules + " modules, " + symbols + " symbols, " + types + " types");
            if (lines > 0) sb.Append(", line numbers");
            if (srcfiles > 0) sb.Append(", " + srcfiles + " source file" + (srcfiles == 1 ? "" : "s"));
            if (!poolOk) sb.Append(" (name pool not at end of file)");
            f.Detail = sb.ToString();
            if (pool != null) f.Samples.AddRange(PreferSourceNames(pool));
            Add(c, f);
            return true;
        }

        static List<string> SplitNul(byte[] b)
        {
            var l = new List<string>(); int p = 0;
            while (p < b.Length) { int e = Array.IndexOf(b, (byte)0, p); if (e < 0) e = b.Length; if (e > p) l.Add(Encoding.ASCII.GetString(b, p, e - p)); p = e + 1; }
            return l;
        }

        static readonly Regex srcName = new Regex(@"\.(c|cpp|cxx|cc|h|hpp|asm|inc|pas|bas|for|f|mod|def)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly HashSet<string> runtimeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "_main", "main", "_exit", "exit", "_printf", "printf", "_malloc", "_free", "_abort", "_atexit", "DGROUP@", "_brk", "_sbrk" };

        /// <summary>Source file names first, then user-looking symbol names.</summary>
        static IEnumerable<string> PreferSourceNames(List<string> names)
        {
            var src = names.Where(n => srcName.IsMatch(n)).Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToList();
            var other = names.Where(n => !srcName.IsMatch(n) && n.Length > 1 && !n.StartsWith("__") && !n.StartsWith("@") && !n.EndsWith("@") && !runtimeNames.Contains(n) && n.Any(char.IsLetter))
                             .Distinct().Take(12 - Math.Min(src.Count, 6)).ToList();
            return src.Concat(other).Take(12);
        }

        /// <summary>Scans a region for an embedded TD header (Borland apps with overlays or Windows executables).</summary>
        static bool SearchTd(Ctx c, long from, long to)
        {
            if (to - from < 48) return false;
            to = Math.Min(to, from + 128L * 1024 * 1024);
            var buf = new byte[1 << 20];
            for (long p = from; p < to; p += buf.Length - 1)
            {
                int n = c.Src.Read(p, buf, 0, (int)Math.Min(buf.Length, to - p));
                if (n < 2) break;
                for (int i = 0; i + 1 < n; i++)
                    if (buf[i] == 0xFB && buf[i + 1] == 0x52 && CheckTdAt(c, p + i, false)) return true;
                if (n < buf.Length) break;
            }
            return false;
        }

        // ------------------------------------------------------------------ MZ and friends

        static void ScanMz(Ctx c)
        {
            var h = c.Head;
            int cblp = Bin.U16(h, 2), cp = Bin.U16(h, 4), hdrParas = Bin.U16(h, 8), lfarlc = Bin.U16(h, 0x18);
            long imageEnd = (long)cp * 512 - (cblp != 0 && cblp < 512 ? 512 - cblp : 0);
            if (imageEnd <= 0 || imageEnd > c.Len) imageEnd = c.Len;
            long lfanew = 0;
            if (h.Length >= 0x40 && (lfarlc >= 0x40 || hdrParas >= 4)) lfanew = Bin.U32(h, 0x3C);
            string newSig = null;
            if (lfanew >= 0x40 && lfanew + 4 <= c.Len)
            {
                var ns = c.Src.ReadBytes(lfanew, 4);
                if (Bin.Match(ns, 0, "PE\0\0")) newSig = "PE";
                else if (Bin.Match(ns, 0, "NE")) newSig = "NE";
                else if (Bin.Match(ns, 0, "LE")) newSig = "LE";
                else if (Bin.Match(ns, 0, "LX")) newSig = "LX";
                else if (Bin.Match(ns, 0, "W3") || Bin.Match(ns, 0, "W4")) newSig = "VXD";
            }
            c.R.FileType = "DOS MZ executable";
            c.R.Packer = DetectPacker(h);

            if (newSig == "PE") ScanPe(c, lfanew);
            else if (newSig == "NE") { c.R.FileType = "NE executable (Win16/OS2)"; }
            else if (newSig == "LE" || newSig == "LX") ScanLe(c, lfanew, newSig);
            else if (newSig == "VXD") c.R.FileType = "Windows VxD";

            bool hasStrong = c.R.Findings.Any(f => f.Strength == Strength.Strong);
            if (newSig == null)
            {
                // DOS extender payloads directly after the stub
                if (imageEnd + 20 <= c.Len)
                {
                    var p = c.Src.ReadBytes(imageEnd, 64);
                    int m16 = Bin.U16(p, 0);
                    if (m16 == 0x014C) { if (LooksLikeCoff(c, imageEnd)) ScanCoff(c, imageEnd, true); }
                    else if ((m16 == 0x010B || m16 == 0x0107 || m16 == 0x0108) && HasGo32OrEmx(h)) ScanAout(c, imageEnd);
                    else if (Bin.Match(p, 0, "P3") || Bin.Match(p, 0, "MP")) c.R.FileType = "Phar Lap executable";
                }
                if (Bin.IndexOf(h, "go32stub", 0, Math.Min(h.Length, 8192)) >= 0 && c.R.FileType == "DOS MZ executable") c.R.FileType = "DJGPP executable";
            }

            if (!c.R.Findings.Any(f => f.Kind == Kinds.BorlandTD))
            {
                bool found = false;
                if (imageEnd + 48 <= c.Len && newSig == null) found = CheckTdAt(c, imageEnd, false, true);
                if (!found)
                {
                    long from = newSig == null ? imageEnd : Math.Min(lfanew, imageEnd);
                    if (newSig != null) from = lfanew;
                    SearchTd(c, from, c.Len);
                }
            }

            // ELF container appended (Watcom DWARF) or DWARF in overlay
            if (!c.R.Findings.Any(f => f.Kind == Kinds.Dwarf) && imageEnd < c.Len && newSig == null)
            {
                var ov = c.Src.ReadBytes(imageEnd, (int)Math.Min(c.Len - imageEnd, 4 * 1024 * 1024));
                int e = Bin.IndexOf(ov, "\u007fELF", 0, ov.Length);
                if (e >= 0) ScanElf(c, imageEnd + e, "ELF in overlay");
            }

            if (!c.R.Findings.Any(f => f.Strength == Strength.Strong)) ScanStrings(c);
        }

        static bool HasGo32OrEmx(byte[] h)
        {
            int lim = Math.Min(h.Length, 16384);
            return Bin.IndexOf(h, "go32", 0, lim) >= 0 || Bin.IndexOf(h, "emx", 0, lim) >= 0 || Bin.IndexOf(h, "GO32", 0, lim) >= 0;
        }

        static string DetectPacker(byte[] h)
        {
            if (h.Length < 0x40) return null;
            if (Bin.IndexOf(h, "PKLITE", 0, Math.Min(h.Length, 0x80)) >= 0) return "PKLITE";
            if (Bin.Match(h, 0x1C, "LZ09") || Bin.Match(h, 0x1C, "LZ91")) return "LZEXE";
            if (Bin.IndexOf(h, "diet", 0, Math.Min(h.Length, 0x100)) >= 0 || Bin.IndexOf(h, "dlz", 0, Math.Min(h.Length, 0x100)) >= 0) return "DIET";
            if (Bin.IndexOf(h, "Packed file is corrupt", 0, Math.Min(h.Length, 0x10000)) >= 0) return "EXEPACK";
            if (Bin.IndexOf(h, "UPX!", 0, Math.Min(h.Length, 0x1000)) >= 0) return "UPX";
            return null;
        }

        static void ScanPe(Ctx c, long peOff)
        {
            var hd = c.Src.ReadBytes(peOff, 24 + 240);
            if (hd.Length < 24) return;
            int machine = Bin.U16(hd, 4), nsec = Bin.U16(hd, 6);
            long symPtr = Bin.U32(hd, 12), nSyms = Bin.U32(hd, 16);
            int optSize = Bin.U16(hd, 20), chars = Bin.U16(hd, 22);
            int magic = Bin.U16(hd, 24);
            c.R.FileType = (magic == 0x20B ? "PE32+ " : "PE32 ") + (machine == 0x14C ? "i386" : machine == 0x8664 ? "x64" : "machine " + Bin.Hex(machine)) + ((chars & 0x2000) != 0 ? " DLL" : " executable");
            if (nSyms > 0 && symPtr > 0 && symPtr + nSyms * 18 <= c.Len)
                Add(c, new Finding(Kinds.Coff, nSyms + " COFF symbols in PE image") { Offset = symPtr, Size = nSyms * 18 });
            if (optSize < 96) return;
            int ddOff = 24 + (magic == 0x20B ? 112 : 96);
            var opt = c.Src.ReadBytes(peOff + 24, optSize);
            int numDirs = (int)Bin.U32(opt, magic == 0x20B ? 108 : 92);
            if (numDirs <= 6) return;
            long dbgRva = Bin.U32(opt, ddOff - 24 + 6 * 8), dbgSize = Bin.U32(opt, ddOff - 24 + 6 * 8 + 4);
            var secs = c.Src.ReadBytes(peOff + 24 + optSize, Math.Min(nsec, 96) * 40);
            Func<long, long> rva2off = rva =>
            {
                for (int i = 0; i + 40 <= secs.Length; i += 40)
                {
                    long va = Bin.U32(secs, i + 12), vs = Math.Max(Bin.U32(secs, i + 8), Bin.U32(secs, i + 16)), raw = Bin.U32(secs, i + 20);
                    if (rva >= va && rva < va + vs) return raw + (rva - va);
                }
                return -1;
            };
            if (dbgRva == 0 || dbgSize == 0) return;
            long dOff = rva2off(dbgRva);
            if (dOff < 0) return;
            var dd = c.Src.ReadBytes(dOff, (int)Math.Min(dbgSize, 28 * 32));
            for (int i = 0; i + 28 <= dd.Length; i += 28)
            {
                long type = Bin.U32(dd, i + 12), size = Bin.U32(dd, i + 16), ptr = Bin.U32(dd, i + 24);
                if (size == 0 || ptr == 0 || ptr >= c.Len) continue;
                var rec = c.Src.ReadBytes(ptr, (int)Math.Min(size, 4096));
                if (type == 2 && rec.Length >= 8)
                {
                    string sig = Bin.Ascii(rec, 0, 4);
                    if (sig == "RSDS") Add(c, new Finding(Kinds.CodeViewPdb, "RSDS -> " + Bin.Ascii(rec, 24, rec.Length - 24), null, "PDB reference (RSDS)"));
                    else if (sig == "NB10") Add(c, new Finding(Kinds.CodeViewPdb, "NB10 -> " + Bin.Ascii(rec, 16, rec.Length - 16), null, "PDB reference (NB10)"));
                    else if (sig.StartsWith("NB")) Add(c, new Finding(Kinds.CodeView, sig + " " + CvVersionName(sig) + " in PE debug directory, " + Fmt.Size(size), null, "Microsoft CodeView (" + sig + ")") { Offset = ptr, Size = size });
                }
                else if (type == 1) Add(c, new Finding(Kinds.Coff, "COFF debug information, " + Fmt.Size(size)) { Offset = ptr, Size = size });
                else if (type == 4)
                {
                    var m = Regex.Match(Encoding.ASCII.GetString(rec), @"[\x20-\x7e]{3,200}\.dbg", RegexOptions.IgnoreCase);
                    Add(c, new Finding(Kinds.PeDbgRef, m.Success ? "symbols moved to " + m.Value : "misc debug record"));
                }
            }
        }

        static void ScanLe(Ctx c, long le, string sig)
        {
            var h = c.Src.ReadBytes(le, 0xB0);
            c.R.FileType = sig == "LE" ? "LE executable (DOS/4GW or VxD)" : "LX executable (OS/2)";
            if (h.Length < 0xA0) return;
            long dbgOff = Bin.U32(h, 0x98), dbgLen = Bin.U32(h, 0x9C);
            if (dbgLen == 0 || dbgOff == 0) return;
            long[] cands = { dbgOff, le + dbgOff };
            foreach (var o in cands)
            {
                if (o <= 0 || o + Math.Min(dbgLen, 8) > c.Len) continue;
                var d = c.Src.ReadBytes(o, 16);
                if (d.Length >= 4 && d[0] == 'N' && d[1] == 'B')
                {
                    string s = Bin.Ascii(d, 0, 4);
                    Add(c, new Finding(s == "NB04" ? Kinds.Hll : Kinds.CodeView, s + " in LE/LX debug section, " + Fmt.Size(dbgLen), null, s == "NB04" ? "IBM HLL debug info" : "Microsoft CodeView (" + s + ")") { Offset = o, Size = dbgLen });
                    return;
                }
            }
            if (!c.R.Findings.Any(f => f.Strength == Strength.Strong))
                Add(c, new Finding(Kinds.LeDebug, Fmt.Size(dbgLen) + " of debug data declared in the " + sig + " header") { Offset = dbgOff, Size = dbgLen });
        }

        // ------------------------------------------------------------------ COFF / a.out / ELF

        static bool LooksLikeCoff(Ctx c, long b)
        {
            var h = c.Src.ReadBytes(b, 20);
            if (h.Length < 20) return false;
            int nscns = Bin.U16(h, 2), opth = Bin.U16(h, 16);
            long symptr = Bin.U32(h, 8), nsyms = Bin.U32(h, 12);
            if (nscns < 1 || nscns > 96 || (opth != 0 && opth != 28 && opth != 224)) return false;
            if (nsyms > 0 && (symptr == 0 || b + symptr + nsyms * 18 > c.Len)) return false;
            var s = c.Src.ReadBytes(b + 20 + opth, 8);
            return s.Length == 8 && (s[0] == '.' || s[0] == '/' || char.IsLetter((char)s[0]));
        }

        static void ScanCoff(Ctx c, long b, bool afterStub)
        {
            var h = c.Src.ReadBytes(b, 20);
            int nscns = Bin.U16(h, 2), opth = Bin.U16(h, 16), flags = Bin.U16(h, 18);
            long symptr = Bin.U32(h, 8), nsyms = Bin.U32(h, 12);
            bool isExe = (flags & 0x0002) != 0;
            c.R.FileType = afterStub ? "DJGPP COFF executable (go32-v2)" : isExe ? "COFF executable" : "COFF object";
            var sec = c.Src.ReadBytes(b + 20 + opth, nscns * 40);
            long strTab = b + symptr + nsyms * 18;
            var dbgSecs = new List<string>(); bool stabs = false, dwarf = false;
            for (int i = 0; i + 40 <= sec.Length; i += 40)
            {
                string nm = Bin.Ascii(sec, i, 8);
                if (nm.StartsWith("/") && nsyms > 0)
                {
                    int so; if (int.TryParse(nm.Substring(1), out so)) { var sn = c.Src.ReadBytes(strTab + so, 64); nm = Bin.Ascii(sn, 0, 64); }
                }
                long size = Bin.U32(sec, i + 16);
                if (nm.StartsWith(".stab")) { stabs = true; dbgSecs.Add(nm + " " + Fmt.Size(size)); }
                else if (nm.StartsWith(".debug")) { dwarf = true; dbgSecs.Add(nm + " " + Fmt.Size(size)); }
            }
            if (stabs) Add(c, new Finding(Kinds.Stabs, string.Join(", ", dbgSecs.Where(s => s.StartsWith(".stab")))));
            if (dwarf) Add(c, new Finding(Kinds.Dwarf, string.Join(", ", dbgSecs.Where(s => s.StartsWith(".debug")).Take(8))));
            if (nsyms > 0 && b + symptr + nsyms * 18 <= c.Len)
            {
                var names = CoffSymbolNames(c, b + symptr, nsyms, strTab, 400);
                var f = new Finding(isExe || afterStub ? Kinds.Coff : Kinds.CoffObj, nsyms + " symbol table entries") { Offset = b + symptr, Size = nsyms * 18 };
                f.Samples.AddRange(PreferSourceNames(names));
                Add(c, f);
            }
        }

        static List<string> CoffSymbolNames(Ctx c, long symOff, long nsyms, long strTab, int max)
        {
            var res = new List<string>();
            int n = (int)Math.Min(nsyms, 4000);
            var s = c.Src.ReadBytes(symOff, n * 18);
            byte[] strs = null;
            for (int i = 0; i + 18 <= s.Length && res.Count < max; )
            {
                string nm;
                if (Bin.U32(s, i) == 0)
                {
                    if (strs == null) { long sl = c.Src.U32(strTab); strs = sl > 4 && sl < 16 * 1024 * 1024 ? c.Src.ReadBytes(strTab, (int)sl) : new byte[0]; }
                    long so = Bin.U32(s, i + 4);
                    nm = so < strs.Length ? Bin.Ascii(strs, (int)so, 128) : "";
                }
                else nm = Bin.Ascii(s, i, 8);
                int sclass = s[i + 16], naux = s[i + 17];
                if (nm.Length > 0 && (sclass == 2 || sclass == 103 || sclass == 3)) res.Add(nm);
                i += 18 * (1 + naux);
            }
            return res;
        }

        static void ScanAout(Ctx c, long b)
        {
            var h = c.Src.ReadBytes(b, 32);
            if (h.Length < 32) return;
            long text = Bin.U32(h, 4), data = Bin.U32(h, 8), syms = Bin.U32(h, 16);
            c.R.FileType = "DJGPP/EMX a.out executable";
            if (syms == 0 || syms % 12 != 0 || text + data > c.Len * 2 || syms > c.Len) return;
            Add(c, new Finding(Kinds.Aout, (syms / 12) + " symbols"));
        }

        static void ScanElf(Ctx c, long b, string what)
        {
            var h = c.Src.ReadBytes(b, 64);
            if (h.Length < 52) return;
            bool is64 = h[4] == 2, be = h[5] == 2;
            Func<byte[], int, int> r16 = (a, o) => be ? Bin.U16BE(a, o) : Bin.U16(a, o);
            Func<byte[], int, long> r32 = (a, o) => be ? Bin.U32BE(a, o) : Bin.U32(a, o);
            long shoff; int shentsize, shnum, shstrndx;
            if (!is64) { shoff = r32(h, 32); shentsize = r16(h, 46); shnum = r16(h, 48); shstrndx = r16(h, 50); }
            else { shoff = r32(h, 40); shentsize = r16(h, 58); shnum = r16(h, 60); shstrndx = r16(h, 62); }
            if (c.R.FileType.Length == 0 || c.R.FileType == "DOS MZ executable") c.R.FileType = b == 0 ? "ELF " + (is64 ? "64" : "32") : c.R.FileType;
            if (shnum == 0 || shnum > 4096 || shentsize < 40 || b + shoff + (long)shnum * shentsize > c.Len) return;
            var sh = c.Src.ReadBytes(b + shoff, shnum * shentsize);
            Func<int, long[]> sec = i =>
            {
                int o = i * shentsize;
                if (!is64) return new[] { r32(sh, o), r32(sh, o + 4), r32(sh, o + 16), r32(sh, o + 20) };
                return new[] { r32(sh, o), r32(sh, o + 4), r32(sh, o + 24), r32(sh, o + 32) };
            };
            if (shstrndx >= shnum) return;
            var ss = sec(shstrndx);
            var strtab = c.Src.ReadBytes(b + ss[2], (int)Math.Min(ss[3], 65536));
            var dbg = new List<string>(); bool stab = false, symtab = false; long symSize = 0;
            for (int i = 0; i < shnum; i++)
            {
                var s = sec(i);
                string nm = s[0] < strtab.Length ? Bin.Ascii(strtab, (int)s[0], 64) : "";
                if (nm.StartsWith(".debug") || nm.StartsWith(".zdebug") || nm == ".line") dbg.Add(nm + " " + Fmt.Size(s[3]));
                if (nm.StartsWith(".stab")) stab = true;
                if (s[1] == 2) { symtab = true; symSize = s[3]; }
            }
            if (dbg.Count > 0) Add(c, new Finding(Kinds.Dwarf, (what != "ELF" ? what + ": " : "") + string.Join(", ", dbg.Take(8))) { Offset = b });
            if (stab) Add(c, new Finding(Kinds.Stabs, what));
            if (symtab && symSize > 0) Add(c, new Finding(Kinds.ElfSyms, "~" + (symSize / (is64 ? 24 : 16)) + " symbols"));
        }

        // ------------------------------------------------------------------ separate symbol files

        static void ScanDbg(Ctx c)
        {
            var h = c.Head;
            if (h.Length < 48) return;
            int machine = Bin.U16(h, 4);
            long nsec = Bin.U32(h, 28);
            if (machine != 0x14C && machine != 0x8664 && machine != 0x166 && machine != 0x184) return;
            if (nsec > 200) return;
            c.R.FileType = "DBG symbol file";
            Add(c, new Finding(Kinds.Dbg, "machine " + Bin.Hex(machine) + ", " + nsec + " sections"));
        }

        static void CheckMapSym(Ctx c)
        {
            var h = c.Head;
            if (h.Length < 32) return;
            int nextPtr = Bin.U16(h, 0), numSegs = Bin.U16(h, 8), segPtr = Bin.U16(h, 10), nameLen = h[15];
            if (nameLen < 1 || nameLen > 64 || !Bin.IsPrintable(h, 16, nameLen)) return;
            if (numSegs < 1 || numSegs > 4096 || segPtr == 0 || segPtr * 16L >= c.Len) return;
            if (nextPtr == 0 || nextPtr * 16L + 4 > c.Len) return;
            var em = c.Src.ReadBytes(nextPtr * 16L, 4);
            if (Bin.U16(em, 0) != 0 || em[3] < 3 || em[3] > 7) return;
            // walk segments
            int symCount = 0; var names = new List<string>(); long sp = segPtr * 16L; var seen = new HashSet<long>();
            for (int i = 0; i < numSegs && sp > 0 && sp < c.Len && seen.Add(sp); i++)
            {
                var sd = c.Src.ReadBytes(sp, 0x30);
                if (sd.Length < 0x15) break;
                int next = Bin.U16(sd, 0), nsyms = Bin.U16(sd, 2), symTabOfs = Bin.U16(sd, 4), segNameLen = sd[0x14];
                symCount += nsyms;
                if (nsyms > 0 && names.Count < 30)
                {
                    // symbol pointer table: nsyms WORD offsets from segdef
                    var ptrs = c.Src.ReadBytes(sp + symTabOfs, Math.Min(nsyms, 40) * 2);
                    bool sym32 = (sd[0x0E] & 1) != 0;
                    for (int k = 0; k + 2 <= ptrs.Length && names.Count < 30; k += 2)
                    {
                        var s = c.Src.ReadBytes(sp + Bin.U16(ptrs, k), 70);
                        int no = sym32 ? 4 : 2;
                        if (s.Length > no && s[no] > 0 && Bin.IsPrintable(s, no + 1, s[no])) names.Add(Bin.Ascii(s, no + 1, s[no]));
                    }
                }
                sp = next * 16L;
                if (next == segPtr) break;
            }
            if (symCount == 0) return;
            c.R.FileType = "MAPSYM symbol file";
            var f = new Finding(Kinds.Sym, "module " + Bin.Ascii(h, 16, nameLen) + ", MAPSYM " + em[3] + "." + em[2] + ", " + numSegs + " segments, " + symCount + " symbols");
            f.Samples.AddRange(PreferSourceNames(names));
            Add(c, f);
        }

        static void ScanTpu(Ctx c)
        {
            var h = c.Head;
            if (h.Length < 64) return;
            char v = (char)h[3];
            string ver;
            switch (v)
            {
                case '0': ver = "Turbo Pascal 4.0"; break;
                case '5': ver = "Turbo Pascal 5.0"; break;
                case '6': ver = "Turbo Pascal 5.5"; break;
                case '9': ver = "Turbo Pascal 6.0"; break;
                case 'Q': ver = "Turbo/Borland Pascal 7.0"; break;
                default: if (!char.IsLetterOrDigit(v)) return; ver = "version '" + v + "'"; break;
            }
            string kind = Bin.Match(h, 0, "TPW") ? "Windows unit" : Bin.Match(h, 0, "TPP") ? "protected-mode unit" : "unit";
            c.R.FileType = "Turbo Pascal " + kind;
            Add(c, new Finding(Kinds.Tpu, ver + " " + kind));
        }

        // ------------------------------------------------------------------ OMF objects and libraries

        static void ScanOmf(Ctx c)
        {
            var src = c.Src; long len = c.Len;
            bool isLib = c.Head[0] == 0xF0;
            long pageSize = 16;
            long pos = 0;
            if (isLib)
            {
                int recLen = Bin.U16(c.Head, 1);
                pageSize = recLen + 3;
                if (pageSize < 16 || pageSize > 32768 || (pageSize & (pageSize - 1)) != 0) return;
                pos = pageSize;
            }
            int modules = 0, debugModules = 0, linnums = 0; bool cv = false, borland = false, watcom = false, msExt = false;
            var publics = new List<string>(); var modNames = new List<string>();
            var buf = new byte[4];
            int guard = 0;
            while (pos + 3 <= len && guard++ < 200000)
            {
                var hdr = src.ReadBytes(pos, 3);
                if (hdr.Length < 3) break;
                int type = hdr[0], rlen = Bin.U16(hdr, 1);
                if (type == 0xF1) break; // library end
                if (type != 0x80 && type != 0x82) { if (modules == 0) return; break; }
                // parse one module
                bool modDebug = false; bool ok = false;
                long p = pos;
                int recs = 0;
                while (p + 3 <= len && recs++ < 100000)
                {
                    var rh = src.ReadBytes(p, 3);
                    int t = rh[0], l = Bin.U16(rh, 1);
                    if (l < 1 || p + 3 + l > len) { if (modules == 0) return; break; }
                    if (!IsOmfType(t)) { if (modules == 0) return; break; }
                    byte[] d = null;
                    if (t == 0x80 || t == 0x82 || t == 0x88 || t == 0x96 || t == 0xCA || ((t == 0x90 || t == 0x91 || t == 0xB6 || t == 0xB7) && publics.Count < 400))
                        d = src.ReadBytes(p + 3, Math.Min(l, 4096));
                    switch (t)
                    {
                        case 0x80: case 0x82:
                            if (d.Length > 1 && d[0] > 0 && d[0] < d.Length) { var nm = Bin.Ascii(d, 1, d[0]); if (modNames.Count < 200) modNames.Add(nm); }
                            break;
                        case 0x88:
                            if (d.Length >= 2)
                            {
                                int cls = d[1];
                                if (cls == 0xA1) { msExt = true; }
                                else if (cls >= 0xE0 && cls <= 0xE7) { modDebug = true; borland = true; }
                            }
                            break;
                        case 0x94: case 0x95: case 0xC4: case 0xC5:
                            modDebug = true; linnums++; break;
                        case 0x96:
                            for (int i = 0; i < d.Length; )
                            {
                                int n = d[i]; if (i + 1 + n > d.Length) break;
                                var s = Bin.Ascii(d, i + 1, n);
                                if (s == "$$SYMBOLS" || s == "$$TYPES" || s == "DEBSYM" || s == "DEBTYP") { modDebug = true; cv = true; }
                                if (s == "DEBUG_INFO" || s.StartsWith(".debug")) { modDebug = true; watcom = true; }
                                i += 1 + n;
                            }
                            break;
                        case 0x90: case 0x91: case 0xB6: case 0xB7:
                            if (d != null) ParsePubdef(d, t == 0x91 || t == 0xB7, publics);
                            break;
                    }
                    p += 3 + l;
                    if (t == 0x8A || t == 0x8B) { ok = true; break; }
                }
                if (!ok && modules == 0) return;
                modules++;
                if (modDebug) debugModules++;
                if (!isLib) { pos = p; if (pos + 3 > len) break; var nx = src.ReadBytes(pos, 1); if (nx.Length == 0 || (nx[0] != 0x80 && nx[0] != 0x82)) break; continue; }
                pos = (p + pageSize - 1) / pageSize * pageSize;
                if (!ok) break;
            }
            if (modules == 0) return;
            c.R.FileType = isLib ? "OMF library" : "OMF object";
            var what = isLib ? "library with " + modules + " module" + (modules == 1 ? "" : "s") : "object module " + (modNames.Count > 0 ? modNames[0] : "");
            if (debugModules > 0)
            {
                var styles = new List<string>();
                if (cv) styles.Add("CodeView"); if (borland) styles.Add("Borland"); if (watcom) styles.Add("Watcom"); if (linnums > 0) styles.Add("line numbers");
                var f = new Finding(Kinds.OmfDebug, what + "; " + debugModules + " with debug records (" + string.Join(", ", styles) + ")");
                f.Samples.AddRange(PreferSourceNames(modNames.Concat(publics).ToList()));
                Add(c, f);
            }
            else
            {
                var f = new Finding(Kinds.OmfObj, what + (publics.Count > 0 ? "; public names" : ""));
                f.Samples.AddRange(PreferSourceNames(modNames.Concat(publics).ToList()));
                Add(c, f);
            }
        }

        static bool IsOmfType(int t)
        {
            switch (t & 0xFE)
            {
                case 0x80: case 0x82: case 0x88: case 0x8A: case 0x8C: case 0x8E: case 0x90: case 0x94: case 0x96: case 0x98: case 0x9A: case 0x9C:
                case 0xA0: case 0xA2: case 0xA4: case 0xA6: case 0xB0: case 0xB2: case 0xB4: case 0xB6: case 0xB8: case 0xBA: case 0xBC:
                case 0xC2: case 0xC4: case 0xC6: case 0xC8: case 0xCA: case 0xCC: case 0x84: case 0x86: case 0x9E:
                    return true;
            }
            return false;
        }

        static void ParsePubdef(byte[] d, bool is32, List<string> outNames)
        {
            int i = 0;
            Func<int> idx = () => { if (i >= d.Length) return 0; int b = d[i++]; if ((b & 0x80) != 0 && i < d.Length) b = ((b & 0x7F) << 8) | d[i++]; return b; };
            int grp = idx(), seg = idx();
            if (seg == 0) i += 2;
            while (i < d.Length - 1)
            {
                int n = d[i];
                if (n == 0 || i + 1 + n > d.Length) break;
                if (outNames.Count < 400) outNames.Add(Bin.Ascii(d, i + 1, n));
                i += 1 + n + (is32 ? 4 : 2);
                idx();
            }
        }

        // ------------------------------------------------------------------ text: maps, sources, listings

        static bool IsText(byte[] h, long len)
        {
            int n = (int)Math.Min(h.Length, 8192);
            if (n < 16) return false;
            int bad = 0, nl = 0;
            for (int i = 0; i < n; i++)
            {
                byte b = h[i];
                if (b == 0x0A) nl++;
                else if (b == 0x1A) { if (i < n - 1 && i < len - 1 && h.Skip(i + 1).Take(n - i - 1).Any(x => x != 0x1A && x != 0)) bad++; }
                else if (b < 0x20 && b != 0x09 && b != 0x0D && b != 0x0C) bad++;
                else if (b == 0) bad += 4;
            }
            return bad * 200 < n && nl > 0;
        }

        static readonly Regex reSegHdr = new Regex(@"^\s*Start\s+Stop\s+Length\s+Name(\s+Class)?", RegexOptions.Multiline | RegexOptions.Compiled);
        static readonly Regex rePubHdr = new Regex(@"(Publics by (Name|Value))|(^\s*Address\s+Publics)", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex rePubLine = new Regex(@"^\s*[0-9A-Fa-f]{4,5}:[0-9A-Fa-f]{4,8}[+* ]*\s+(?:(?:Abs|Idle|Imp|Res)\s+)?([_A-Za-z@?$.][\w@?$.]{0,127})\s*(?:[0-9A-Fa-f]{8}.*)?$", RegexOptions.Multiline | RegexOptions.Compiled);
        static readonly Regex reWatcomMap = new Regex(@"(Open )?Watcom (C/C\+\+32 |C/C\+\+16 )?Linker Version|WATCOM Linker", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex reWatcomSym = new Regex(@"^([0-9a-fA-F]{4}:[0-9a-fA-F]{4,8})[+*s ]\s*([_A-Za-z@?$.][\w@?$.]{0,127})\s*$", RegexOptions.Multiline | RegexOptions.Compiled);
        static readonly Regex reGnuMap = new Regex(@"^\s+0x[0-9a-f]{8,16}\s+([_A-Za-z.$][\w.$@]{0,127})\s*$", RegexOptions.Multiline | RegexOptions.Compiled);
        static readonly Regex reLines = new Regex(@"^\s*Line numbers for", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

        static void ScanText(Ctx c)
        {
            int textLen = (int)Math.Min(c.Len, 4 * 1024 * 1024);
            var bytes = textLen <= c.Head.Length ? c.Head : c.Src.ReadBytes(0, textLen);
            string text = Cp437.Decode(bytes, 0, Math.Min(bytes.Length, textLen));
            string ext = c.Ext;
            string fn = PathUtil.FileName(c.Name).ToUpperInvariant();

            // ---- linker maps
            bool segHdr = reSegHdr.IsMatch(text);
            bool pubHdr = rePubHdr.IsMatch(text);
            bool watcom = reWatcomMap.IsMatch(text) && text.Contains("Memory Map");
            bool gnu = text.Contains("Linker script and memory map");
            if (segHdr || pubHdr || watcom || gnu || (ext == ".map" && text.Contains("Program entry point")))
            {
                var names = new List<string>();
                int pubs = 0;
                if (watcom)
                {
                    foreach (Match m in reWatcomSym.Matches(text)) { pubs++; if (names.Count < 300) names.Add(m.Groups[2].Value); }
                }
                else if (gnu)
                {
                    foreach (Match m in reGnuMap.Matches(text)) { pubs++; if (names.Count < 300) names.Add(m.Groups[1].Value); }
                }
                if (pubHdr || (!watcom && !gnu))
                {
                    foreach (Match m in rePubLine.Matches(text)) { pubs++; if (names.Count < 300) names.Add(m.Groups[1].Value); }
                }
                bool lines = reLines.IsMatch(text);
                string linker = watcom ? "Watcom WLINK" : gnu ? "GNU ld" : text.Contains("Turbo Link") || text.Contains("TLINK") ? "Borland TLINK" : "MS LINK / TLINK";
                if (pubs > 0 && (pubHdr || watcom || gnu))
                {
                    var f = new Finding(Kinds.Map, linker + " map: " + pubs + " public symbol" + (pubs == 1 ? "" : "s") + (lines ? ", line numbers" : ""));
                    f.Samples.AddRange(PreferSourceNames(names));
                    c.R.FileType = "Linker map";
                    Add(c, f);
                    return;
                }
                if (segHdr && (ext == ".map" || text.Contains("Program entry point") || text.Contains("Class")))
                {
                    c.R.FileType = "Linker map";
                    Add(c, new Finding(Kinds.MapSegs, linker + " map without public symbols" + (lines ? " (has line numbers)" : ""), lines ? (Strength?)Strength.Strong : null));
                    return;
                }
            }

            // ---- listings
            if (ext == ".lst" || ext == ".cod" || ext == ".lis" || ext == ".prn")
            {
                if (text.Contains("Microsoft (R) Macro Assembler") || text.Contains("Turbo Assembler") || text.Contains("Segments and Groups") ||
                    text.Contains("Symbol Name") || text.Contains("Microsoft (R) C") || Regex.IsMatch(text, @"^\s*\d+\s+[0-9A-F]{4}\s+[0-9A-F]{2,}", RegexOptions.Multiline))
                {
                    c.R.FileType = "Listing";
                    Add(c, new Finding(Kinds.Listing, "assembler/compiler listing"));
                    return;
                }
            }

            // ---- source code
            string lang = SourceLanguage(ext, fn, text);
            if (lang != null)
            {
                c.R.FileType = lang + " source";
                Add(c, new Finding(Kinds.Source, lang + " source, " + CountLines(text) + " lines"));
            }
        }

        static int CountLines(string s) { int n = 0; foreach (char ch in s) if (ch == '\n') n++; return n; }

        static int Hits(string text, params string[] words)
        {
            int n = 0;
            foreach (var w in words) if (text.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0) n++;
            return n;
        }

        static string SourceLanguage(string ext, string fn, string text)
        {
            switch (ext)
            {
                case ".c": case ".cpp": case ".cxx": case ".cc": case ".h": case ".hpp": case ".hh":
                    if (Hits(text, "#include", "#define", "void ", "int ", "char ", "return", "struct ", "typedef", "{", "/*", "//") >= 3) return ext == ".h" || ext == ".hpp" || ext == ".hh" ? "C/C++ header" : ext == ".c" ? "C" : "C++";
                    break;
                case ".asm": case ".inc": case ".mac": case ".a86": case ".s":
                    if (Hits(text, " proc", "endp", "segment", "ends", "mov ", "push ", "call ", " db ", " dw ", ".model", ".code", "equ ", "include") >= 3) return "Assembler";
                    if (ext == ".inc" && Hits(text, "procedure", "function", "begin", "end;", "var ", "const ") >= 3) return "Pascal include";
                    break;
                case ".pas": case ".pp": case ".dpr":
                    if (Hits(text, "program ", "unit ", "begin", "end.", "procedure", "function", "var ", "uses ", "writeln") >= 3) return "Pascal";
                    break;
                case ".bas": case ".bi":
                    if (Hits(text, "PRINT", "GOTO", "GOSUB", "DIM ", "SUB ", "END SUB", "IF ", "THEN", "DECLARE") >= 3 && !text.StartsWith("ÿ")) return "BASIC";
                    break;
                case ".for": case ".f77": case ".ftn":
                    if (Hits(text, "PROGRAM", "SUBROUTINE", "INTEGER", "REAL", "CALL ", "END") >= 3) return "Fortran";
                    break;
                case ".mak": case ".mk":
                    if (Hits(text, ".obj", ".exe", "$(", ":", "link", "cc") >= 3) return "Makefile";
                    break;
            }
            if ((fn == "MAKEFILE" || fn.StartsWith("MAKEFILE.")) && Hits(text, ".obj", ".exe", "$(", ":", "link", "cc", "cl ", "tcc", "bcc", "wcl") >= 3) return "Makefile";
            return null;
        }

        // ------------------------------------------------------------------ weak hints

        static readonly Regex reAssert = new Regex(@"Assertion failed|assertion failed|Assertion \(%s\) failed|ASSERT|assert\(", RegexOptions.Compiled);
        static readonly Regex rePath = new Regex(@"(?:[A-Za-z]:)?\\?(?:[A-Za-z0-9_~$!#-]{1,8}\\){1,8}[A-Za-z0-9_~$!#-]{1,8}\.(?:C|CPP|ASM|PAS|H|CC|CXX)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex reBare = new Regex(@"(?<![A-Za-z0-9_.\\])[A-Za-z0-9_~$-]{1,8}\.(?:C|CPP|ASM|PAS)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        static readonly HashSet<string> runtimeSourceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "stub.asm", "crt0.asm", "c0.asm", "crt0.c", "c0.c" };

        static void ScanStrings(Ctx c)
        {
            int n = (int)Math.Min(c.Len, 8 * 1024 * 1024);
            var b = n <= c.Head.Length ? c.Head : c.Src.ReadBytes(0, n);
            var sb = new StringBuilder(n);
            for (int i = 0; i < b.Length; i++) { byte x = b[i]; sb.Append(x >= 0x20 && x < 0x7F ? (char)x : '\n'); }
            string s = sb.ToString();
            bool asserts = s.Contains("Assertion failed") || s.Contains("assertion failed") || s.Contains("Assertion (") ;
            var paths = new List<string>();
            foreach (Match m in rePath.Matches(s)) { if (m.Value.Contains("\\") && !paths.Contains(m.Value, StringComparer.OrdinalIgnoreCase)) paths.Add(m.Value); if (paths.Count > 20) break; }
            if (asserts)
                foreach (Match m in reBare.Matches(s)) { if (!paths.Contains(m.Value, StringComparer.OrdinalIgnoreCase)) paths.Add(m.Value); if (paths.Count > 20) break; }
            // ignore runtime-library paths that ship inside many retail programs
            paths.RemoveAll(p => Regex.IsMatch(p, @"\\(BC|BORLANDC|TC|TCPP|MSC|C600|C700|WATCOM|DJGPP|LIBSRC|CRT)\\.*(LIB|RTL|CRT|SRC)", RegexOptions.IgnoreCase));
            paths.RemoveAll(p => runtimeSourceNames.Contains(PathUtil.FileName(p)));
            if (!asserts && paths.Count == 0) return;
            var f = new Finding(Kinds.Strings, (asserts ? "assert() messages" : "") + (asserts && paths.Count > 0 ? "; " : "") + (paths.Count > 0 ? paths.Count + " source path/name string" + (paths.Count == 1 ? "" : "s") : ""));
            f.Samples.AddRange(paths.Take(10));
            Add(c, f);
        }
    }
}
