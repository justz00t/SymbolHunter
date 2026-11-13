using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SymbolHunter.Core
{
    /// <summary>FAT12/16/32 file systems (floppies, partitions), DOS 1.x disks without a BPB, long names, deleted files.</summary>
    public sealed class FatContainer : Container
    {
        readonly DataSource src;
        int bps, spc, reserved, nfats, rootEntries, media; long totalSectors, fatSectors, rootCluster;
        long fatStart, rootStart, rootSecs, dataStart, clusters; int fatType;
        byte[] fat; long csize;
        public string Label = "", Oem = "";
        public bool NoBpb;
        public override string FormatName { get { return "FAT" + fatType; } }

        static readonly Dictionary<long, int[]> dos1 = new Dictionary<long, int[]>
        {
            // size: sec/cluster, root entries, fat sectors, media
            { 163840, new[] { 1, 64, 1, 0xFE } }, { 184320, new[] { 1, 64, 2, 0xFC } }, { 327680, new[] { 2, 112, 1, 0xFF } },
            { 368640, new[] { 2, 112, 2, 0xFD } }, { 737280, new[] { 2, 112, 3, 0xF9 } }, { 1228800, new[] { 1, 224, 7, 0xF9 } },
            { 1474560, new[] { 1, 224, 9, 0xF0 } }, { 2949120, new[] { 2, 240, 9, 0xF0 } }, { 1720320, new[] { 4, 16, 3, 0xF0 } },
        };

        public static bool LooksLikeBpb(byte[] h)
        {
            if (h.Length < 64) return false;
            int bps = Bin.U16(h, 11), spc = h[13], rsv = Bin.U16(h, 14), nf = h[16], root = Bin.U16(h, 17), media = h[21];
            long tot = Bin.U16(h, 19) != 0 ? Bin.U16(h, 19) : Bin.U32(h, 32);
            long fats = Bin.U16(h, 22) != 0 ? Bin.U16(h, 22) : Bin.U32(h, 36);
            if (bps != 128 && bps != 256 && bps != 512 && bps != 1024 && bps != 2048 && bps != 4096) return false;
            if (spc == 0 || (spc & (spc - 1)) != 0) return false;
            if (rsv < 1 || nf < 1 || nf > 4 || media < 0xE5 || tot == 0 || fats == 0) return false;
            if (root == 0 && Bin.U16(h, 22) != 0) return false;
            return h[0] == 0xEB || h[0] == 0xE9 || h[0] == 0x60 || h[0] == 0x00 || (h[510] == 0x55 && h[511] == 0xAA) || h[0] == 0xFA;
        }

        /// <summary>Finds a FAT boot sector that sits behind an image-file header (first 16 KB). Returns its offset or -1.
        /// The boot sector must be followed by a FAT whose first bytes match its media byte.</summary>
        public static long FindBehindHeader(DataSource s, byte[] h)
        {
            if (s.Length < 100 * 1024 || h.Length < 1024) return -1;
            int limit = Math.Min(h.Length - 512, 16384);
            var sec = new byte[512];
            for (int off = 1; off <= limit; off++)
            {
                byte b0 = h[off];
                if (b0 != 0xEB && b0 != 0xE9) continue;
                if (h[off + 11] != 0 || h[off + 12] != 2) continue;          // 512-byte sectors
                Array.Copy(h, off, sec, 0, 512);
                if (!LooksLikeBpb(sec)) continue;
                int rsv = Bin.U16(sec, 14), media = sec[21], nf = sec[16], root = Bin.U16(sec, 17);
                long tot = Bin.U16(sec, 19) != 0 ? Bin.U16(sec, 19) : Bin.U32(sec, 32);
                if (root == 0 || root > 4096 || tot < 320 || tot > 8L * 1024 * 1024) continue;
                if ((tot * 512) > s.Length - off + 64 * 1024) continue;       // image must (nearly) fit in the file
                var f = s.ReadBytes(off + rsv * 512L, 3);
                if (f.Length == 3 && f[0] == media && f[1] == 0xFF && f[2] == 0xFF) return off;
            }
            return -1;
        }

        public static bool LooksLikeDos1(DataSource s, byte[] h)
        {
            int[] g;
            if (!dos1.TryGetValue(s.Length, out g)) return false;
            var f = s.ReadBytes(512, 3);
            return f.Length == 3 && f[0] == g[3] && f[1] == 0xFF && f[2] == 0xFF;
        }

        public FatContainer(DataSource s)
        {
            src = s;
            var h = s.ReadBytes(0, 512);
            if (LooksLikeBpb(h))
            {
                bps = Bin.U16(h, 11); spc = h[13]; reserved = Bin.U16(h, 14); nfats = h[16]; rootEntries = Bin.U16(h, 17); media = h[21];
                totalSectors = Bin.U16(h, 19) != 0 ? Bin.U16(h, 19) : Bin.U32(h, 32);
                fatSectors = Bin.U16(h, 22) != 0 ? Bin.U16(h, 22) : Bin.U32(h, 36);
                rootCluster = Bin.U16(h, 22) == 0 ? Bin.U32(h, 44) : 0;
                Oem = Bin.Ascii(h, 3, 8).Trim();
                if (rootEntries != 0 && h[38] == 0x29) Label = Bin.Ascii(h, 43, 11).Trim();
                else if (rootEntries == 0 && h[66] == 0x29) Label = Bin.Ascii(h, 71, 11).Trim();
            }
            else
            {
                int[] g;
                if (!dos1.TryGetValue(s.Length, out g)) throw new FormatException2("no FAT boot sector");
                var f = s.ReadBytes(512, 3);
                if (f[0] != g[3]) throw new FormatException2("FAT media byte mismatch");
                bps = 512; spc = g[0]; reserved = 1; nfats = 2; rootEntries = g[1]; fatSectors = g[2]; media = g[3];
                totalSectors = s.Length / 512; NoBpb = true;
            }
            if (totalSectors * bps > s.Length + 1024L * 1024 * 1024) totalSectors = s.Length / bps;
            rootSecs = (rootEntries * 32L + bps - 1) / bps;
            fatStart = reserved;
            rootStart = reserved + nfats * fatSectors;
            dataStart = rootStart + rootSecs;
            clusters = (totalSectors - dataStart) / spc;
            if (clusters <= 0) throw new FormatException2("bad FAT geometry");
            fatType = rootEntries == 0 ? 32 : clusters < 4085 ? 12 : clusters < 65525 ? 16 : 32;
            if (fatSectors * bps > 64L * 1024 * 1024) throw new FormatException2("FAT too large");
            fat = s.ReadBytes(fatStart * bps, (int)(fatSectors * bps));
            csize = (long)spc * bps;
            Description = FormatName + ", " + bps + "-byte sectors, " + spc + " sector(s)/cluster, " + clusters + " clusters" + (NoBpb ? ", DOS 1.x layout (no BPB)" : "") + (Oem.Length > 0 ? ", OEM '" + Oem + "'" : "");
        }

        long Next(long n)
        {
            if (fatType == 12)
            {
                long off = n + n / 2;
                if (off + 1 >= fat.Length) return -1;
                int v = Bin.U16(fat, (int)off);
                v = (n & 1) != 0 ? v >> 4 : v & 0xFFF;
                return v >= 0xFF7 || v < 2 ? -1 : v;
            }
            if (fatType == 16)
            {
                if (n * 2 + 1 >= fat.Length) return -1;
                int v = Bin.U16(fat, (int)(n * 2));
                return v >= 0xFFF7 || v < 2 ? -1 : v;
            }
            if (n * 4 + 3 >= fat.Length) return -1;
            long w = Bin.U32(fat, (int)(n * 4)) & 0x0FFFFFFF;
            return w >= 0x0FFFFFF7 || w < 2 ? -1 : w;
        }

        bool IsFree(long n)
        {
            if (fatType == 12) { long off = n + n / 2; if (off + 1 >= fat.Length) return false; int v = Bin.U16(fat, (int)off); v = (n & 1) != 0 ? v >> 4 : v & 0xFFF; return v == 0; }
            if (fatType == 16) return n * 2 + 1 < fat.Length && Bin.U16(fat, (int)(n * 2)) == 0;
            return n * 4 + 3 < fat.Length && (Bin.U32(fat, (int)(n * 4)) & 0x0FFFFFFF) == 0;
        }

        List<long> Chain(long first, long maxBytes)
        {
            var l = new List<long>(); var seen = new HashSet<long>();
            long n = first;
            while (n >= 2 && n < clusters + 2 && seen.Add(n))
            {
                l.Add(n);
                if (maxBytes >= 0 && l.Count * csize >= maxBytes) break;
                n = Next(n);
            }
            return l;
        }

        long ClusterPos(long n) { return (dataStart + (n - 2) * spc) * bps; }

        byte[] ReadDir(long first, bool root)
        {
            if (root && fatType != 32) return src.ReadBytes(rootStart * bps, (int)(rootSecs * bps));
            var ch = Chain(root ? rootCluster : first, 8 * 1024 * 1024);
            var b = new byte[ch.Count * csize];
            for (int i = 0; i < ch.Count; i++) src.ReadFull(ClusterPos(ch[i]), b, (int)(i * csize), (int)csize);
            return b;
        }

        sealed class F { public string Path; public long Size, First; public bool Dir, Deleted; public DateTime? Time; }

        IEnumerable<F> Walk()
        {
            var stack = new Stack<Tuple<string, long, int>>();
            stack.Push(Tuple.Create("", 0L, 0));
            var seen = new HashSet<long>();
            while (stack.Count > 0)
            {
                var t = stack.Pop();
                if (t.Item3 > 32 || !seen.Add(t.Item2)) continue;
                byte[] d = ReadDir(t.Item2, t.Item2 == 0);
                var lfn = new SortedDictionary<int, string>();
                for (int i = 0; i + 32 <= d.Length; i += 32)
                {
                    if (d[i] == 0) break;
                    int attr = d[i + 11];
                    if (attr == 0x0F)
                    {
                        int seq = d[i] & 0x3F;
                        var part = new StringBuilder();
                        foreach (var o in new[] { 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 })
                        {
                            int c = Bin.U16(d, i + o);
                            if (c == 0 || c == 0xFFFF) break;
                            part.Append((char)c);
                        }
                        if (d[i] != 0xE5) lfn[seq] = part.ToString();
                        continue;
                    }
                    bool deleted = d[i] == 0xE5;
                    string longName = lfn.Count > 0 && !deleted ? string.Concat(lfn.Values) : null;
                    lfn.Clear();
                    if ((attr & 0x08) != 0) { if (!deleted && Label.Length == 0 && (attr & 0x10) == 0) Label = Cp437.Decode(d, i, 11).Trim(); continue; }
                    string b8 = Cp437.Decode(d, i, 8).TrimEnd(), e3 = Cp437.Decode(d, i + 8, 3).TrimEnd();
                    if (d[i] == 0x05) b8 = "å" + b8.Substring(1);
                    if (deleted) b8 = "_" + (b8.Length > 1 ? b8.Substring(1) : "");
                    if (b8 == "." || b8 == ".." || b8.Length == 0) continue;
                    string nm = longName ?? (b8 + (e3.Length > 0 ? "." + e3 : ""));
                    long first = Bin.U16(d, i + 26) | (fatType == 32 ? (long)Bin.U16(d, i + 20) << 16 : 0);
                    long size = Bin.U32(d, i + 28);
                    var f = new F { Path = t.Item1 + nm, Size = size, First = first, Deleted = deleted, Dir = (attr & 0x10) != 0, Time = ZipContainer.DosTime(Bin.U16(d, i + 24), Bin.U16(d, i + 22)) };
                    if (f.Dir)
                    {
                        f.Path += "/";
                        if (!deleted && first >= 2 && first < clusters + 2) stack.Push(Tuple.Create(f.Path, first, t.Item3 + 1));
                    }
                    yield return f;
                }
            }
        }

        public override IEnumerable<Entry> Entries()
        {
            foreach (var f in Walk())
            {
                var ff = f;
                var e = new Entry { Name = f.Path, Size = f.Dir ? 0 : f.Size, IsDirectory = f.Dir, IsDeleted = f.Deleted, Time = f.Time, Method = f.Deleted ? "deleted" : "" };
                if (!f.Dir) e.Open = () => OpenFile(ff, e);
                yield return e;
            }
        }

        DataSource OpenFile(F f, Entry e)
        {
            if (f.Size == 0) return new MemorySource(new byte[0]);
            if (f.First < 2 || f.First >= clusters + 2) throw new FormatException2("bad first cluster");
            List<long> chain;
            if (f.Deleted)
            {
                // assume the file was stored contiguously in clusters that are still free
                chain = new List<long>();
                long need = (f.Size + csize - 1) / csize;
                for (long c = f.First; c < f.First + need && c < clusters + 2; c++)
                {
                    if (!IsFree(c)) { e.Note = "deleted: partially overwritten"; break; }
                    chain.Add(c);
                }
                if (chain.Count == 0) throw new FormatException2("deleted file's clusters are reused");
            }
            else chain = Chain(f.First, f.Size);
            var parts = new List<DataSource>();
            long left = f.Size;
            // merge consecutive clusters into runs
            for (int i = 0; i < chain.Count && left > 0; )
            {
                int j = i;
                while (j + 1 < chain.Count && chain[j + 1] == chain[j] + 1) j++;
                long runLen = Math.Min(left, (j - i + 1) * csize);
                long pos = ClusterPos(chain[i]);
                if (pos >= src.Length) break;
                parts.Add(src.Slice(pos, Math.Min(runLen, src.Length - pos)));
                left -= runLen;
                i = j + 1;
            }
            if (left > 0 && !f.Deleted) e.Note = ZipContainer.AppendNote(e.Note, "cluster chain shorter than file size");
            if (parts.Count == 1) return parts[0];
            return new ConcatSource(parts, false);
        }
    }

    /// <summary>MBR partition table: exposes each FAT partition as a raw volume entry.</summary>
    public sealed class MbrContainer : Container
    {
        readonly DataSource src; readonly List<Tuple<int, long, long>> parts = new List<Tuple<int, long, long>>();
        public override string FormatName { get { return "MBR"; } }

        static bool PartTypeOk(int t) { return t != 0; }

        public static List<Tuple<int, long, long>> Parse(DataSource s)
        {
            var res = new List<Tuple<int, long, long>>();
            var h = s.ReadBytes(0, 512);
            if (h.Length < 512 || h[510] != 0x55 || h[511] != 0xAA || FatContainer.LooksLikeBpb(h)) return res;
            long total = s.Length / 512;
            var ext = new List<long>();
            for (int i = 0; i < 4; i++)
            {
                int o = 446 + 16 * i, status = h[o], type = h[o + 4];
                long lba = Bin.U32(h, o + 8), cnt = Bin.U32(h, o + 12);
                if (status != 0 && status != 0x80) return new List<Tuple<int, long, long>>();
                if (type == 0) continue;
                if (lba == 0 || cnt == 0 || lba > total + 2048) return new List<Tuple<int, long, long>>();
                if (type == 5 || type == 0x0F || type == 0x85) ext.Add(lba);
                else res.Add(Tuple.Create(type, lba, cnt));
            }
            foreach (var eb in ext)
            {
                long cur = eb; var seen = new HashSet<long>();
                for (int g = 0; g < 64 && seen.Add(cur); g++)
                {
                    var e = s.ReadBytes(cur * 512, 512);
                    if (e.Length < 512 || e[510] != 0x55 || e[511] != 0xAA) break;
                    int t1 = e[446 + 4]; long l1 = Bin.U32(e, 446 + 8), c1 = Bin.U32(e, 446 + 12);
                    if (t1 != 0 && c1 > 0) res.Add(Tuple.Create(t1, cur + l1, c1));
                    int t2 = e[462 + 4]; long l2 = Bin.U32(e, 462 + 8);
                    if (t2 == 5 || t2 == 0x0F) cur = eb + l2; else break;
                }
            }
            return res;
        }

        public MbrContainer(DataSource s)
        {
            src = s;
            parts.AddRange(Parse(s));
            if (parts.Count == 0) throw new FormatException2("no partitions");
            Description = "hard disk image, " + parts.Count + " partition(s)";
        }

        public override IEnumerable<Entry> Entries()
        {
            int i = 0;
            foreach (var p in parts)
            {
                i++;
                var pp = p;
                long len = Math.Min(p.Item3 * 512, Math.Max(0, src.Length - p.Item2 * 512));
                yield return new Entry { Name = "partition" + i + "_type" + p.Item1.ToString("X2") + ".img", Size = len, Method = "partition", Open = () => src.Slice(pp.Item2 * 512, len) };
            }
        }
    }
}
