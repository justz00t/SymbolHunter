using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SymbolHunter.Core
{
    /// <summary>ZIP reader: PKZIP 0.9+ (Store, Shrink, Reduce, Implode, Deflate, Deflate64, BZip2, LZMA, PPMd, XZ), SFX, ZIP64.</summary>
    public sealed class ZipContainer : Container
    {
        sealed class Item
        {
            public string Name; public int Method, Flags; public long CSize, USize, LocalOffset, DataStart = -1; public uint Crc; public DateTime? Time;
            public bool IsDir; public int Disk;
        }

        readonly DataSource src; readonly List<Item> items = new List<Item>();
        readonly long[] diskStarts;   // spanned/split archives: start of each disk inside the joined data
        public override string FormatName { get { return "ZIP"; } }

        /// <summary>True if the end record says this is the last disk of a spanned/split set.</summary>
        public static bool IsMultiDisk(DataSource s)
        {
            long eocd = FindEocd(s);
            if (eocd < 0) return false;
            var e = s.ReadBytes(eocd, 22);
            return Bin.U16(e, 4) > 0 || Bin.U16(e, 6) > 0;
        }

        /// <summary>True if the data ends with a plausible ZIP end record (ZIP with leading junk, or the last disk of a split set).</summary>
        public static bool ProbeEndRecord(DataSource s)
        {
            long eocd = FindEocd(s);
            if (eocd < 0) return false;
            var e = s.ReadBytes(eocd, 22);
            int thisDisk = Bin.U16(e, 4), cdDisk = Bin.U16(e, 6), entries = Bin.U16(e, 10);
            long cdSize = Bin.U32(e, 12), cdOff = Bin.U32(e, 16);
            if (entries == 0 || cdSize < 46 || cdSize > eocd) return false;
            var cd = s.ReadBytes(eocd - cdSize, 4);
            if (!Bin.Match(cd, 0, "PK\u0001\u0002")) return false;
            return thisDisk > 0 || cdOff + cdSize <= eocd;
        }

        /// <summary>Number of the disk holding the end record (0 for single archives), or -1 if there is none.</summary>
        public static int DiskNumber(DataSource s)
        {
            long eocd = FindEocd(s);
            if (eocd < 0) return -1;
            return Bin.U16(s.ReadBytes(eocd, 22), 4);
        }

        /// <summary>Spanned or split archive: earlier disks first, the disk holding the central directory last.</summary>
        public ZipContainer(DataSource last, List<DataSource> priorDisks)
            : this(new ConcatSource(priorDisks.Concat(new[] { last }).ToList(), false), Starts(priorDisks, last)) { }

        static long[] Starts(List<DataSource> prior, DataSource last)
        {
            var st = new long[prior.Count + 1]; long p = 0;
            for (int i = 0; i < prior.Count; i++) { st[i] = p; p += prior[i].Length; }
            st[prior.Count] = p;
            return st;
        }

        ZipContainer(DataSource joined, long[] starts) { diskStarts = starts; src = joined; Init(); Description += ", " + starts.Length + " disks joined"; }

        long DiskBase(int disk) { return diskStarts == null ? 0 : disk < diskStarts.Length ? diskStarts[disk] : diskStarts[diskStarts.Length - 1]; }

        public static bool Probe(byte[] h)
        {
            if (h.Length < 4) return false;
            return Bin.Match(h, 0, "PK\u0003\u0004") || Bin.Match(h, 0, "PK00PK\u0003\u0004") || Bin.Match(h, 0, "PK\u0005\u0006") || Bin.Match(h, 0, "PK\u0007\u0008PK\u0003\u0004");
        }

        /// <summary>True if the data ends with a ZIP central directory (used for self-extracting archives).</summary>
        public static bool HasEndRecord(DataSource s)
        {
            long eocd = FindEocd(s);
            return eocd >= 0;
        }

        public ZipContainer(DataSource s) { src = s; Init(); }

        void Init()
        {
            var s = src;
            long eocd = FindEocd(s);
            bool ok = false;
            if (eocd >= 0) { try { ok = ReadCentral(eocd); } catch (Exception ex) { Warnings.Add("central directory: " + ex.Message); } }
            if (!ok) { items.Clear(); ScanLocalHeaders(); if (items.Count > 0) Warnings.Add("central directory missing or damaged; read local headers instead"); }
            if (items.Count == 0 && eocd < 0) throw new FormatException2("no ZIP entries found");
            int methods = items.Select(i => i.Method).Distinct().Count();
            Description = "ZIP, " + items.Count + " entries, methods: " + string.Join(", ", items.Select(i => MethodName(i.Method, i.Flags)).Distinct().Take(6));
        }

        static long FindEocd(DataSource s)
        {
            long len = s.Length;
            if (len < 22) return -1;
            int n = (int)Math.Min(len, 65557 + 1024);
            var b = s.ReadBytes(len - n, n);
            for (int i = b.Length - 22; i >= 0; i--)
            {
                if (b[i] == 'P' && b[i + 1] == 'K' && b[i + 2] == 5 && b[i + 3] == 6)
                {
                    int commentLen = Bin.U16(b, i + 20);
                    if (i + 22 + commentLen <= b.Length + 0) return len - n + i;
                    if (i + 22 <= b.Length) return len - n + i; // tolerate truncated comment
                }
            }
            return -1;
        }

        bool ReadCentral(long eocd)
        {
            var e = src.ReadBytes(eocd, 22);
            int thisDisk = Bin.U16(e, 4), cdDisk = Bin.U16(e, 6);
            long count = Bin.U16(e, 10), cdSize = Bin.U32(e, 12), cdOff = Bin.U32(e, 16) + DiskBase(cdDisk);
            long cdEnd = eocd;
            if (count == 0xFFFF || cdSize == 0xFFFFFFFF || cdOff == 0xFFFFFFFF)
            {
                var loc = src.ReadBytes(eocd - 20, 20);
                if (Bin.Match(loc, 0, "PK\u0006\u0007"))
                {
                    long z64 = Bin.U64(loc, 8);
                    var z = src.ReadBytes(z64, 56);
                    if (Bin.Match(z, 0, "PK\u0006\u0006")) { count = Bin.U64(z, 32); cdSize = Bin.U64(z, 40); cdOff = Bin.U64(z, 48); cdEnd = z64; }
                }
            }
            if (count == 0) return true;
            long expected = cdEnd - cdSize;
            long delta = 0;
            var sig = src.ReadBytes(cdOff, 4);
            if (!Bin.Match(sig, 0, "PK\u0001\u0002"))
            {
                var sig2 = src.ReadBytes(expected, 4);
                if (Bin.Match(sig2, 0, "PK\u0001\u0002")) delta = expected - cdOff;
                else return false;
            }
            long p = cdOff + delta;
            if (cdSize > 256L * 1024 * 1024) return false;
            var cd = src.ReadBytes(p, (int)Math.Min(cdSize + 4096, int.MaxValue / 2));
            int q = 0;
            for (long i = 0; i < count && q + 46 <= cd.Length; i++)
            {
                if (!Bin.Match(cd, q, "PK\u0001\u0002")) break;
                int madeBy = Bin.U16(cd, q + 4), flags = Bin.U16(cd, q + 8), method = Bin.U16(cd, q + 10);
                int time = Bin.U16(cd, q + 12), date = Bin.U16(cd, q + 14);
                uint crc = Bin.U32(cd, q + 16);
                long cs = Bin.U32(cd, q + 20), us = Bin.U32(cd, q + 24);
                int nl = Bin.U16(cd, q + 28), xl = Bin.U16(cd, q + 30), cl = Bin.U16(cd, q + 32), disk = Bin.U16(cd, q + 34);
                long extAttr = Bin.U32(cd, q + 38), lo = Bin.U32(cd, q + 42);
                if (q + 46 + nl + xl > cd.Length) break;
                string name = DecodeName(cd, q + 46, nl, flags);
                int x = q + 46 + nl, xe = x + xl;
                while (x + 4 <= xe)
                {
                    int id = Bin.U16(cd, x), sz = Bin.U16(cd, x + 2);
                    int d = x + 4;
                    if (id == 1)
                    {
                        if (us == 0xFFFFFFFF && d + 8 <= xe) { us = Bin.U64(cd, d); d += 8; }
                        if (cs == 0xFFFFFFFF && d + 8 <= xe) { cs = Bin.U64(cd, d); d += 8; }
                        if (lo == 0xFFFFFFFF && d + 8 <= xe) { lo = Bin.U64(cd, d); d += 8; }
                    }
                    else if (id == 0x7075 && sz > 5 && cd[d] == 1) name = Encoding.UTF8.GetString(cd, d + 5, sz - 5);
                    x += 4 + sz;
                }
                bool isDir = name.EndsWith("/") || name.EndsWith("\\") || ((madeBy >> 8) == 0 && (extAttr & 0x10) != 0 && us == 0);
                items.Add(new Item { Name = PathUtil.Clean(name), Method = method, Flags = flags, CSize = cs, USize = us, Crc = crc, LocalOffset = lo + delta + DiskBase(disk), IsDir = isDir, Time = DosTime(date, time), Disk = disk });
                q += 46 + nl + xl + cl;
            }
            if (items.Count == 0) return false;
            // check a sample of local headers
            int bad = 0;
            foreach (var it in items.Take(8)) if (!Bin.Match(src.ReadBytes(it.LocalOffset, 4), 0, "PK\u0003\u0004")) bad++;
            if (bad == Math.Min(8, items.Count) && (thisDisk == 0 || diskStarts != null)) return false;
            if (thisDisk > 0 && diskStarts == null && items.Any(i => i.Disk != thisDisk)) Warnings.Add("spanned ZIP: disk " + (thisDisk + 1) + " of a multi-disk set; earlier disks not found");
            return true;
        }

        static string DecodeName(byte[] b, int off, int n, int flags)
        {
            if ((flags & 0x800) != 0) return Encoding.UTF8.GetString(b, off, n);
            return Cp437.Decode(b, off, n);
        }

        public static DateTime? DosTime(int date, int time)
        {
            try
            {
                int y = 1980 + (date >> 9), m = (date >> 5) & 15, d = date & 31;
                if (m < 1 || m > 12 || d < 1) return null;
                return new DateTime(y, m, Math.Min(d, DateTime.DaysInMonth(y, m)), Math.Min(time >> 11, 23), Math.Min((time >> 5) & 63, 59), Math.Min((time & 31) * 2, 59));
            }
            catch { return null; }
        }

        void ScanLocalHeaders()
        {
            long len = src.Length;
            var first = src.ReadBytes(0, (int)Math.Min(len, 4 * 1024 * 1024));
            int start = Bin.IndexOf(first, "PK\u0003\u0004", 0, first.Length);
            if (start < 0) return;
            long p = start;
            int guard = 0;
            while (p + 30 <= len && guard++ < 1000000)
            {
                var h = src.ReadBytes(p, 30);
                if (!Bin.Match(h, 0, "PK\u0003\u0004")) break;
                int flags = Bin.U16(h, 6), method = Bin.U16(h, 8);
                uint crc = Bin.U32(h, 14); long cs = Bin.U32(h, 18), us = Bin.U32(h, 22);
                int nl = Bin.U16(h, 26), xl = Bin.U16(h, 28);
                var nb = src.ReadBytes(p + 30, nl);
                var it = new Item { Name = PathUtil.Clean(DecodeName(nb, 0, nb.Length, flags)), Method = method, Flags = flags, CSize = cs, USize = us, Crc = crc, LocalOffset = p, Time = DosTime(Bin.U16(h, 12), Bin.U16(h, 10)) };
                it.IsDir = it.Name.EndsWith("/");
                it.DataStart = p + 30 + nl + xl;
                if ((flags & 8) != 0 && cs == 0)
                {
                    // sizes are in a data descriptor after the data; find the end of the stream
                    long end = FindDataEnd(it);
                    if (end < 0) { Warnings.Add("cannot find the end of " + it.Name); break; }
                    it.CSize = end - it.DataStart;
                    var dd = src.ReadBytes(end, 16);
                    int o = Bin.Match(dd, 0, "PK\u0007\u0008") ? 4 : 0;
                    it.Crc = Bin.U32(dd, o); it.USize = Bin.U32(dd, o + 8);
                    items.Add(it);
                    p = end + o + 12;
                    continue;
                }
                items.Add(it);
                p = it.DataStart + cs + ((flags & 8) != 0 ? (Bin.Match(src.ReadBytes(it.DataStart + cs, 4), 0, "PK\u0007\u0008") ? 16 : 12) : 0);
            }
        }

        long FindDataEnd(Item it)
        {
            if (it.Method == 8 || it.Method == 9)
            {
                var inp = new ByteInput(src, it.DataStart, -1);
                var br = new BitReaderLsb(inp);
                using (var sink = new Sink(-1, 512L * 1024 * 1024))
                {
                    var w = new LzWindow(16, sink, -1);
                    if (!Inflate.Run(br, w, it.Method == 9)) return -1;
                    w.Flush();
                    br.AlignToByte();
                    return inp.Position - br.BitsInBuffer / 8;
                }
            }
            // search for a data descriptor signature
            var buf = src.ReadBytes(it.DataStart, (int)Math.Min(src.Length - it.DataStart, 64 * 1024 * 1024));
            int i = Bin.IndexOf(buf, "PK\u0007\u0008", 0, buf.Length);
            return i < 0 ? -1 : it.DataStart + i;
        }

        public static string MethodName(int m, int flags)
        {
            switch (m)
            {
                case 0: return "stored";
                case 1: return "shrunk";
                case 2: case 3: case 4: case 5: return "reduced(" + (m - 1) + ")";
                case 6: return "imploded";
                case 8: return "deflated";
                case 9: return "deflate64";
                case 10: return "PKWARE DCL implode";
                case 12: return "bzip2";
                case 14: return "LZMA";
                case 93: return "Zstandard";
                case 95: return "XZ";
                case 96: return "JPEG";
                case 97: return "WavPack";
                case 98: return "PPMd";
                case 99: return "AES";
                default: return "method " + m;
            }
        }

        public override IEnumerable<Entry> Entries()
        {
            foreach (var it in items)
            {
                var item = it;
                var e = new Entry { Name = it.Name, Size = it.USize, CompressedSize = it.CSize, IsDirectory = it.IsDir, Method = MethodName(it.Method, it.Flags), Time = it.Time, IsEncrypted = (it.Flags & 1) != 0 };
                e.Open = () => OpenItem(item, e);
                yield return e;
            }
        }

        DataSource OpenItem(Item it, Entry e)
        {
            if ((it.Flags & 1) != 0 || it.Method == 99) throw new UnsupportedException("encrypted (password protected)");
            if (it.DataStart < 0)
            {
                var h = src.ReadBytes(it.LocalOffset, 30);
                if (!Bin.Match(h, 0, "PK\u0003\u0004")) throw new FormatException2("local header not found");
                it.DataStart = it.LocalOffset + 30 + Bin.U16(h, 26) + Bin.U16(h, 28);
            }
            long cs = Math.Min(it.CSize, src.Length - it.DataStart);
            if (it.USize == 0 && it.Crc == 0 && (it.Flags & 8) == 0) return new MemorySource(new byte[0]);   // empty file (CRC of nothing is 0)
            if (cs < it.CSize) e.Note = "truncated archive";
            DataSource result;
            if (it.Method == 0)
            {
                result = src.Slice(it.DataStart, Math.Min(cs, it.USize < 0 ? cs : it.USize));
            }
            else
            {
                var sink = new Sink(it.USize, it.USize);
                try
                {
                    var inp = new ByteInput(src, it.DataStart, cs);
                    switch (it.Method)
                    {
                        case 1: PkLegacy.Unshrink(new BitReaderLsb(inp), sink, it.USize); break;
                        case 2: case 3: case 4: case 5: PkLegacy.Expand(new BitReaderLsb(inp), sink, it.USize, it.Method - 1); break;
                        case 6: PkLegacy.Explode(new BitReaderLsb(inp), sink, it.USize, it.Flags); break;
                        case 8: case 9:
                            {
                                var w = new LzWindow(16, sink, it.USize);
                                Inflate.Run(new BitReaderLsb(inp), w, it.Method == 9);
                                w.Flush();
                                break;
                            }
                        case 10: Dcl.Explode(new BitReaderLsb(inp), sink, it.USize); break;
                        case 12: CopyStream(new SharpCompress.Compressors.BZip2.BZip2Stream(src.Slice(it.DataStart, cs).OpenStream(), SharpCompress.Compressors.CompressionMode.Decompress, false), sink); break;
                        case 14:
                            {
                                var hdr = src.ReadBytes(it.DataStart, 4);
                                int psz = Bin.U16(hdr, 2);
                                var props = src.ReadBytes(it.DataStart + 4, psz);
                                var s = src.Slice(it.DataStart + 4 + psz, cs - 4 - psz).OpenStream();
                                CopyStream(new SharpCompress.Compressors.LZMA.LzmaStream(props, s, cs - 4 - psz, (it.Flags & 2) != 0 ? -1 : it.USize), sink);
                                break;
                            }
                        case 98:
                            {
                                var props = src.ReadBytes(it.DataStart, 2);
                                var s = src.Slice(it.DataStart + 2, cs - 2).OpenStream();
                                CopyStream(new SharpCompress.Compressors.PPMd.PpmdStream(new SharpCompress.Compressors.PPMd.PpmdProperties(props), s, false), sink);
                                break;
                            }
                        case 95: CopyStream(new SharpCompress.Compressors.Xz.XZStream(src.Slice(it.DataStart, cs).OpenStream()), sink); break;
                        default: throw new UnsupportedException("ZIP compression method " + it.Method + " (" + MethodName(it.Method, it.Flags) + ")");
                    }
                    result = sink.ToSource();
                }
                catch { sink.Dispose(); throw; }
            }
            if (result.Length != it.USize && it.USize >= 0) e.Note = AppendNote(e.Note, "size mismatch (" + result.Length + " of " + it.USize + " bytes)");
            else if (Crc.Crc32(result) != it.Crc) e.Note = AppendNote(e.Note, "CRC error");
            return result;
        }

        internal static string AppendNote(string a, string b) { return string.IsNullOrEmpty(a) ? b : a + "; " + b; }

        internal static void CopyStream(Stream s, Sink sink)
        {
            using (s)
            {
                var buf = new byte[1 << 16]; int n;
                while ((n = s.Read(buf, 0, buf.Length)) > 0) { sink.Write(buf, 0, n); if (sink.Full) break; }
            }
        }
    }
}
