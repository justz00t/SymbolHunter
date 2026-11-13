using System;
using System.Collections.Generic;
using System.Linq;

namespace SymbolHunter.Core
{
    /// <summary>ARJ archives (ARJ 1.x-3.x): methods 0-4, multi-volume sets (.ARJ/.A01/...), self-extractors.</summary>
    public sealed class ArjContainer : Container
    {
        sealed class Seg
        {
            public DataSource Src; public long Data; public long CSize, USize, Resume; public uint Crc; public int Method, Flags, Type;
            public string Name; public DateTime? Time; public int Volume;
        }

        readonly List<Seg> segs = new List<Seg>();
        public override string FormatName { get { return "ARJ"; } }

        /// <summary>Returns the offset of a valid ARJ main header at or after 'from' (searching up to maxScan bytes), or -1.</summary>
        public static long FindArchive(DataSource s, long from, long maxScan)
        {
            long end = Math.Min(s.Length - 4, from + maxScan);
            var buf = new byte[1 << 16];
            for (long p = from; p < end; p += buf.Length - 1)
            {
                int n = s.Read(p, buf, 0, (int)Math.Min(buf.Length, end + 2 - p));
                for (int i = 0; i + 1 < n; i++)
                    if (buf[i] == 0x60 && buf[i + 1] == 0xEA && ReadHeader(s, p + i) != null) return p + i;
                if (n < buf.Length) break;
            }
            return -1;
        }

        public static bool Probe(DataSource s) { return ReadHeader(s, 0) != null; }

        sealed class Hdr { public byte[] B; public long Next; }

        /// <summary>Reads and CRC-checks a basic header at pos. Returns null if invalid; B.Length==0 marks end of archive.</summary>
        static Hdr ReadHeader(DataSource s, long pos)
        {
            var h = s.ReadBytes(pos, 4);
            if (h.Length < 4 || h[0] != 0x60 || h[1] != 0xEA) return null;
            int size = Bin.U16(h, 2);
            if (size == 0) return new Hdr { B = new byte[0], Next = pos + 4 };
            if (size < 30 || size > 2600) return null;
            var b = s.ReadBytes(pos + 4, size + 4);
            if (b.Length < size + 4) return null;
            if (Crc.Crc32(0, b, 0, size) != Bin.U32(b, size)) return null;
            int fhs = b[0];
            if (fhs < 30 || fhs > size) return null;
            long p = pos + 4 + size + 4;
            for (int guard = 0; guard < 64; guard++)
            {
                int xs = s.U16(p);
                if (xs < 0) return null;
                p += 2;
                if (xs == 0) break;
                p += xs + 4;
            }
            Array.Resize(ref b, size);
            return new Hdr { B = b, Next = p };
        }

        public ArjContainer(DataSource src, string name, ISiblingProvider sib)
        {
            long start = ReadHeader(src, 0) != null ? 0 : FindArchive(src, 0, 4 * 1024 * 1024);
            if (start < 0) throw new FormatException2("no ARJ header found");
            bool multi = ReadVolume(src, start, 0);
            // further volumes
            if (multi && sib != null)
            {
                string baseName = name;
                int dot = baseName.LastIndexOf('.');
                string stem = dot >= 0 ? baseName.Substring(0, dot) : baseName;
                bool numbered = false;
                for (int v = 1; v < 1000; v++)
                {
                    string vn = stem + "." + (v < 100 ? "A" + v.ToString("00") : v.ToString());
                    DataSource vs = numbered ? null : sib.GetSibling(PathUtil.FileName(vn));
                    if (vs == null && (v == 1 || numbered))
                    {
                        // renamed volume sets: GAME1.ARJ, GAME2.ARJ ...
                        var alt = VolumeSets.NumberedNext(PathUtil.FileName(baseName), v);
                        if (alt != null) { var a = sib.GetSibling(alt); if (a != null) { vs = a; vn = alt; numbered = true; } }
                    }
                    if (vs == null) { if (segs.Any(x => (x.Flags & 0x04) != 0 && x.Volume == v - 1)) Warnings.Add("missing volume " + PathUtil.FileName(vn)); break; }
                    ConsumedVolumes.Add(PathUtil.FileName(vn));
                    long vstart = ReadHeader(vs, 0) != null ? 0 : FindArchive(vs, 0, 1024 * 1024);
                    if (vstart < 0) { Warnings.Add("bad volume " + vn); break; }
                    if (!ReadVolume(vs, vstart, v)) break;
                }
            }
            Description = "ARJ, " + segs.Count(s => s.Type == 0 || s.Type == 1) + " entries" + (ConsumedVolumes.Count > 0 ? ", " + (ConsumedVolumes.Count + 1) + " volumes" : "");
        }

        /// <summary>Reads one volume. Returns true if another volume follows.</summary>
        bool ReadVolume(DataSource s, long start, int volume)
        {
            var main = ReadHeader(s, start);
            if (main == null || main.B.Length == 0) throw new FormatException2("bad ARJ main header");
            bool more = (main.B[4] & 0x04) != 0;
            long p = main.Next;
            for (int guard = 0; guard < 200000; guard++)
            {
                var h = ReadHeader(s, p);
                if (h == null) { Warnings.Add("damaged header at " + p); break; }
                if (h.B.Length == 0) break;
                var b = h.B;
                int fhs = b[0], flags = b[4], method = b[5], type = b[6];
                long cs = Bin.U32(b, 12), us = Bin.U32(b, 16);
                uint crc = Bin.U32(b, 20);
                long resume = 0;
                if (fhs >= 34) resume = Bin.U32(b, 30);
                int ne = Array.IndexOf(b, (byte)0, fhs);
                string nm = Cp437.Decode(b, fhs, (ne < 0 ? b.Length : ne) - fhs);
                var seg = new Seg { Src = s, Data = h.Next, CSize = cs, USize = us, Crc = crc, Method = method, Flags = flags, Type = type, Resume = (flags & 0x08) != 0 ? resume : 0, Name = PathUtil.Clean(nm), Time = ZipContainer.DosTime((int)(Bin.U32(b, 8) >> 16), (int)(Bin.U32(b, 8) & 0xFFFF)), Volume = volume };
                segs.Add(seg);
                if ((flags & 0x04) != 0) more = true;
                p = h.Next + cs;
                if (p > s.Length) { Warnings.Add("archive is truncated"); break; }
            }
            return more;
        }

        public override IEnumerable<Entry> Entries()
        {
            var done = new HashSet<Seg>();
            foreach (var s in segs)
            {
                if (done.Contains(s)) continue;
                if (s.Type == 3) { yield return new Entry { Name = s.Name, IsDirectory = true, Size = 0 }; continue; }
                if (s.Type != 0 && s.Type != 1) continue;
                // gather continuation segments of the same file
                var parts = new List<Seg> { s };
                done.Add(s);
                var cur = s;
                while ((cur.Flags & 0x04) != 0)
                {
                    var nx = segs.FirstOrDefault(x => !done.Contains(x) && x.Volume > cur.Volume && x.Name == cur.Name && (x.Flags & 0x08) != 0);
                    if (nx == null) break;
                    parts.Add(nx); done.Add(nx); cur = nx;
                }
                long total = parts.Max(x => x.Resume + x.USize);
                var e = new Entry { Name = s.Name, Size = total, CompressedSize = parts.Sum(x => x.CSize), Method = "ARJ method " + s.Method, Time = s.Time, IsEncrypted = (s.Flags & 0x01) != 0 };
                if ((s.Flags & 0x08) != 0 && s.Resume > 0) e.Note = "continued from a missing previous volume";
                else if ((cur.Flags & 0x04) != 0) e.Note = "continues in a missing next volume";
                var ps = parts;
                e.Open = () => OpenParts(ps, e);
                yield return e;
            }
        }

        DataSource OpenParts(List<Seg> parts, Entry e)
        {
            if ((parts[0].Flags & 0x01) != 0) throw new UnsupportedException("encrypted (garbled)");
            var sink = new Sink(e.Size, -1);
            try
            {
                long written = 0;
                foreach (var p in parts.OrderBy(x => x.Resume))
                {
                    if (p.Resume > written && parts[0].Resume == 0) { var pad = new byte[p.Resume - written]; sink.Write(pad, 0, pad.Length); written = p.Resume; }
                    using (var seg = new Sink(p.USize, p.USize))
                    {
                        DecodeSegment(p, seg);
                        var data = seg.ToSource();
                        if (data.Length != p.USize) e.Note = ZipContainer.AppendNote(e.Note, "size mismatch");
                        else if (Crc.Crc32(data) != p.Crc) e.Note = ZipContainer.AppendNote(e.Note, "CRC error");
                        var buf = new byte[1 << 16];
                        for (long q = 0; q < data.Length; ) { int n = data.Read(q, buf, 0, buf.Length); if (n <= 0) break; sink.Write(buf, 0, n); q += n; }
                        written += data.Length;
                        data.Dispose();
                    }
                }
                return sink.ToSource();
            }
            catch { sink.Dispose(); throw; }
        }

        static void DecodeSegment(Seg p, Sink sink)
        {
            var inp = new ByteInput(p.Src, p.Data, p.CSize);
            switch (p.Method)
            {
                case 0:
                    {
                        var buf = new byte[1 << 16]; long left = p.USize;
                        while (left > 0) { int n = inp.Read(buf, 0, (int)Math.Min(buf.Length, left)); if (n <= 0) break; sink.Write(buf, 0, n); left -= n; }
                        break;
                    }
                case 1: case 2: case 3:
                    new LzhStatic(new BitReaderMsb(inp), 17, 5).Run(sink, p.USize, 0);
                    break;
                case 4:
                    LzhSimple.ArjFast(new BitReaderMsb(inp), sink, p.USize);
                    break;
                default: throw new UnsupportedException("ARJ method " + p.Method);
            }
        }
    }
}
