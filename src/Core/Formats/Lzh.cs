using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SymbolHunter.Core
{
    /// <summary>LHA / LHarc / LArc archives: header levels 0-3, -lh0- -lh1- -lh4- -lh5- -lh6- -lh7- -lzs- -lz4- -lz5- -lhd-, self-extractors.</summary>
    public sealed class LzhContainer : Container
    {
        sealed class Item { public string Name, Method; public long Data, CSize, USize; public int Crc = -1; public DateTime? Time; public bool Dir; }
        readonly DataSource src; readonly List<Item> items = new List<Item>();
        public override string FormatName { get { return "LZH"; } }

        static bool IsMethod(byte[] b, int o)
        {
            return o + 5 <= b.Length && b[o] == '-' && b[o + 4] == '-' && ((b[o + 1] == 'l' && (b[o + 2] == 'h' || b[o + 2] == 'z')) || (b[o + 1] == 'p' && b[o + 2] == 'm'));
        }

        /// <summary>Validates an LZH header at pos.</summary>
        public static bool ValidHeader(DataSource s, long pos)
        {
            var b = s.ReadBytes(pos, 32);
            if (b.Length < 24 || !IsMethod(b, 2)) return false;
            int level = b[20];
            if (level == 0 || level == 1)
            {
                int h = b[0];
                if (h < 20) return false;
                var hb = s.ReadBytes(pos + 2, h);
                if (hb.Length < h) return false;
                int sum = 0; foreach (var x in hb) sum += x;
                return (sum & 0xFF) == b[1];
            }
            if (level == 2) { int ts = Bin.U16(b, 0); return ts >= 26 && ts < 65536; }
            if (level == 3) return Bin.U16(b, 0) == 4;
            return false;
        }

        public static long FindArchive(DataSource s, long from, long maxScan)
        {
            long end = Math.Min(s.Length - 24, from + maxScan);
            var buf = new byte[1 << 16];
            for (long p = from; p < end; p += buf.Length - 8)
            {
                int n = s.Read(p, buf, 0, (int)Math.Min(buf.Length, end + 8 - p));
                for (int i = 0; i + 7 < n; i++)
                    if (buf[i + 2] == '-' && buf[i + 6] == '-' && buf[i + 3] == 'l' && ValidHeader(s, p + i)) return p + i;
                if (n < buf.Length) break;
            }
            return -1;
        }

        public LzhContainer(DataSource s)
        {
            src = s;
            long p = ValidHeader(s, 0) ? 0 : FindArchive(s, 0, 2 * 1024 * 1024);
            if (p < 0) throw new FormatException2("no LZH header found");
            for (int guard = 0; guard < 200000 && p < s.Length; guard++)
            {
                var b = s.ReadBytes(p, 32);
                if (b.Length == 0 || b[0] == 0) break;
                if (b.Length < 22 || !IsMethod(b, 2)) { Warnings.Add("damaged header at offset " + p); break; }
                var it = new Item { Method = Encoding.ASCII.GetString(b, 2, 5) };
                long cs = Bin.U32(b, 7), us = Bin.U32(b, 11);
                int level = b[20];
                string dir = null, fname = null;
                long dataStart;
                if (level == 0 || level == 1)
                {
                    int h = b[0];
                    var hb = s.ReadBytes(p, h + 2);
                    int nl = hb[21];
                    fname = Cp437.Decode(hb, 22, Math.Min(nl, Math.Max(0, hb.Length - 22)));
                    if (22 + nl + 2 <= hb.Length) it.Crc = Bin.U16(hb, 22 + nl);
                    it.Time = ZipContainer.DosTime(Bin.U16(hb, 17), Bin.U16(hb, 15));
                    dataStart = p + h + 2;
                    if (level == 1)
                    {
                        long ext = 0;
                        int next = Bin.U16(hb, h);
                        long q = p + h + 2;
                        for (int g = 0; next > 0 && g < 64; g++)
                        {
                            var xb = s.ReadBytes(q, next);
                            if (xb.Length < 3) break;
                            ParseExt(xb, 0, next - 2, ref fname, ref dir, it);
                            ext += next; q += next;
                            next = Bin.U16(xb, next - 2);
                        }
                        dataStart = q;
                        cs -= ext;
                    }
                }
                else if (level == 2 || level == 3)
                {
                    bool l3 = level == 3;
                    long total = l3 ? Bin.U32(s.ReadBytes(p + 24, 4), 0) : Bin.U16(b, 0);
                    it.Crc = Bin.U16(b, 21);
                    var hb = s.ReadBytes(p, (int)Math.Min(total, 65536));
                    int q = l3 ? 28 : 24;
                    long next = l3 ? Bin.U32(hb, q) : Bin.U16(hb, q);
                    q += l3 ? 4 : 2;
                    try { it.Time = new DateTime(1970, 1, 1).AddSeconds(Bin.U32(b, 15)); } catch { }
                    for (int g = 0; next > 0 && q + next <= hb.Length && g < 64; g++)
                    {
                        int sz = (int)next;
                        int nsz = l3 ? 4 : 2;
                        ParseExt(hb, q, sz - nsz, ref fname, ref dir, it);
                        next = l3 ? Bin.U32(hb, q + sz - 4) : Bin.U16(hb, q + sz - 2);
                        q += sz;
                    }
                    dataStart = p + total;
                }
                else { Warnings.Add("unknown header level " + level); break; }
                string full = (dir ?? "") + (fname ?? "");
                it.Name = PathUtil.Clean(full.Replace('\\', '/'));
                it.Data = dataStart; it.CSize = cs; it.USize = us;
                it.Dir = it.Method == "-lhd-" || it.Name.EndsWith("/");
                items.Add(it);
                p = dataStart + cs;
                if (p > s.Length) { Warnings.Add("archive is truncated"); break; }
            }
            if (items.Count == 0) throw new FormatException2("no LZH entries");
            Description = "LZH, " + items.Count + " entries, methods: " + string.Join(" ", items.Select(i => i.Method).Distinct());
        }

        static void ParseExt(byte[] b, int off, int len, ref string fname, ref string dir, Item it)
        {
            if (len < 1 || off + len > b.Length) return;
            int type = b[off];
            if (type == 0x01) fname = Cp437.Decode(b, off + 1, len - 1);
            else if (type == 0x02)
            {
                var d = new byte[len - 1]; Array.Copy(b, off + 1, d, 0, len - 1);
                for (int i = 0; i < d.Length; i++) if (d[i] == 0xFF) d[i] = (byte)'/';
                dir = Cp437.Decode(d);
                if (dir.Length > 0 && !dir.EndsWith("/")) dir += "/";
            }
        }

        public override IEnumerable<Entry> Entries()
        {
            foreach (var it in items)
            {
                var item = it;
                var e = new Entry { Name = it.Name, Size = it.USize, CompressedSize = it.CSize, IsDirectory = it.Dir, Method = it.Method, Time = it.Time };
                if (!it.Dir) e.Open = () => OpenItem(item, e);
                yield return e;
            }
        }

        DataSource OpenItem(Item it, Entry e)
        {
            long cs = Math.Min(it.CSize, src.Length - it.Data);
            if (cs < it.CSize) e.Note = "truncated archive";
            DataSource result;
            if (it.Method == "-lh0-" || it.Method == "-lz4-" || it.Method == "-pm0-") result = src.Slice(it.Data, Math.Min(cs, it.USize));
            else
            {
                var sink = new Sink(it.USize, it.USize);
                try
                {
                    var inp = new ByteInput(src, it.Data, cs);
                    switch (it.Method)
                    {
                        case "-lh1-": new Lzhuf(new BitReaderMsb(inp)).Run(sink, it.USize); break;
                        case "-lh4-": LzhStatic.ForDicbit(new BitReaderMsb(inp), 12).Run(sink, it.USize); break;
                        case "-lh5-": LzhStatic.ForDicbit(new BitReaderMsb(inp), 13).Run(sink, it.USize); break;
                        case "-lh6-": LzhStatic.ForDicbit(new BitReaderMsb(inp), 15).Run(sink, it.USize); break;
                        case "-lh7-": LzhStatic.ForDicbit(new BitReaderMsb(inp), 16).Run(sink, it.USize); break;
                        case "-lzs-": LzhSimple.Lzs(new BitReaderMsb(inp), sink, it.USize); break;
                        case "-lz5-": LzhSimple.Lz5(inp, sink, it.USize); break;
                        default: throw new UnsupportedException("LZH method " + it.Method);
                    }
                    result = sink.ToSource();
                }
                catch { sink.Dispose(); throw; }
            }
            if (result.Length != it.USize) e.Note = ZipContainer.AppendNote(e.Note, "size mismatch");
            else if (it.Crc >= 0 && Crc.Crc16Arc(result) != it.Crc) e.Note = ZipContainer.AppendNote(e.Note, "CRC error");
            return result;
        }
    }
}
