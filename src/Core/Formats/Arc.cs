using System;
using System.Collections.Generic;
using System.Linq;

namespace SymbolHunter.Core
{
    /// <summary>SEA ARC / PKARC / PKPAK / PAK archives: stored, packed (RLE), squeezed, crunched (5,6,8), squashed (9).</summary>
    public sealed class ArcContainer : Container
    {
        sealed class Item { public string Name; public int Method; public long Data, CSize, USize; public int Crc; public DateTime? Time; }
        readonly DataSource src; readonly List<Item> items = new List<Item>();
        public override string FormatName { get { return "ARC"; } }

        public static bool Probe(byte[] h)
        {
            if (h.Length < 29 || h[0] != 0x1A) return false;
            int m = h[1];
            if (m < 1 || m > 11) return false;
            int nl = Array.IndexOf(h, (byte)0, 2, 13);
            if (nl < 3) return false;
            for (int i = 2; i < nl; i++) if (h[i] < 0x21 || h[i] > 0x7E) return false;
            long cs = Bin.U32(h, 15);
            long us = m == 1 ? cs : Bin.U32(h, 25);
            return cs < 0x7FFFFFFF && us < 0x7FFFFFFF;
        }

        public ArcContainer(DataSource s)
        {
            src = s;
            long p = 0;
            for (int guard = 0; guard < 100000; guard++)
            {
                var h = s.ReadBytes(p, 29);
                if (h.Length < 2) { Warnings.Add("archive ends without end marker"); break; }
                if (h[0] != 0x1A)
                {
                    // some archivers pad; try to resync on the next marker
                    Warnings.Add("bad header at offset " + p); break;
                }
                int m = h[1];
                if (m == 0) break;
                bool old = m == 1;
                int hl = old ? 25 : 29;
                if (h.Length < hl) { Warnings.Add("truncated header"); break; }
                var it = new Item { Method = m, Name = PathUtil.Clean(Cp437.Decode(h, 2, 13)), CSize = Bin.U32(h, 15), Crc = Bin.U16(h, 23), Time = ZipContainer.DosTime(Bin.U16(h, 19), Bin.U16(h, 21)) };
                it.USize = old ? it.CSize : Bin.U32(h, 25);
                it.Data = p + hl;
                if (m >= 20) { p = it.Data + it.CSize; continue; } // PAK informational records
                items.Add(it);
                p = it.Data + it.CSize;
                if (p > s.Length) { Warnings.Add("archive is truncated"); break; }
            }
            if (items.Count == 0) throw new FormatException2("no ARC entries");
            Description = "ARC, " + items.Count + " entries, methods: " + string.Join(", ", items.Select(i => MethodName(i.Method)).Distinct());
        }

        static string MethodName(int m)
        {
            switch (m)
            {
                case 1: case 2: return "stored";
                case 3: return "packed";
                case 4: return "squeezed";
                case 5: case 6: case 7: return "crunched (old)";
                case 8: return "crunched";
                case 9: return "squashed";
                case 10: return "crushed";
                case 11: return "distilled";
                default: return "method " + m;
            }
        }

        public override IEnumerable<Entry> Entries()
        {
            foreach (var it in items)
            {
                var item = it;
                var e = new Entry { Name = it.Name, Size = it.USize, CompressedSize = it.CSize, Method = MethodName(it.Method), Time = it.Time };
                e.Open = () => OpenItem(item, e);
                yield return e;
            }
        }

        DataSource OpenItem(Item it, Entry e)
        {
            long cs = Math.Min(it.CSize, src.Length - it.Data);
            if (cs < it.CSize) e.Note = "truncated archive";
            DataSource result;
            if (it.Method <= 2) result = src.Slice(it.Data, cs);
            else
            {
                var data = src.ReadBytes(it.Data, (int)cs);
                var sink = new Sink(it.USize, it.USize);
                try
                {
                    switch (it.Method)
                    {
                        case 3: { var r = new Rle90(sink); foreach (var b in data) r.Put(b); r.Flush(); break; }
                        case 4: Unsqueeze(data, sink); break;
                        case 5: ArcLzw.Old(data, sink, false); break;
                        case 6: ArcLzw.Old(data, sink, true); break;
                        case 8: ArcLzw.Dynamic(data, 1, 12, true, sink); break;
                        case 9: ArcLzw.Dynamic(data, 0, 13, false, sink); break;
                        default: throw new UnsupportedException("ARC method " + it.Method + " (" + MethodName(it.Method) + ")");
                    }
                    result = sink.ToSource();
                }
                catch { sink.Dispose(); throw; }
            }
            if (result.Length != it.USize) e.Note = ZipContainer.AppendNote(e.Note, "size mismatch");
            else if (Crc.Crc16Arc(result) != it.Crc) e.Note = ZipContainer.AppendNote(e.Note, "CRC error");
            return result;
        }

        /// <summary>ARC "squeezed": static Huffman tree stored as node pairs, LSB-first bits, RLE90 output.</summary>
        static void Unsqueeze(byte[] d, Sink sink)
        {
            if (d.Length < 2) return;
            int nodes = Bin.U16(d, 0);
            if (nodes == 0) return;
            if (nodes > 257 || 2 + nodes * 4 > d.Length) throw new FormatException2("squeeze: bad node table");
            var kids = new int[nodes, 2];
            for (int i = 0; i < nodes; i++) { kids[i, 0] = (short)Bin.U16(d, 2 + i * 4); kids[i, 1] = (short)Bin.U16(d, 4 + i * 4); }
            var rle = new Rle90(sink);
            int pos = 2 + nodes * 4, bit = 8, cur = 0;
            while (!sink.Full)
            {
                int f = 0;
                bool eof = false;
                while (f >= 0)
                {
                    if (f >= nodes) throw new FormatException2("squeeze: bad tree");
                    if (bit == 8) { if (pos >= d.Length) { eof = true; break; } cur = d[pos++]; bit = 0; }
                    int b = (cur >> bit) & 1; bit++;
                    f = kids[f, b];
                }
                if (eof) break;
                int v = ~f;   // leaf values are stored as -(value+1)
                if (v == 256) break;
                rle.Put((byte)v);
            }
            rle.Flush();
        }
    }

    /// <summary>RLE90 decoder (0x90 = repeat previous byte; 0x90 0x00 = literal 0x90).</summary>
    public sealed class Rle90
    {
        readonly Sink sink; int last; bool rep;
        readonly byte[] buf = new byte[4096]; int n;
        public Rle90(Sink s) { sink = s; }
        void Out(int b) { buf[n++] = (byte)b; if (n == buf.Length) { sink.Write(buf, 0, n); n = 0; } }
        public void Put(byte c)
        {
            if (rep)
            {
                if (c == 0) Out(0x90);
                else for (int i = 1; i < c; i++) Out(last);
                rep = false;
            }
            else if (c == 0x90) rep = true;
            else { Out(c); last = c; }
            if (n > 0 && sink.Full) n = 0;
        }
        public void Flush() { if (n > 0) { sink.Write(buf, 0, n); n = 0; } }
    }

    /// <summary>ARC LZW variants.</summary>
    public static class ArcLzw
    {
        const int Unused = -1;

        sealed class Out
        {
            readonly Rle90 rle; readonly Sink sink; readonly byte[] buf = new byte[4096]; int n;
            public Out(Sink s, bool useRle) { sink = s; if (useRle) rle = new Rle90(s); }
            public void Put(int b) { if (rle != null) rle.Put((byte)b); else { buf[n++] = (byte)b; if (n == buf.Length) { sink.Write(buf, 0, n); n = 0; } } }
            public void Flush() { if (rle != null) rle.Flush(); else if (n > 0) { sink.Write(buf, 0, n); n = 0; } }
        }

        /// <summary>Crunched (8), squashed (9): 9..maxBits LZW, LSB-first, clear code 256, code groups of 8.</summary>
        public static void Dynamic(byte[] d, int skip, int maxBits, bool useRle, Sink sink)
        {
            int maxstr = 1 << maxBits;
            var chr = new int[maxstr]; var ptr = new int[maxstr];
            for (int i = 0; i < maxstr; i++) { chr[i] = Unused; ptr[i] = Unused; }
            for (int i = 0; i < 256; i++) chr[i] = i;
            int last = 255;
            var o = new Out(sink, useRle);
            int pos = skip, bitbox = 0, bitsLeft = 0, codeofs = 0;
            int csize = 9;
            var stack = new byte[maxstr + 1];

            Func<int, int> readCode = bits =>
            {
                int code = 0, filled = 0;
                while (filled < bits)
                {
                    if (bitsLeft == 0) { if (pos >= d.Length) return -1; bitbox = d[pos++]; bitsLeft = 8; }
                    int got = Math.Min(bitsLeft, bits - filled);
                    code |= (bitbox & ((1 << got) - 1)) << filled;
                    bitbox >>= got; bitsLeft -= got; filled += got;
                }
                if (code > maxstr - 1) return -1;
                codeofs = (codeofs + 1) & 7;
                return code;
            };
            Action<int> resync = bits => { while (codeofs != 0) if (readCode(bits) < 0) break; };
            Func<int, int> first = c => { int g = 0; while (ptr[c] != Unused && g++ < maxstr) c = ptr[c]; return chr[c]; };
            Action<int> outStr = c =>
            {
                int sp = 0, g = 0;
                while (c != Unused && g++ <= maxstr) { stack[sp++] = (byte)chr[c]; c = ptr[c]; if (sp >= stack.Length) break; }
                while (sp > 0) o.Put(stack[--sp]);
            };

            int oldcode = 0, k = 0; bool firstCode = true;
            while (!sink.Full)
            {
                int nc = readCode(csize);
                if (nc < 0) break;
                if (firstCode) { k = nc; firstCode = false; }
                if (nc == 256)
                {
                    last = 255;
                    resync(csize);
                    csize = 9;
                    nc = readCode(csize);
                    if (nc < 0) break;
                }
                if (nc <= last) { outStr(nc); k = first(nc); }
                else { outStr(oldcode); o.Put(k); }
                if (last != maxstr - 1)
                {
                    last++;
                    if (last < maxstr)
                    {
                        chr[last] = k;
                        ptr[last] = oldcode < maxstr ? oldcode : Unused;
                    }
                    if (last != maxstr - 1 && last == (1 << csize) - 1) { csize++; resync(csize - 1); }
                }
                oldcode = nc;
            }
            o.Flush();
        }

        /// <summary>Old crunched (5, 6): fixed 12-bit codes, MSB-first, hash-assigned table slots.</summary>
        public static void Old(byte[] d, Sink sink, bool useRle)
        {
            const int maxstr = 4096;
            var chr = new int[maxstr]; var ptr = new int[maxstr]; var links = new int[maxstr];
            for (int i = 0; i < maxstr; i++) { chr[i] = Unused; ptr[i] = Unused; links[i] = Unused; }
            int last = -1;
            Func<int, int, int> getIdx = (oldcode, c) =>
            {
                int a = ((oldcode + c) | 0x800) & 0xFFFF;
                int h = (int)(((long)a * a >> 6) & 0xFFF);
                while (chr[h] != Unused && links[h] != Unused) h = links[h];
                if (chr[h] == Unused) return h;
                int lastHash = h;
                h = (h + 101) & 0xFFF;
                if (chr[h] != Unused)
                {
                    int f;
                    for (f = 0; f < maxstr; f++, h = (h + 1) & 0xFFF) if (chr[h] == Unused) break;
                    if (f == maxstr) return -1;
                }
                links[lastHash] = h;
                return h;
            };
            Func<int, int, bool> add = (oldcode, c) =>
            {
                last++;
                if ((last & maxstr) != 0) { last = maxstr - 1; return true; }
                int idx = getIdx(oldcode, c);
                if (idx < 0) return false;
                chr[idx] = c;
                if (oldcode >= maxstr) return true;
                ptr[idx] = oldcode;
                return true;
            };
            for (int i = 0; i < 256; i++) add(0xFFFF, i);
            var o = new Out(sink, useRle);
            var stack = new byte[maxstr + 1];
            Func<int, int> first = c => { int g = 0; while (ptr[c] != Unused && g++ < maxstr) c = ptr[c]; return chr[c]; };
            Action<int> outStr = c =>
            {
                int sp = 0, g = 0;
                while (c != Unused && g++ <= maxstr) { stack[sp++] = (byte)chr[c]; c = ptr[c]; if (sp >= stack.Length) break; }
                while (sp > 0) o.Put(stack[--sp]);
            };
            int pos = 0, bitbox = 0, bitsLeft = 0;
            Func<int> readCode = () =>
            {
                int code = 0, filled = 0;
                while (filled < 12)
                {
                    if (bitsLeft == 0) { if (pos >= d.Length) return -1; bitbox = d[pos++]; bitsLeft = 8; }
                    int got = Math.Min(bitsLeft, 12 - filled);
                    bitbox &= 0xFF; bitbox <<= got; filled += got;
                    code |= (bitbox >> 8) << (12 - filled);
                    bitsLeft -= got;
                }
                return code;
            };
            int oldcode = 0, k = 0; bool firstCode = true;
            while (!sink.Full)
            {
                int nc = readCode();
                if (nc < 0) break;
                bool noadd = false;
                if (firstCode) { k = nc; firstCode = false; noadd = true; }
                if (chr[nc] != Unused) { outStr(nc); k = first(nc); }
                else { outStr(oldcode); o.Put(k); }
                if (last != maxstr - 1 && !noadd) add(oldcode, k);
                oldcode = nc;
            }
            o.Flush();
        }
    }
}
