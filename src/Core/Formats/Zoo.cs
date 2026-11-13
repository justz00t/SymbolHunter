using System;
using System.Collections.Generic;
using System.Linq;

namespace SymbolHunter.Core
{
    /// <summary>ZOO archives (Rahul Dhesi's zoo 1.x/2.x): stored, LZW (method 1), LZH (method 2).</summary>
    public sealed class ZooContainer : Container
    {
        const uint Tag = 0xFDC4A7DC;
        sealed class Item { public string Name; public int Method; public long Data, CSize, USize; public int Crc; public DateTime? Time; }
        readonly DataSource src; readonly List<Item> items = new List<Item>();
        public override string FormatName { get { return "ZOO"; } }

        public static bool Probe(byte[] h) { return h.Length >= 34 && Bin.U32(h, 20) == Tag && Bin.Match(h, 0, "ZOO"); }

        public ZooContainer(DataSource s)
        {
            src = s;
            var h = s.ReadBytes(0, 34);
            if (!Probe(h)) throw new FormatException2("not a ZOO archive");
            long p = Bin.U32(h, 24);
            var seen = new HashSet<long>();
            for (int guard = 0; guard < 100000 && p > 0 && p < s.Length && seen.Add(p); guard++)
            {
                var d = s.ReadBytes(p, 56);
                if (d.Length < 51 || Bin.U32(d, 0) != Tag) { Warnings.Add("bad directory entry at " + p); break; }
                int type = d[4], method = d[5];
                long next = Bin.U32(d, 6), off = Bin.U32(d, 10);
                if (next == 0) break;
                int date = Bin.U16(d, 14), time = Bin.U16(d, 16), crc = Bin.U16(d, 18);
                long us = Bin.U32(d, 20), cs = Bin.U32(d, 24);
                bool deleted = d[30] != 0;
                string name = Cp437.Decode(d, 38, 13);
                if (type == 2 && d.Length >= 56)
                {
                    int varLen = Bin.U16(d, 51);
                    if (varLen > 0)
                    {
                        var v = s.ReadBytes(p + 56, varLen);
                        if (v.Length >= 2)
                        {
                            int nl = v[0], dl = v[1];
                            string lname = nl > 0 && 2 + nl <= v.Length ? Cp437.Decode(v, 2, nl) : "";
                            string dname = dl > 0 && 2 + nl + dl <= v.Length ? Cp437.Decode(v, 2 + nl, dl) : "";
                            if (lname.Length > 0) name = lname;
                            if (dname.Length > 0) name = dname.TrimEnd('/', '\\') + "/" + name;
                        }
                    }
                }
                if (!deleted)
                    items.Add(new Item { Name = PathUtil.Clean(name), Method = method, Data = off, CSize = cs, USize = us, Crc = crc, Time = ZipContainer.DosTime(date, time) });
                p = next;
            }
            if (items.Count == 0) throw new FormatException2("no ZOO entries");
            Description = "ZOO, " + items.Count + " entries";
        }

        public override IEnumerable<Entry> Entries()
        {
            foreach (var it in items)
            {
                var item = it;
                var e = new Entry { Name = it.Name, Size = it.USize, CompressedSize = it.CSize, Method = it.Method == 0 ? "stored" : it.Method == 1 ? "LZW" : it.Method == 2 ? "LZH" : "method " + it.Method, Time = it.Time };
                e.Open = () => OpenItem(item, e);
                yield return e;
            }
        }

        DataSource OpenItem(Item it, Entry e)
        {
            long cs = Math.Min(it.CSize, src.Length - it.Data);
            if (cs < it.CSize) e.Note = "truncated archive";
            DataSource result;
            if (it.Method == 0) result = src.Slice(it.Data, cs);
            else
            {
                var sink = new Sink(it.USize, it.USize);
                try
                {
                    var inp = new ByteInput(src, it.Data, cs);
                    if (it.Method == 1) Lzd(new BitReaderLsb(inp), sink);
                    else if (it.Method == 2) LzhStatic.ForDicbit(new BitReaderMsb(inp), 13).Run(sink, it.USize, 0);
                    else throw new UnsupportedException("ZOO method " + it.Method);
                    result = sink.ToSource();
                }
                catch { sink.Dispose(); throw; }
            }
            if (result.Length != it.USize) e.Note = ZipContainer.AppendNote(e.Note, "size mismatch");
            else if (Crc.Crc16Arc(result) != it.Crc) e.Note = ZipContainer.AppendNote(e.Note, "CRC error");
            return result;
        }

        /// <summary>zoo LZD: LZW 9..13 bits LSB-first, CLEAR=256, EOF=257, first free code 258.</summary>
        static void Lzd(BitReaderLsb br, Sink sink)
        {
            const int Clear = 256, Eof = 257, First = 258, MaxMax = 8192;
            var next = new int[MaxMax + 2]; var ch = new byte[MaxMax + 2];
            var stack = new byte[MaxMax + 2];
            var outb = new byte[1 << 15]; int on = 0;
            int nbits = 9, maxCode = 512, free = First, oldCode = 0; byte fin = 0;
            Action<byte> put = b => { outb[on++] = b; if (on == outb.Length) { sink.Write(outb, 0, on); on = 0; } };
            while (!sink.Full)
            {
                if (br.Overrun > 2) break;
                int cur = br.Get(nbits);
                if (cur == Eof) break;
                if (cur == Clear)
                {
                    nbits = 9; maxCode = 512; free = First;
                    cur = br.Get(nbits);
                    if (cur == Eof) break;
                    fin = (byte)cur; oldCode = cur;
                    put(fin);
                    continue;
                }
                int inCode = cur, sp = 0;
                if (cur >= free) { cur = oldCode; stack[sp++] = fin; }
                int guard = 0;
                while (cur > 255)
                {
                    if (cur >= free || guard++ > MaxMax) throw new FormatException2("zoo LZW: bad code");
                    stack[sp++] = ch[cur]; cur = next[cur];
                }
                fin = (byte)cur;
                stack[sp++] = fin;
                while (sp > 0) put(stack[--sp]);
                if (free < MaxMax)
                {
                    ch[free] = fin; next[free] = oldCode; free++;
                    if (free >= maxCode && nbits < 13) { nbits++; maxCode <<= 1; }
                }
                oldCode = inCode;
            }
            if (on > 0) sink.Write(outb, 0, on);
        }
    }
}
