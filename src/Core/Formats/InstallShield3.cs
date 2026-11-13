using System;
using System.Collections.Generic;

namespace SymbolHunter.Core
{
    /// <summary>InstallShield 3 ".Z" archives (DCL-compressed members), common in early 90s installers.</summary>
    public sealed class InstallShield3Container : Container
    {
        sealed class Item { public string Name; public long USize, CSize, Offset; public int Attr; public bool Split; public uint DateTime; }
        readonly DataSource src; readonly List<Item> items = new List<Item>();
        public override string FormatName { get { return "InstallShield 3"; } }

        public InstallShield3Container(DataSource s)
        {
            src = s;
            var h = s.ReadBytes(0, 59);
            if (h.Length < 59 || Bin.U32(h, 0) != 0x8C655D13) throw new FormatException2("not an InstallShield 3 archive");
            int dirCount = Bin.U16(h, 49);
            long toc = Bin.U32(h, 41);
            if (toc <= 0 || toc >= s.Length) throw new FormatException2("bad TOC address");
            var t = s.ReadBytes(toc, (int)Math.Min(s.Length - toc, 4 * 1024 * 1024));
            int p = 0;
            var dirs = new List<Tuple<string, int>>();
            for (int i = 0; i < dirCount && p + 6 <= t.Length; i++)
            {
                int fc = Bin.U16(t, p), chunk = Bin.U16(t, p + 2), nl = Bin.U16(t, p + 4);
                string name = Cp437.Decode(t, p + 6, nl);
                dirs.Add(Tuple.Create(name, fc));
                p += chunk;
            }
            foreach (var d in dirs)
            {
                for (int i = 0; i < d.Item2 && p + 30 <= t.Length; i++)
                {
                    var it = new Item();
                    it.USize = Bin.U32(t, p + 3); it.CSize = Bin.U32(t, p + 7); it.Offset = Bin.U32(t, p + 11);
                    it.DateTime = Bin.U32(t, p + 15);
                    int chunk = Bin.U16(t, p + 23);
                    it.Attr = t[p + 25]; it.Split = t[p + 26] != 0;
                    int nl = t[p + 29];
                    string fn = Cp437.Decode(t, p + 30, nl);
                    it.Name = PathUtil.Clean((d.Item1.Length > 0 ? d.Item1 + "/" : "") + fn);
                    items.Add(it);
                    if (chunk < 30) break;
                    p += chunk;
                }
            }
            if (items.Count == 0) throw new FormatException2("no files in InstallShield archive");
            Description = "InstallShield 3 archive, " + items.Count + " files";
        }

        public override IEnumerable<Entry> Entries()
        {
            foreach (var it in items)
            {
                var item = it;
                var e = new Entry { Name = it.Name, Size = it.USize, CompressedSize = it.CSize, Method = (it.Attr & 0x10) != 0 ? "stored" : "DCL implode", Time = ZipContainer.DosTime((int)(it.DateTime & 0xFFFF), (int)(it.DateTime >> 16)) };
                e.Open = () =>
                {
                    if (item.Split) e.Note = "file is split across disks; only this part is available";
                    long cs = Math.Min(item.CSize, src.Length - item.Offset);
                    if ((item.Attr & 0x10) != 0) return src.Slice(item.Offset, cs);
                    var sink = new Sink(item.USize, item.USize);
                    try { Dcl.Explode(new BitReaderLsb(new ByteInput(src, item.Offset, cs)), sink, item.USize); return sink.ToSource(); }
                    catch { sink.Dispose(); throw; }
                };
                yield return e;
            }
        }
    }
}
