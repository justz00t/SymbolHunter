using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SymbolHunter.Core
{
    /// <summary>
    /// RAR 1.3/1.4 archives ("RE~^", 1993-94). Old header layout (as read by unrar's ReadHeader14);
    /// the data uses the RAR 1.5 compression, decoded by the bundled SharpCompress Unpack15.
    /// Supports solid archives and multi-volume sets (.RAR, .R00, .R01 ...).
    /// </summary>
    public sealed class Rar14Container : Container
    {
        sealed class Seg { public DataSource Src; public long Pos, Len; }
        sealed class Item
        {
            public string Name; public long UnpSize; public int Crc, Method, Flags, Attr; public DateTime? Time;
            public List<Seg> Segs = new List<Seg>(); public bool Incomplete;
        }

        const int MhdVolume = 0x01, MhdSolid = 0x08, LhdSplitBefore = 0x01, LhdSplitAfter = 0x02, LhdPassword = 0x04;

        readonly List<Item> items = new List<Item>();
        readonly bool solid;
        public override string FormatName { get { return "RAR 1.3"; } }

        public static bool Probe(byte[] h) { return h.Length >= 7 && Bin.Match(h, 0, "RE~^") && Bin.U16(h, 4) >= 7; }

        public Rar14Container(DataSource s, string name, ISiblingProvider sib)
        {
            int mainFlags;
            Parse(s, true, out mainFlags);
            solid = (mainFlags & MhdSolid) != 0;
            bool wantMore = (mainFlags & MhdVolume) != 0 || (items.Count > 0 && (items[items.Count - 1].Flags & LhdSplitAfter) != 0);
            if (wantMore && sib != null && name != null)
            {
                var names = RarContainer.VolumeNames(PathUtil.FileName(name), false).Take(999).ToList();
                bool any = false;
                foreach (var vn in names)
                {
                    var vs = sib.GetSibling(vn);
                    if (vs == null) break;
                    int vf;
                    if (!Probe(vs.ReadBytes(0, 8))) break;
                    ConsumedVolumes.Add(vn); any = true;
                    Parse(vs, false, out vf);
                    if ((vf & MhdVolume) == 0 && !(items.Count > 0 && (items[items.Count - 1].Flags & LhdSplitAfter) != 0)) break;
                }
                if (!any) Warnings.Add("multi-volume RAR 1.3: next volume not found");
            }
            else if (wantMore && items.Count > 0 && (items[items.Count - 1].Flags & LhdSplitAfter) != 0)
                Warnings.Add("multi-volume RAR 1.3: next volume not found");
            foreach (var it in items) if (it.Incomplete || (it.Flags & LhdSplitAfter) != 0) it.Incomplete = true;
            Description = "RAR 1.3 archive, " + items.Count + " files" + (solid ? ", solid" : "") + (ConsumedVolumes.Count > 0 ? ", " + (ConsumedVolumes.Count + 1) + " volumes" : "");
        }

        void Parse(DataSource s, bool first, out int mainFlags)
        {
            var h = s.ReadBytes(0, 7);
            if (!Probe(h)) throw new FormatException2("not a RAR 1.3 archive");
            int headSize = Bin.U16(h, 4);
            mainFlags = h[6];
            long p = headSize;
            int guard = 0;
            while (p + 21 <= s.Length && guard++ < 200000)
            {
                var fh = s.ReadBytes(p, 21);
                long pack = Bin.U32(fh, 0), unp = Bin.U32(fh, 4);
                int crc = Bin.U16(fh, 8), hs = Bin.U16(fh, 10);
                uint ftime = Bin.U32(fh, 12);
                int attr = fh[16], fl = fh[17], nsz = fh[19], method = fh[20];
                if (hs < 21 || hs < 21 + nsz) { Warnings.Add("damaged header at offset " + p); break; }
                var nb = s.ReadBytes(p + 21, nsz);
                string nm = PathUtil.Clean(Cp437.Decode(nb, 0, nb.Length).Replace('\\', '/'));
                long dataPos = p + hs;
                long avail = Math.Max(0, Math.Min(pack, s.Length - dataPos));
                var seg = new Seg { Src = s, Pos = dataPos, Len = avail };
                Item it;
                if ((fl & LhdSplitBefore) != 0 && items.Count > 0 && (items[items.Count - 1].Flags & LhdSplitAfter) != 0)
                {
                    it = items[items.Count - 1];                 // continuation of the previous volume's last file
                    it.Segs.Add(seg); it.Flags = (it.Flags & ~LhdSplitAfter) | (fl & LhdSplitAfter); it.Crc = crc;
                }
                else
                {
                    it = new Item { Name = nm, UnpSize = unp, Crc = crc, Method = method, Flags = fl, Attr = attr, Time = ZipContainer.DosTime((int)(ftime >> 16), (int)(ftime & 0xFFFF)) };
                    it.Segs.Add(seg);
                    if ((fl & LhdSplitBefore) != 0) it.Incomplete = true;   // first part is in a missing volume
                    items.Add(it);
                }
                if (avail < pack) { it.Incomplete = true; Warnings.Add("archive is truncated"); break; }
                p = dataPos + pack;
            }
        }

        // solid archives: one shared decoder, files decoded in order
        SharpCompress.Compressors.Rar.UnpackV1.Unpack shared;
        int lastDecoded = -1;

        public override IEnumerable<Entry> Entries()
        {
            for (int i = 0; i < items.Count; i++)
            {
                var it = items[i]; int idx = i;
                bool dir = (it.Attr & 0x10) != 0;
                var e = new Entry { Name = it.Name, Size = it.UnpSize, IsDirectory = dir, Method = it.Method == 0 ? "stored" : "RAR 1.3", Time = it.Time, IsEncrypted = (it.Flags & LhdPassword) != 0 };
                if (!dir) e.Open = () => OpenItem(idx, e);
                yield return e;
            }
        }

        DataSource OpenItem(int idx, Entry e)
        {
            if (solid)
            {
                if (idx <= lastDecoded) { shared = null; lastDecoded = -1; }
                for (int k = lastDecoded + 1; k < idx; k++)
                {
                    if ((items[k].Flags & LhdPassword) != 0 || (items[k].Attr & 0x10) != 0) { lastDecoded = k; continue; }
                    string ignored; try { using (var d = Decode(k, out ignored)) { } } catch { shared = null; lastDecoded = k; throw new FormatException2("solid archive: an earlier file is damaged"); }
                }
            }
            string damage;
            var res = Decode(idx, out damage);
            var it = items[idx];
            if (damage != null) e.Note = "damaged data (" + damage + "); only the first " + res.Length + " of " + it.UnpSize + " bytes recovered";
            else if (it.Incomplete) e.Note = "file is split across volumes and a volume is missing or truncated";
            else if (res.Length != it.UnpSize) e.Note = "size mismatch (" + res.Length + " of " + it.UnpSize + " bytes)";
            else if (it.Segs.Count == 1 && Checksum14(res) != it.Crc) e.Note = "CRC error";
            return res;
        }

        DataSource Decode(int idx, out string damage)
        {
            damage = null;
            var it = items[idx];
            lastDecoded = idx;
            DataSource packed = it.Segs.Count == 1 ? it.Segs[0].Src.Slice(it.Segs[0].Pos, it.Segs[0].Len) : new ConcatSource(it.Segs.Select(sg => sg.Src.Slice(sg.Pos, sg.Len)), true);
            var sink = new Sink(it.UnpSize, it.UnpSize + 65536);
            try
            {
                using (var input = packed.OpenStream())
                {
                    if (it.Method == 0)
                    {
                        var buf = new byte[1 << 16]; int n;
                        while ((n = input.Read(buf, 0, buf.Length)) > 0) sink.Write(buf, 0, n);
                    }
                    else
                    {
                        bool useSolid = solid && shared != null;
                        if (!useSolid) shared = new SharpCompress.Compressors.Rar.UnpackV1.Unpack();
                        var outStream = new SinkWriteStream(sink);
                        try { shared.DoUnpack15(it.UnpSize, useSolid, input, outStream); }
                        catch (Exception ex)
                        {
                            if (!solid) shared = null;
                            if (sink.Length == 0) throw new FormatException2("RAR 1.3: " + ex.Message);
                            damage = ex.Message;   // keep what was decoded before the damage
                        }
                        if (!solid) shared = null;
                    }
                }
                return sink.ToSource();
            }
            catch { sink.Dispose(); throw; }
            finally { packed.Dispose(); }
        }

        static int Checksum14(DataSource d)
        {
            int crc = 0;
            var buf = new byte[1 << 16];
            for (long pos = 0; pos < d.Length;)
            {
                int n = d.Read(pos, buf, 0, (int)Math.Min(buf.Length, d.Length - pos));
                if (n <= 0) break;
                for (int i = 0; i < n; i++) { crc = (crc + buf[i]) & 0xFFFF; crc = ((crc << 1) | (crc >> 15)) & 0xFFFF; }
                pos += n;
            }
            return crc;
        }

        sealed class SinkWriteStream : Stream
        {
            readonly Sink sink;
            public SinkWriteStream(Sink s) { sink = s; }
            public override void Write(byte[] buffer, int offset, int count) { sink.Write(buffer, offset, count); }
            public override bool CanRead { get { return false; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return true; } }
            public override long Length { get { return sink.Length; } }
            public override long Position { get { return sink.Length; } set { throw new NotSupportedException(); } }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
        }
    }
}
