using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SymbolHunter.Core
{
    /// <summary>Maps 2048-byte logical sectors onto raw CD images (2048, 2336, 2352, 2448 bytes per sector).</summary>
    public sealed class CdSectorSource : DataSource
    {
        readonly DataSource src; readonly long baseOff; readonly int ssize, dataOff; readonly long sectors;
        public CdSectorSource(DataSource s, long baseOff, int ssize, int dataOff)
        {
            src = s; this.baseOff = baseOff; this.ssize = ssize; this.dataOff = dataOff;
            sectors = (s.Length - baseOff) / ssize;
        }
        public override long Length { get { return sectors * 2048; } }
        public override int Read(long pos, byte[] buf, int off, int count)
        {
            if (pos < 0 || pos >= Length) return 0;
            if (count > Length - pos) count = (int)(Length - pos);
            if (ssize == 2048) return src.Read(baseOff + pos, buf, off, count);
            int done = 0;
            while (done < count)
            {
                long sec = (pos + done) / 2048; int within = (int)((pos + done) % 2048);
                int n = Math.Min(count - done, 2048 - within);
                int got = src.Read(baseOff + sec * ssize + dataOff + within, buf, off + done, n);
                if (got <= 0) break;
                done += got;
            }
            return done;
        }
    }

    /// <summary>ISO 9660 / High Sierra / Joliet file systems on plain or raw CD images (ISO, BIN, IMG, MDF, NRG, CDI ...).</summary>
    public sealed class IsoContainer : Container
    {
        readonly DataSource vol;   // 2048-byte logical sectors
        readonly bool joliet, hsf;
        readonly byte[] rootRec;
        public string Label = "";
        public override string FormatName { get { return hsf ? "High Sierra" : "ISO9660"; } }

        /// <summary>Finds the logical volume inside a (possibly raw) CD image. Returns null if none.</summary>
        public static DataSource Locate(DataSource s, out string layout)
        {
            layout = null;
            // fast paths
            var probes = new[] { Tuple.Create(0L, 2048, 0), Tuple.Create(0L, 2352, 16), Tuple.Create(0L, 2352, 24), Tuple.Create(0L, 2336, 8), Tuple.Create(0L, 2448, 16), Tuple.Create(0L, 2448, 24), Tuple.Create(307200L, 2048, 0), Tuple.Create(307200L, 2352, 16), Tuple.Create(307200L, 2352, 24) };
            foreach (var p in probes)
            {
                long pos = p.Item1 + 16L * p.Item2 + p.Item3;
                var b = s.ReadBytes(pos, 8);
                if (IsVd(b)) { layout = p.Item2 + "-byte sectors" + (p.Item1 > 0 ? " at offset " + p.Item1 : ""); return p.Item2 == 2048 && p.Item1 == 0 ? s : new CdSectorSource(s, p.Item1, p.Item2, p.Item3); }
            }
            // slow path: search the first 64 MB for a volume descriptor (multi-track/multi-session images)
            long lim = Math.Min(s.Length, 64L * 1024 * 1024);
            var buf = new byte[1 << 20];
            for (long q = 0; q < lim; q += buf.Length - 16)
            {
                int n = s.Read(q, buf, 0, (int)Math.Min(buf.Length, lim - q));
                for (int i = 0; i + 8 <= n; i++)
                {
                    if (buf[i + 1] != 'C' || !IsVd(buf, i)) continue;
                    long pvd = q + i;
                    foreach (var ss in new[] { 2048, 2352, 2336, 2448 })
                        foreach (var dOff in ss == 2048 ? new[] { 0 } : ss == 2336 ? new[] { 8 } : new[] { 16, 24 })
                        {
                            long bse = pvd - dOff - 16L * ss;
                            if (bse < 0) continue;
                            var cand = new CdSectorSource(s, bse, ss, dOff);
                            var root = cand.ReadBytes(16 * 2048, 2048);
                            if (IsVd(root)) { layout = ss + "-byte sectors at offset " + bse; return cand; }
                        }
                }
                if (n < buf.Length) break;
            }
            return null;
        }

        static bool IsVd(byte[] b, int o = 0)
        {
            if (o + 8 > b.Length) return false;
            bool iso = b[o + 1] == 'C' && b[o + 2] == 'D' && b[o + 3] == '0' && b[o + 4] == '0' && b[o + 5] == '1' && (b[o] == 1 || b[o] == 2 || b[o] == 255 || b[o] == 0);
            return iso;
        }

        public static bool ProbeHsf(DataSource s)
        {
            var b = s.ReadBytes(16 * 2048 + 8, 6);
            return b.Length == 6 && b[0] == 1 && Bin.Match(b, 1, "CDROM");
        }

        public IsoContainer(DataSource s, string layoutHint)
        {
            string layout;
            if (ProbeHsf(s)) { vol = s; hsf = true; layout = "High Sierra"; }
            else
            {
                vol = Locate(s, out layout);
                if (vol == null) throw new FormatException2("no ISO 9660 volume descriptor");
            }
            byte[] pvd = null, svd = null;
            for (int lba = 16; lba < 64; lba++)
            {
                var d = vol.ReadBytes(lba * 2048L, 2048);
                if (d.Length < 2048) break;
                if (hsf) { if (d[8] == 1 && Bin.Match(d, 9, "CDROM")) { pvd = d; break; } if (d[8] == 255) break; continue; }
                if (!Bin.Match(d, 1, "CD001")) break;
                if (d[0] == 1 && pvd == null) pvd = d;
                else if (d[0] == 2 && d[88] == 0x25 && d[89] == 0x2F && (d[90] == 0x40 || d[90] == 0x43 || d[90] == 0x45)) svd = d;
                else if (d[0] == 255) break;
            }
            if (pvd == null) throw new FormatException2("no primary volume descriptor");
            if (hsf)
            {
                rootRec = new byte[34]; Array.Copy(pvd, 180, rootRec, 0, 34);
                Label = Bin.Ascii(pvd, 48, 32).Trim();
            }
            else
            {
                joliet = svd != null;
                var vd = svd ?? pvd;
                rootRec = new byte[34]; Array.Copy(vd, 156, rootRec, 0, 34);
                Label = Bin.Ascii(pvd, 40, 32).Trim();
            }
            Description = FormatName + (joliet ? " + Joliet" : "") + ", " + layout + (Label.Length > 0 ? ", label '" + Label + "'" : "");
        }

        public override IEnumerable<Entry> Entries()
        {
            var stack = new Stack<Tuple<string, long, long, int>>();
            stack.Push(Tuple.Create("", (long)Bin.U32(rootRec, 2), (long)Bin.U32(rootRec, 10), 0));
            var seen = new HashSet<long>();
            while (stack.Count > 0)
            {
                var t = stack.Pop();
                if (t.Item4 > 40 || !seen.Add(t.Item2) || t.Item3 > 32 * 1024 * 1024) continue;
                var d = vol.ReadBytes(t.Item2 * 2048, (int)t.Item3);
                var pending = new List<Entry>();
                string lastName = null; List<Tuple<long, long>> extents = null; Entry lastEntry = null;
                for (int i = 0; i < d.Length; )
                {
                    int rl = d[i];
                    if (rl == 0) { i = (i / 2048 + 1) * 2048; continue; }
                    if (i + rl > d.Length || rl < 33) break;
                    int nl = d[i + 32];
                    int flags = hsf ? d[i + 24] : d[i + 25];
                    long lba = Bin.U32(d, i + 2), size = Bin.U32(d, i + 10);
                    if (nl == 1 && (d[i + 33] == 0 || d[i + 33] == 1)) { i += rl; continue; }
                    string name = joliet ? Encoding.BigEndianUnicode.GetString(d, i + 33, nl & ~1) : Cp437.Decode(d, i + 33, nl);
                    int semi = name.IndexOf(';');
                    if (semi >= 0) name = name.Substring(0, semi);
                    if (name.EndsWith(".")) name = name.Substring(0, name.Length - 1);
                    DateTime? time = null;
                    try { int y = d[i + 18]; if (y > 0) time = new DateTime(1900 + y, Math.Max(1, (int)d[i + 19]), Math.Max(1, (int)d[i + 20]), d[i + 21] % 24, d[i + 22] % 60, d[i + 23] % 60); } catch { }
                    string path = t.Item1 + name;
                    if ((flags & 2) != 0)
                    {
                        stack.Push(Tuple.Create(path + "/", lba, size, t.Item4 + 1));
                        yield return new Entry { Name = path + "/", IsDirectory = true, Size = 0, Time = time };
                    }
                    else
                    {
                        // multi-extent files: consecutive records with the same name, flag 0x80 on all but the last
                        if (lastEntry != null && lastName == path && extents != null) extents.Add(Tuple.Create(lba, size));
                        else { extents = new List<Tuple<long, long>> { Tuple.Create(lba, size) }; }
                        if ((flags & 0x80) == 0)
                        {
                            var ex = extents;
                            var e = new Entry { Name = path, Size = ex.Sum(x => x.Item2), Time = time, Method = "" };
                            e.Open = () =>
                            {
                                if (ex.Count == 1) { long st = ex[0].Item1 * 2048; return vol.Slice(st, Math.Min(ex[0].Item2, Math.Max(0, vol.Length - st))); }
                                return new ConcatSource(ex.Select(x => vol.Slice(x.Item1 * 2048, Math.Min(x.Item2, Math.Max(0, vol.Length - x.Item1 * 2048)))), false);
                            };
                            yield return e;
                            lastEntry = null; extents = null;
                        }
                        else lastEntry = new Entry();
                        lastName = path;
                    }
                    i += rl;
                }
            }
        }
    }

    /// <summary>Virtual PC VHD (fixed and dynamic) exposing the raw disk.</summary>
    public sealed class VhdContainer : Container
    {
        readonly DataSource disk;
        public override string FormatName { get { return "VHD"; } }

        public static bool Probe(DataSource s)
        {
            if (s.Length < 1024) return false;
            var f = s.ReadBytes(s.Length - 512, 8);
            var g = s.ReadBytes(0, 8);
            return Bin.Match(f, 0, "conectix") || Bin.Match(g, 0, "conectix");
        }

        public VhdContainer(DataSource s)
        {
            var foot = s.ReadBytes(s.Length - 512, 512);
            if (!Bin.Match(foot, 0, "conectix")) foot = s.ReadBytes(0, 512);
            long type = Bin.U32BE(foot, 60);
            long size = ((long)Bin.U32BE(foot, 48) << 32) | Bin.U32BE(foot, 52);
            if (type == 2) disk = s.Slice(0, Math.Min(size, s.Length - 512));
            else if (type == 3)
            {
                long dhOff = ((long)Bin.U32BE(foot, 16) << 32) | Bin.U32BE(foot, 20);
                var dh = s.ReadBytes(dhOff, 1024);
                if (!Bin.Match(dh, 0, "cxsparse")) throw new FormatException2("bad VHD dynamic header");
                long bat = ((long)Bin.U32BE(dh, 16) << 32) | Bin.U32BE(dh, 20);
                int entries = (int)Bin.U32BE(dh, 28); long block = Bin.U32BE(dh, 32);
                var batb = s.ReadBytes(bat, entries * 4);
                var parts = new List<DataSource>();
                long bitmap = ((block / 512 / 8) + 511) / 512 * 512;
                var zero = new ZeroSource(block);
                for (int i = 0; i < entries; i++)
                {
                    long sec = Bin.U32BE(batb, i * 4);
                    parts.Add(sec == 0xFFFFFFFF ? (DataSource)zero : s.Slice(sec * 512 + bitmap, block));
                }
                disk = new ConcatSource(parts, false).Slice(0, size);
            }
            else throw new UnsupportedException("VHD type " + type + " (differencing disks need their parent)");
            Description = "Virtual PC VHD (" + (type == 2 ? "fixed" : "dynamic") + "), " + Fmt.Size(size);
        }

        public override IEnumerable<Entry> Entries()
        {
            yield return new Entry { Name = "disk.img", Size = disk.Length, Method = "VHD", Open = () => disk };
        }
    }

    public sealed class ZeroSource : DataSource
    {
        readonly long len;
        public ZeroSource(long l) { len = l; }
        public override long Length { get { return len; } }
        public override int Read(long pos, byte[] buf, int off, int count)
        {
            if (pos >= len) return 0;
            int n = (int)Math.Min(count, len - pos);
            Array.Clear(buf, off, n);
            return n;
        }
    }
}
