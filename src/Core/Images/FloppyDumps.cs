using System;
using System.Collections.Generic;
using System.Linq;

namespace SymbolHunter.Core
{
    /// <summary>Floppy dump formats (Teledisk, ImageDisk, CopyQM) converted to a linear sector image.</summary>
    public sealed class FloppyDumpContainer : Container
    {
        readonly string kind; DataSource raw; readonly string note;
        public override string FormatName { get { return kind; } }

        public static string Probe(byte[] h)
        {
            if (h.Length < 16) return null;
            if ((Bin.Match(h, 0, "TD") || Bin.Match(h, 0, "td")) && h[2] < 0x10 && Crc.CrcTd0(h, 0, 10) == Bin.U16(h, 10)) return "Teledisk";
            if (Bin.Match(h, 0, "IMD ") && h.Length > 10 && char.IsDigit((char)h[4])) return "ImageDisk";
            if (h.Length >= 133 && Bin.Match(h, 0, "CQ\u0014")) { int sum = 0; for (int i = 0; i < 133; i++) sum += h[i]; if ((sum & 0xFF) == 0) return "CopyQM"; }
            return null;
        }

        sealed class Sec { public int C, H, R, Size; public byte[] Data; }

        public FloppyDumpContainer(DataSource s, string kind)
        {
            this.kind = kind;
            var secs = new List<Sec>();
            if (kind == "ImageDisk") { if (!ReadImd(s.ReadAll(), secs)) Warnings.Add("image is truncated; missing sectors read as empty"); }
            else if (kind == "Teledisk")
            {
                note = ReadTd0(s, secs);
                if (note != null && note.Contains("truncated")) Warnings.Add("image is truncated; missing sectors read as empty");
                if (note != null && note.Contains("damaged")) Warnings.Add("image has damaged sectors (read as empty)");
            }
            else { raw = ReadCqm(s); Description = "CopyQM image, " + Fmt.Size(raw.Length); return; }
            raw = Assemble(secs);
            Description = kind + " image, " + secs.Count + " sectors" + (note != null ? ", " + note : "");
        }

        /// <summary>Reads all sectors; returns false when the image ends early (sectors read so far are kept).</summary>
        static bool ReadImd(byte[] d, List<Sec> secs)
        {
            int p = Array.IndexOf(d, (byte)0x1A);
            if (p < 0) throw new FormatException2("IMD: no header terminator");
            p++;
            while (p + 5 <= d.Length)
            {
                int mode = d[p], cyl = d[p + 1], head = d[p + 2], n = d[p + 3], sz = d[p + 4];
                p += 5;
                if (mode > 5 || n == 0) { if (n == 0) continue; if (secs.Count > 0) return false; throw new FormatException2("IMD: bad track header"); }
                int mapBytes = n * (1 + ((head & 0x80) != 0 ? 1 : 0) + ((head & 0x40) != 0 ? 1 : 0) + (sz == 0xFF ? 2 : 0));
                if (p + mapBytes > d.Length) return false;
                var rmap = new int[n]; for (int i = 0; i < n; i++) rmap[i] = d[p + i]; p += n;
                int[] cmap = null, hmap = null, szs = null;
                if ((head & 0x80) != 0) { cmap = new int[n]; for (int i = 0; i < n; i++) cmap[i] = d[p + i]; p += n; }
                if ((head & 0x40) != 0) { hmap = new int[n]; for (int i = 0; i < n; i++) hmap[i] = d[p + i]; p += n; }
                if (sz == 0xFF) { szs = new int[n]; for (int i = 0; i < n; i++) szs[i] = Bin.U16(d, p + i * 2); p += 2 * n; }
                for (int i = 0; i < n; i++)
                {
                    int size = szs != null ? szs[i] : 128 << Math.Min(sz, 6);
                    if (p >= d.Length) return false;
                    int t = d[p++];
                    byte[] data = null;
                    if (t == 0) { }
                    else if ((t & 1) == 1) { if (p + size > d.Length) return false; data = new byte[size]; Array.Copy(d, p, data, 0, size); p += size; }
                    else { if (p >= d.Length) return false; data = new byte[size]; byte fill = d[p++]; for (int k = 0; k < size; k++) data[k] = fill; }
                    if (data != null) secs.Add(new Sec { C = cmap != null ? cmap[i] : cyl, H = hmap != null ? hmap[i] : head & 0x0F, R = rmap[i], Size = size, Data = data });
                }
            }
            return true;
        }

        static string ReadTd0(DataSource s, List<Sec> secs)
        {
            var hdr = s.ReadBytes(0, 12);
            bool adv = hdr[0] == 't';
            int ver = hdr[4];
            byte[] d;
            if (adv)
            {
                if (ver < 20) throw new UnsupportedException("Teledisk 1.x advanced compression");
                var sink = new Sink(-1, 64L * 1024 * 1024);
                // the decompressed size is unknown: decode until input ends
                var br = new BitReaderMsb(new ByteInput(s, 12, -1));
                var lz = new Lzhuf(br);
                try { lz.Run(sink, 16L * 1024 * 1024 + 1); } catch (FormatException2) { }
                var body = sink.ToArray(); sink.Dispose();
                d = new byte[12 + body.Length];
                Array.Copy(hdr, d, 12); Array.Copy(body, 0, d, 12, body.Length);
            }
            else d = s.ReadAll();
            int p = 12;
            bool damaged = false;
            if ((hdr[7] & 0x80) != 0)
            {
                if (d.Length < p + 10) throw new FormatException2("Teledisk: image ends inside the comment block");
                int clen = Bin.U16(d, p + 2);
                p += 10 + clen;
            }
            while (p + 4 <= d.Length)
            {
                int nsec = d[p], cyl = d[p + 1], head = d[p + 2] & 1;
                p += 4;
                if (nsec == 0xFF) break;
                for (int i = 0; i < nsec; i++)
                {
                    if (p + 6 > d.Length) return (adv ? "advanced compression, " : "") + "truncated";
                    int c = d[p], h = d[p + 1], r = d[p + 2], sz = d[p + 3], flags = d[p + 4];
                    p += 6;
                    if ((flags & 0x20) != 0 || (sz & 0xF8) != 0) continue;
                    int size = 128 << sz;
                    var data = new byte[size];
                    for (int k = 0; k < size; k++) data[k] = 0xE5;
                    if ((flags & 0x10) == 0)
                    {
                        if (p + 3 > d.Length) return (adv ? "advanced compression, " : "") + "truncated";
                        int blen = Bin.U16(d, p); int method = d[p + 2];
                        int start = p + 3, end = p + 2 + blen;
                        if (blen == 0) { damaged = true; p += 2; secs.Add(new Sec { C = c, H = h & 1, R = r, Size = size, Data = data }); continue; }
                        p = end;
                        if (end > d.Length) return (adv ? "advanced compression, " : "") + "truncated";
                        int q = start, o = 0;
                        if (method == 0) { Array.Copy(d, q, data, 0, Math.Max(0, Math.Min(size, end - q))); }
                        else if (method == 1)
                        {
                            while (q + 4 <= end) { int cnt = Bin.U16(d, q); byte b1 = d[q + 2], b2 = d[q + 3]; q += 4; for (int k = 0; k < cnt && o + 1 < size; k++) { data[o++] = b1; data[o++] = b2; } }
                        }
                        else if (method == 2)
                        {
                            while (q + 2 <= end && o < size)
                            {
                                int a = d[q], b = d[q + 1]; q += 2;
                                if (a == 0) { for (int k = 0; k < b && o < size && q < end; k++) data[o++] = d[q++]; }
                                else
                                {
                                    int blk = 1 << a;
                                    if (q + blk > end) break;
                                    for (int rep = 0; rep < b; rep++) for (int k = 0; k < blk && o < size; k++) data[o++] = d[q + k];
                                    q += blk;
                                }
                            }
                        }
                        else damaged = true;   // unknown encoding: keep the sector as empty
                    }
                    secs.Add(new Sec { C = c, H = h & 1, R = r, Size = size, Data = data });
                }
            }
            string res = adv ? "advanced compression" : null;
            if (damaged) res = (res != null ? res + ", " : "") + "damaged sectors";
            return res;
        }

        static DataSource ReadCqm(DataSource s)
        {
            var h = s.ReadBytes(0, 133);
            int ssize = Bin.U16(h, 3), spt = Bin.U16(h, 0x10), heads = Bin.U16(h, 0x12);
            int usedCyls = h[0x5A], cyls = h[0x5B], clen = Bin.U16(h, 0x6F);
            long total = (long)ssize * spt * heads * Math.Max(cyls, usedCyls);
            if (ssize == 0 || spt == 0 || heads == 0 || total <= 0 || total > 64L * 1024 * 1024) throw new FormatException2("CopyQM: bad geometry");
            long want = (long)ssize * spt * heads * usedCyls;
            var outb = new byte[total];
            long o = 0;
            var inp = new ByteInput(s, 133 + clen, -1);
            while (o < want)
            {
                int lo = inp.ReadByte(), hi = inp.ReadByte();
                if (lo < 0 || hi < 0) break;
                short len = (short)(lo | (hi << 8));
                if (len <= 0)
                {
                    int fill = inp.ReadByte(); if (fill < 0) break;
                    for (int k = 0; k < -len && o < outb.Length; k++) outb[o++] = (byte)fill;
                }
                else
                {
                    var b = new byte[len];
                    int n = inp.Read(b, 0, len);
                    for (int k = 0; k < n && o < outb.Length; k++) outb[o++] = b[k];
                    if (n < len) break;
                }
            }
            return new MemorySource(outb);
        }

        static DataSource Assemble(List<Sec> secs)
        {
            if (secs.Count == 0) throw new FormatException2("no sectors in image");
            int ssize = secs.GroupBy(x => x.Size).OrderByDescending(g => g.Count()).First().Key;
            var std = secs.Where(x => x.Size == ssize).ToList();
            int heads = std.Max(x => x.H) + 1;
            int baseR = std.GroupBy(x => x.R).OrderBy(g => g.Key).First().Key;
            var perTrack = std.GroupBy(x => x.C * 2 + x.H).Select(g => g.Max(x => x.R) - baseR + 1).ToList();
            int spt = perTrack.GroupBy(x => x).OrderByDescending(g => g.Count()).First().Key;
            int cyls = std.Max(x => x.C) + 1;
            long total = (long)cyls * heads * spt * ssize;
            if (total > 64L * 1024 * 1024) throw new FormatException2("unreasonable floppy geometry");
            var img = new byte[total];
            foreach (var x in std)
            {
                int r = x.R - baseR;
                if (r < 0 || r >= spt || x.H >= heads) continue;
                long off = (((long)x.C * heads + x.H) * spt + r) * ssize;
                Array.Copy(x.Data, 0, img, off, ssize);
            }
            return new MemorySource(img);
        }

        public override IEnumerable<Entry> Entries()
        {
            yield return new Entry { Name = "disk.img", Size = raw.Length, Method = kind, Open = () => raw };
        }
    }
}
