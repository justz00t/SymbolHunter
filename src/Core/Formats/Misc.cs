using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SharpCompress.Readers;

namespace SymbolHunter.Core
{
    /// <summary>RAR 1.5-5.x via the bundled SharpCompress decoders, including multi-volume sets and solid archives.</summary>
    public sealed class RarContainer : Container
    {
        readonly List<Stream> streams = new List<Stream>();
        readonly List<DataSource> volSources = new List<DataSource>();
        public override string FormatName { get { return "RAR"; } }

        public static bool Probe(byte[] h) { return h.Length >= 7 && Bin.Match(h, 0, "Rar!\u001a\u0007"); }
        public static bool ProbeOld(byte[] h) { return h.Length >= 4 && Bin.Match(h, 0, "RE~^"); }

        public static long FindArchive(DataSource s, long from, long max)
        {
            var b = s.ReadBytes(from, (int)Math.Min(s.Length - from, max));
            int i = Bin.IndexOf(b, "Rar!\u001a\u0007", 0, b.Length);
            return i < 0 ? -1 : from + i;
        }

        public RarContainer(DataSource s, string name, ISiblingProvider sib)
        {
            long start = Probe(s.ReadBytes(0, 8)) ? 0 : FindArchive(s, 0, 4 * 1024 * 1024);
            if (start < 0) throw new FormatException2("no RAR signature");
            volSources.Add(start == 0 ? s : s.Slice(start, -1));
            var h = s.ReadBytes(start, 64);
            bool rar5 = h.Length > 7 && h[6] == 1;
            bool multi = false, newNaming = false;
            if (!rar5 && h.Length >= 13) { int flags = Bin.U16(h, 10); multi = (flags & 0x0001) != 0; newNaming = (flags & 0x0010) != 0; }
            else if (rar5) { multi = IsRar5Volume(h); newNaming = true; }
            if (multi && sib != null)
            {
                foreach (var vn in VolumeNames(PathUtil.FileName(name), newNaming))
                {
                    var vs = sib.GetSibling(vn);
                    if (vs == null) break;
                    volSources.Add(vs);
                    ConsumedVolumes.Add(vn);
                }
                if (volSources.Count == 1)
                    for (int k = 1; k < 1000; k++)
                    {
                        var alt = VolumeSets.NumberedNext(PathUtil.FileName(name), k);
                        if (alt == null) break;
                        var vs = sib.GetSibling(alt);
                        if (vs == null) break;
                        volSources.Add(vs); ConsumedVolumes.Add(alt);
                    }
            }
            foreach (var v in volSources) streams.Add(v.OpenStream());
            Description = "RAR" + (rar5 ? "5" : "") + (volSources.Count > 1 ? ", " + volSources.Count + " volumes" : multi ? ", first volume only" : "");
            if (multi && volSources.Count == 1) Warnings.Add("multi-volume RAR: next volume not found");
        }

        static bool IsRar5Volume(byte[] h)
        {
            // main archive header follows the 8-byte signature: CRC32, vint size, vint type(1), vint flags
            int p = 12;
            Func<long> vint = () => { long v = 0; int sh = 0; while (p < h.Length) { byte b = h[p++]; v |= (long)(b & 0x7F) << sh; sh += 7; if ((b & 0x80) == 0) break; } return v; };
            vint(); long type = vint(); long hflags = vint(); // size, type, header flags
            if (type != 1) return false;
            if ((hflags & 1) != 0) vint();   // extra area size
            if ((hflags & 2) != 0) vint();   // data size
            long flags = vint();
            return (flags & 1) != 0;
        }

        public static IEnumerable<string> VolumeNames(string first, bool newNaming)
        {
            var m = System.Text.RegularExpressions.Regex.Match(first, @"^(.*\.part)(\d+)(\.rar)$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success)
            {
                int width = m.Groups[2].Value.Length, n = int.Parse(m.Groups[2].Value);
                for (int i = n + 1; i < n + 1000; i++) yield return m.Groups[1].Value + i.ToString().PadLeft(width, '0') + m.Groups[3].Value;
                yield break;
            }
            int dot = first.LastIndexOf('.');
            string stem = dot >= 0 ? first.Substring(0, dot) : first;
            bool upper = dot >= 0 && first.Substring(dot + 1).ToUpperInvariant() == first.Substring(dot + 1);
            for (int i = 0; i < 1000; i++)
            {
                char c = (char)((upper ? 'R' : 'r') + i / 100);
                yield return stem + "." + c + (i % 100).ToString("00");
            }
        }

        public override IEnumerable<Entry> Entries()
        {
            IReader reader;
            try { reader = SharpCompress.Readers.Rar.RarReader.Open(streams, new ReaderOptions { LeaveStreamOpen = true }); }
            catch (Exception ex) { throw new FormatException2("RAR: " + ex.Message); }
            using (reader)
            {
                while (true)
                {
                    bool ok;
                    try { ok = reader.MoveToNextEntry(); }
                    catch (Exception ex) { Warnings.Add("RAR: " + ex.Message); yield break; }
                    if (!ok) yield break;
                    var re = reader.Entry;
                    var e = new Entry { Name = PathUtil.Clean(re.Key ?? ""), Size = re.Size, CompressedSize = re.CompressedSize, IsDirectory = re.IsDirectory, IsEncrypted = re.IsEncrypted, Method = "RAR", Time = re.LastModifiedTime };
                    var rdr = reader;
                    if (!re.IsDirectory)
                        e.Open = () =>
                        {
                            if (re.IsEncrypted) throw new UnsupportedException("encrypted (password protected)");
                            var sink = new Sink(re.Size, -1);
                            try
                            {
                                using (var st = rdr.OpenEntryStream())
                                {
                                    var buf = new byte[1 << 16]; int n;
                                    var sw = System.Diagnostics.Stopwatch.StartNew();
                                    while ((n = st.Read(buf, 0, buf.Length)) > 0)
                                    {
                                        sink.Write(buf, 0, n);
                                        if (sink.Length > re.Size + (1 << 20) && re.Size >= 0) throw new FormatException2("RAR: decoder overrun");
                                    }
                                }
                                return sink.ToSource();
                            }
                            catch (Exception ex) when (!(ex is UnsupportedException) && !(ex is FormatException2)) { sink.Dispose(); throw new FormatException2("RAR: " + ex.Message); }
                            catch { sink.Dispose(); throw; }
                        };
                    yield return e;
                }
            }
        }

        public override void Dispose() { foreach (var s in streams) s.Dispose(); }
    }

    /// <summary>7-Zip archives via the bundled SharpCompress decoders.</summary>
    public sealed class SevenZipContainer : Container
    {
        readonly Stream stream;
        public override string FormatName { get { return "7z"; } }
        public static bool Probe(byte[] h) { return h.Length >= 6 && Bin.Match(h, 0, new byte[] { (byte)'7', (byte)'z', 0xBC, 0xAF, 0x27, 0x1C }); }
        public SevenZipContainer(DataSource s) { stream = s.OpenStream(); Description = "7-Zip archive"; }

        public override IEnumerable<Entry> Entries()
        {
            SharpCompress.Archives.SevenZip.SevenZipArchive arc;
            IReader reader;
            try { arc = SharpCompress.Archives.SevenZip.SevenZipArchive.Open(stream, new ReaderOptions { LeaveStreamOpen = true }); reader = arc.ExtractAllEntries(); }
            catch (Exception ex) { throw new FormatException2("7z: " + ex.Message); }
            using (arc)
            {
                while (true)
                {
                    bool ok;
                    try { ok = reader.MoveToNextEntry(); }
                    catch (NotSupportedException ex) { throw new UnsupportedException("7z: " + ex.Message); }
                    catch (Exception ex) { throw new FormatException2("7z: " + ex.Message); }
                    if (!ok) yield break;
                    var re = reader.Entry;
                    var e = new Entry { Name = PathUtil.Clean(re.Key ?? ""), Size = re.Size, CompressedSize = re.CompressedSize, IsDirectory = re.IsDirectory, IsEncrypted = re.IsEncrypted, Method = "7z", Time = re.LastModifiedTime };
                    var rdr = reader;
                    if (!re.IsDirectory)
                        e.Open = () =>
                        {
                            var sink = new Sink(re.Size, -1);
                            try
                            {
                                using (var st = rdr.OpenEntryStream()) { var buf = new byte[1 << 16]; int n; while ((n = st.Read(buf, 0, buf.Length)) > 0) sink.Write(buf, 0, n); }
                                return sink.ToSource();
                            }
                            catch (Exception ex) { sink.Dispose(); if (ex is FormatException2 || ex is UnsupportedException) throw; throw new FormatException2("7z: " + ex.Message); }
                        };
                    yield return e;
                }
            }
        }
        public override void Dispose() { stream.Dispose(); }
    }

    /// <summary>A container holding exactly one stream (gzip, bzip2, xz, Unix compress).</summary>
    public sealed class SingleStreamContainer : Container
    {
        readonly string kind, innerName; readonly DataSource src; readonly long size;
        public override string FormatName { get { return kind; } }

        public static string Probe(byte[] h)
        {
            if (h.Length < 4) return null;
            if (h[0] == 0x1F && h[1] == 0x8B && h[2] == 8) return "gzip";
            if (h[0] == 0x1F && h[1] == 0x9D) return "compress";
            if (Bin.Match(h, 0, "BZh") && h[3] >= '1' && h[3] <= '9') return "bzip2";
            if (h.Length >= 6 && Bin.Match(h, 0, new byte[] { 0xFD, (byte)'7', (byte)'z', (byte)'X', (byte)'Z', 0 })) return "xz";
            return null;
        }

        public SingleStreamContainer(DataSource s, string name, string kind)
        {
            src = s; this.kind = kind; size = -1;
            string fn = PathUtil.FileName(name);
            string lower = fn.ToLowerInvariant();
            innerName = lower.EndsWith(".tgz") ? fn.Substring(0, fn.Length - 4) + ".tar" :
                        lower.EndsWith(".gz") || lower.EndsWith(".xz") ? fn.Substring(0, fn.Length - 3) :
                        lower.EndsWith(".bz2") ? fn.Substring(0, fn.Length - 4) :
                        lower.EndsWith(".z") ? fn.Substring(0, fn.Length - 2) : fn + ".out";
            if (kind == "gzip")
            {
                var h = s.ReadBytes(0, 1024);
                int flags = h[3];
                if ((flags & 8) != 0)
                {
                    int p = 10;
                    if ((flags & 4) != 0) p += 2 + Bin.U16(h, 10);
                    int e = Array.IndexOf(h, (byte)0, p);
                    if (e > p) innerName = PathUtil.FileName(Cp437.Decode(h, p, e - p));
                }
                if (s.Length >= 18) size = s.U32(s.Length - 4);
            }
            Description = kind + " stream";
        }

        public override IEnumerable<Entry> Entries()
        {
            var e = new Entry { Name = innerName, Size = kind == "gzip" ? size : -1, Method = kind };
            e.Open = () =>
            {
                var sink = new Sink(-1, -1);
                try
                {
                    if (kind == "gzip") Gunzip(src, sink);
                    else if (kind == "compress")
                    {
                        var d = src.ReadAll();
                        if (d.Length < 3) throw new FormatException2("compress: too short");
                        if ((d[2] & 0x80) == 0) throw new UnsupportedException("compress without block mode");
                        ArcLzw.Dynamic(d, 3, Math.Max(9, Math.Min(16, d[2] & 0x1F)), false, sink);
                    }
                    else if (kind == "bzip2") ZipContainer.CopyStream(new SharpCompress.Compressors.BZip2.BZip2Stream(src.OpenStream(), SharpCompress.Compressors.CompressionMode.Decompress, true), sink);
                    else ZipContainer.CopyStream(new SharpCompress.Compressors.Xz.XZStream(src.OpenStream()), sink);
                    return sink.ToSource();
                }
                catch (Exception ex) { sink.Dispose(); if (ex is FormatException2 || ex is UnsupportedException) throw; throw new FormatException2(kind + ": " + ex.Message); }
            };
            yield return e;
        }

        static void Gunzip(DataSource s, Sink sink)
        {
            long p = 0;
            while (p + 18 <= s.Length)
            {
                var h = s.ReadBytes(p, 1024);
                if (h[0] != 0x1F || h[1] != 0x8B) break;
                int flags = h[3]; int q = 10;
                if ((flags & 4) != 0) q += 2 + Bin.U16(h, q);
                if ((flags & 8) != 0) { int e = Array.IndexOf(h, (byte)0, q); q = e + 1; }
                if ((flags & 16) != 0) { int e = Array.IndexOf(h, (byte)0, q); q = e + 1; }
                if ((flags & 2) != 0) q += 2;
                var inp = new ByteInput(s, p + q, -1);
                var br = new BitReaderLsb(inp);
                var w = new LzWindow(15, sink, -1);
                if (!Inflate.Run(br, w)) { w.Flush(); throw new FormatException2("gzip: truncated"); }
                w.Flush();
                br.AlignToByte();
                long end = inp.Position - br.BitsInBuffer / 8;
                p = end + 8;
            }
        }
    }

    /// <summary>tar archives (v7, ustar, GNU long names, pax paths).</summary>
    public sealed class TarContainer : Container
    {
        readonly DataSource src;
        public override string FormatName { get { return "TAR"; } }
        public TarContainer(DataSource s) { src = s; Description = "tar archive"; }

        public static bool Probe(byte[] h)
        {
            if (h.Length < 512) return false;
            if (Bin.Match(h, 257, "ustar")) return true;
            // v7: verify header checksum
            long chk = Octal(h, 148, 8);
            if (chk <= 0) return false;
            long sum = 0;
            for (int i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 32 : h[i];
            return sum == chk && h[0] != 0;
        }

        static long Octal(byte[] b, int o, int n)
        {
            if ((b[o] & 0x80) != 0) { long v = 0; for (int i = 1; i < n; i++) v = (v << 8) | b[o + i]; return v; }
            long r = 0; bool any = false;
            for (int i = 0; i < n; i++) { byte c = b[o + i]; if (c >= '0' && c <= '7') { r = r * 8 + (c - '0'); any = true; } else if (any && (c == 0 || c == ' ')) break; }
            return any ? r : -1;
        }

        public override IEnumerable<Entry> Entries()
        {
            long p = 0; string longName = null;
            while (p + 512 <= src.Length)
            {
                var h = src.ReadBytes(p, 512);
                if (h.All(x => x == 0)) yield break;
                long size = Math.Max(0, Octal(h, 124, 12));
                char type = (char)h[156];
                string name = Cp437.Decode(h, 0, 100);
                if (Bin.Match(h, 257, "ustar") && h[345] != 0) name = Cp437.Decode(h, 345, 155) + "/" + name;
                long data = p + 512;
                p = data + (size + 511) / 512 * 512;
                if (type == 'L') { longName = Cp437.Decode(src.ReadBytes(data, (int)Math.Min(size, 4096))); continue; }
                if (type == 'x' || type == 'g')
                {
                    var t = Encoding.UTF8.GetString(src.ReadBytes(data, (int)Math.Min(size, 65536)));
                    var m = System.Text.RegularExpressions.Regex.Match(t, @"\d+ path=([^\n]*)\n");
                    if (m.Success && type == 'x') longName = m.Groups[1].Value;
                    continue;
                }
                if (longName != null) { name = longName; longName = null; }
                bool dir = type == '5' || name.EndsWith("/");
                if (type != '0' && type != '\0' && type != '7' && !dir) continue;
                long d0 = data, sz = size;
                var e = new Entry { Name = PathUtil.Clean(name), Size = size, IsDirectory = dir, Method = "tar" };
                if (!dir) e.Open = () => src.Slice(d0, Math.Min(sz, src.Length - d0));
                yield return e;
            }
        }
    }
}
