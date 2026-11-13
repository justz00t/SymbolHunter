using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SymbolHunter.Core
{
    /// <summary>Microsoft Cabinet (MSCF): stored, MSZIP, LZX; cabinet sets that continue into the next cabinet.</summary>
    public sealed class CabContainer : Container
    {
        sealed class Block { public DataSource Src; public long Pos; public int CSize, USize; }
        sealed class Folder { public int Type; public List<Block> Blocks = new List<Block>(); public long Total; public string Damage; }
        sealed class FileRec { public string Name; public long Size, Offset; public int Folder; public DateTime? Time; }

        readonly List<Folder> folders = new List<Folder>();
        readonly List<FileRec> files = new List<FileRec>();
        public override string FormatName { get { return "CAB"; } }

        public static bool Probe(byte[] h) { return h.Length >= 36 && Bin.Match(h, 0, "MSCF") && h[25] == 1 && (Bin.U32(h, 4) == 0 || (h[24] == 3 && Bin.U32(h, 20) == 0)); }

        /// <summary>Strict header check used when searching for cabinets inside other data.</summary>
        static bool StrictHeader(byte[] h, int o, long remaining)
        {
            if (o + 36 > h.Length || !Bin.Match(h, o, "MSCF")) return false;
            long cb = Bin.U32(h, o + 8), coff = Bin.U32(h, o + 16);
            return Bin.U32(h, o + 20) == 0 && h[o + 24] == 3 && h[o + 25] == 1 &&
                   cb >= 44 && coff >= 36 && coff < cb && cb <= remaining + 512 && Bin.U16(h, o + 26) >= 1 && Bin.U16(h, o + 28) >= 1 && (Bin.U16(h, o + 30) & ~7) == 0;
        }

        /// <summary>Finds cabinets stored inside other data (installer data files, raw dumps); returns (offset, length) pairs.</summary>
        public static List<KeyValuePair<long, long>> FindEmbedded(DataSource s, long maxScan)
        {
            var res = new List<KeyValuePair<long, long>>();
            long limit = Math.Min(s.Length, maxScan);
            const int chunk = 1 << 20;
            for (long basePos = 0; basePos < limit; basePos += chunk)
            {
                var h = s.ReadBytes(basePos, (int)Math.Min(chunk + 64, s.Length - basePos));
                int end = (int)Math.Min(chunk, limit - basePos);
                for (int i = Bin.IndexOf(h, "MSCF", 0, Math.Min(h.Length, end + 4)); i >= 0 && i < end; i = Bin.IndexOf(h, "MSCF", i + 1, Math.Min(h.Length, end + 4)))
                {
                    long at = basePos + i;
                    if (res.Count > 0 && at < res[res.Count - 1].Key + res[res.Count - 1].Value) continue;
                    if (!StrictHeader(h, i, s.Length - at)) continue;
                    res.Add(new KeyValuePair<long, long>(at, Bin.U32(h, i + 8)));
                    if (res.Count >= 64) return res;
                }
            }
            return res;
        }

        public CabContainer(DataSource s, string name, ISiblingProvider sib)
        {
            string next = Load(s, true);
            int guard = 0;
            while (next != null && sib != null && guard++ < 100)
            {
                var ns = sib.GetSibling(next);
                if (ns == null) { Warnings.Add("missing next cabinet " + next); break; }
                ConsumedVolumes.Add(next);
                next = Load(ns, false);
            }
            Description = "Microsoft CAB, " + files.Count + " files, " + string.Join(", ", folders.Select(f => TypeName(f.Type)).Distinct());
        }

        static string TypeName(int t) { switch (t & 15) { case 0: return "stored"; case 1: return "MSZIP"; case 2: return "Quantum"; case 3: return "LZX"; default: return "type " + t; } }

        /// <summary>Loads one cabinet; returns the next cabinet's name if the set continues.</summary>
        string Load(DataSource s, bool first)
        {
            var h = s.ReadBytes(0, 64);
            if (h.Length < 36 || !Bin.Match(h, 0, "MSCF")) throw new FormatException2("not a cabinet");
            long cbCabinet = Bin.U32(h, 8), coffFiles = Bin.U32(h, 16);
            int cFolders = Bin.U16(h, 26), cFiles = Bin.U16(h, 28), flags = Bin.U16(h, 30);
            if (cbCabinet > s.Length) Warnings.Add("cabinet is truncated (" + s.Length + " of " + cbCabinet + " bytes present)");
            int p = 36, cbFolder = 0, cbData = 0;
            if ((flags & 4) != 0)
            {
                if (h.Length < 40) throw new FormatException2("cabinet header truncated");
                int cbHdr = Bin.U16(h, 36); cbFolder = h[38]; cbData = h[39]; p = 40 + cbHdr;
            }
            if (coffFiles > s.Length) throw new FormatException2("file table lies beyond the end of the cabinet");
            var hdr = s.ReadBytes(0, (int)Math.Min(s.Length, Math.Max(coffFiles + 65536, 4096)));
            Func<int, int, bool> has = (at, n) => at >= 0 && at + n <= hdr.Length;
            string nextCab = null;
            if ((flags & 1) != 0) { p = SkipStr(hdr, p); p = SkipStr(hdr, p); }
            if ((flags & 2) != 0)
            {
                int e = p < hdr.Length ? Array.IndexOf(hdr, (byte)0, p) : -1;
                if (e < 0) throw new FormatException2("cabinet header truncated (next cabinet name)");
                nextCab = Encoding.ASCII.GetString(hdr, p, e - p);
                if (nextCab.Length == 0) nextCab = null;
                p = SkipStr(hdr, e + 1);
            }
            bool continuesPrev = (flags & 1) != 0 && folders.Count > 0;
            int baseIdx = continuesPrev ? folders.Count - 1 : folders.Count;
            for (int i = 0; i < cFolders; i++)
            {
                if (!has(p, 8)) throw new FormatException2("cabinet header truncated (folder table)");
                long start = Bin.U32(hdr, p); int nData = Bin.U16(hdr, p + 4), type = Bin.U16(hdr, p + 6);
                p += 8 + cbFolder;
                Folder f;
                if (i == 0 && continuesPrev) f = folders[baseIdx];
                else { f = new Folder { Type = type }; folders.Add(f); }
                long dp = start;
                for (int k = 0; k < nData; k++)
                {
                    var db = s.ReadBytes(dp, 8);
                    if (db.Length < 8) { if (cbCabinet <= s.Length) Warnings.Add("data blocks missing (cabinet truncated)"); f.Damage = "cabinet is truncated"; break; }
                    int cb = Bin.U16(db, 4), ub = Bin.U16(db, 6);
                    if (dp + 8 + cbData + cb > s.Length) { if (cbCabinet <= s.Length) Warnings.Add("data blocks missing (cabinet truncated)"); f.Damage = "cabinet is truncated"; break; }
                    f.Blocks.Add(new Block { Src = s, Pos = dp + 8 + cbData, CSize = cb, USize = ub });
                    f.Total += ub;
                    dp += 8 + cbData + cb;
                }
            }
            int fp = (int)coffFiles;
            for (int i = 0; i < cFiles; i++)
            {
                if (!has(fp, 17)) { Warnings.Add("file table truncated after " + i + " of " + cFiles + " files"); break; }
                long size = Bin.U32(hdr, fp), off = Bin.U32(hdr, fp + 4);
                int ifolder = Bin.U16(hdr, fp + 8), date = Bin.U16(hdr, fp + 10), time = Bin.U16(hdr, fp + 12), attr = Bin.U16(hdr, fp + 14);
                int e = Array.IndexOf(hdr, (byte)0, fp + 16);
                if (e < 0) { Warnings.Add("file table truncated after " + i + " of " + cFiles + " files"); break; }
                string nm = (attr & 0x80) != 0 ? Encoding.UTF8.GetString(hdr, fp + 16, e - fp - 16) : Cp437.Decode(hdr, fp + 16, e - fp - 16);
                fp = e + 1;
                if (nm.Length == 0) continue;
                int folderIdx;
                if (ifolder == 0xFFFD || ifolder == 0xFFFF) { if (continuesPrev) continue; folderIdx = baseIdx; }
                else if (ifolder == 0xFFFE) folderIdx = baseIdx + cFolders - 1;
                else folderIdx = baseIdx + ifolder;
                if (folderIdx < 0 || folderIdx >= folders.Count) continue;
                files.Add(new FileRec { Name = PathUtil.Clean(nm), Size = size, Offset = off, Folder = folderIdx, Time = ZipContainer.DosTime(date, time) });
            }
            return nextCab;
        }

        static int SkipStr(byte[] b, int p) { if (p >= b.Length) return b.Length; int e = Array.IndexOf(b, (byte)0, p); return e < 0 ? b.Length : e + 1; }

        readonly Dictionary<int, DataSource> decoded = new Dictionary<int, DataSource>();

        DataSource DecodeFolder(int idx)
        {
            DataSource d;
            if (decoded.TryGetValue(idx, out d)) return d;
            var f = folders[idx];
            var sink = new Sink(f.Total, -1);
            try
            {
                int type = f.Type & 15;
                LzwWindowHolder mszip = null; LzxDecoder lzx = null; QuantumDecoder qtm = null;
                if (type == 1) mszip = new LzwWindowHolder(sink);
                else if (type == 3) lzx = new LzxDecoder((f.Type >> 8) & 0x1F);
                else if (type == 2) qtm = new QuantumDecoder((f.Type >> 8) & 0x1F);
                else if (type != 0) throw new UnsupportedException("CAB compression type " + type);
                byte[] carry = null;
                int bi = 0;
                try
                {
                    foreach (var b in f.Blocks)
                    {
                        var data = b.Src.ReadBytes(b.Pos, b.CSize);
                        if (carry != null) { var m = new byte[carry.Length + data.Length]; Buffer.BlockCopy(carry, 0, m, 0, carry.Length); Buffer.BlockCopy(data, 0, m, carry.Length, data.Length); data = m; carry = null; }
                        if (b.USize == 0) { carry = data; bi++; continue; }
                        if (type == 0) sink.Write(data, 0, Math.Min(data.Length, b.USize));
                        else if (type == 1)
                        {
                            if (data.Length < 2 || data[0] != 'C' || data[1] != 'K') throw new FormatException2("MSZIP: missing CK signature");
                            var br = new BitReaderLsb(new ByteInput(new MemorySource(data, 2, data.Length - 2), 0, data.Length - 2));
                            mszip.Block(br, b.USize);
                        }
                        else if (type == 3) lzx.DecodeFrame(data, data.Length, b.USize, sink);
                        else qtm.DecodeFrame(data, b.USize, sink);
                        bi++;
                    }
                }
                catch (Exception ex)
                {
                    if (ex is UnsupportedException || sink.Length == 0 || ex is System.Threading.ThreadAbortException) throw;
                    // keep everything decoded before the damaged block
                    f.Damage = "damaged cabinet data in block " + (bi + 1) + " of " + f.Blocks.Count + " (" + ex.Message + ")";
                }
                d = sink.ToSource();
                decoded[idx] = d;
                return d;
            }
            catch { sink.Dispose(); throw; }
        }

        /// <summary>MSZIP keeps the 32K history between blocks.</summary>
        sealed class LzwWindowHolder
        {
            readonly LzWindow w;
            public LzwWindowHolder(Sink s) { w = new LzWindow(15, s, -1); }
            public void Block(BitReaderLsb br, int usize)
            {
                long target = w.Total + usize;
                Inflate.Run(br, w, false);
                w.Flush();
                if (w.Total != target) throw new FormatException2("MSZIP: block size mismatch");
            }
        }

        public override IEnumerable<Entry> Entries()
        {
            foreach (var fr in files)
            {
                var f = fr;
                var e = new Entry { Name = f.Name, Size = f.Size, Method = TypeName(folders.Count > f.Folder ? folders[f.Folder].Type : 0), Time = f.Time };
                e.Open = () =>
                {
                    var d = DecodeFolder(f.Folder);
                    if (f.Offset + f.Size > d.Length)
                    {
                        string dmg = folders[f.Folder].Damage;
                        e.Note = dmg != null ? dmg + "; only the first " + Math.Max(0, d.Length - f.Offset) + " of " + f.Size + " bytes recovered" : "data missing (incomplete cabinet set?)";
                        return d.Slice(Math.Min(f.Offset, d.Length), Math.Max(0, d.Length - f.Offset));
                    }
                    return d.Slice(f.Offset, f.Size);
                };
                yield return e;
            }
        }

        public override void Dispose() { foreach (var d in decoded.Values) d.Dispose(); decoded.Clear(); }
    }

    /// <summary>MS-DOS COMPRESS.EXE / EXPAND.EXE single files (SZDD, KWAJ, and the old "SZ" variant).</summary>
    public sealed class MsCompressContainer : Container
    {
        readonly DataSource src; readonly string outName; readonly int kind; readonly long dataOff, usize; readonly int kwajMethod;
        public override string FormatName { get { return kind == 2 ? "KWAJ" : "SZDD"; } }

        public static bool Probe(byte[] h)
        {
            return h.Length >= 14 && (Bin.Match(h, 0, new byte[] { (byte)'S', (byte)'Z', (byte)'D', (byte)'D', 0x88, 0xF0, 0x27, 0x33 }) ||
                                      Bin.Match(h, 0, new byte[] { (byte)'K', (byte)'W', (byte)'A', (byte)'J', 0x88, 0xF0, 0x27, 0xD1 }) ||
                                      Bin.Match(h, 0, new byte[] { (byte)'S', (byte)'Z', (byte)' ', 0x88, 0xF0, 0x27, 0x33, 0xD1 }));
        }

        public MsCompressContainer(DataSource s, string name)
        {
            src = s;
            var h = s.ReadBytes(0, 64);
            string fn = PathUtil.FileName(name);
            if (Bin.Match(h, 0, "SZDD"))
            {
                kind = 1; dataOff = 14; usize = Bin.U32(h, 10);
                char missing = (char)h[9];
                outName = fn.EndsWith("_") && missing >= 0x20 && missing < 0x7F ? fn.Substring(0, fn.Length - 1) + missing : fn + ".out";
            }
            else if (Bin.Match(h, 0, "SZ "))
            {
                kind = 3; dataOff = 12; usize = Bin.U32(h, 8);
                outName = fn.EndsWith("_") ? fn.Substring(0, fn.Length - 1) + "?" : fn + ".out";
            }
            else
            {
                kind = 2;
                kwajMethod = Bin.U16(h, 8); dataOff = Bin.U16(h, 10);
                int flags = Bin.U16(h, 12);
                int p = 14; long len = -1;
                if ((flags & 1) != 0) { len = Bin.U32(h, p); p += 4; }
                if ((flags & 2) != 0) p += 2;
                if ((flags & 4) != 0) { int n = Bin.U16(h, p); p += 2 + n; }
                string bn = null, ext = null;
                var hh = s.ReadBytes(0, (int)Math.Min(s.Length, dataOff + 16));
                if ((flags & 8) != 0) { int e = Array.IndexOf(hh, (byte)0, p); if (e < 0) e = p; bn = Encoding.ASCII.GetString(hh, p, e - p); p = e + 1; }
                if ((flags & 16) != 0) { int e = Array.IndexOf(hh, (byte)0, p); if (e < 0) e = p; ext = Encoding.ASCII.GetString(hh, p, e - p); p = e + 1; }
                usize = len;
                outName = bn != null ? bn + (string.IsNullOrEmpty(ext) ? "" : "." + ext) : (fn.EndsWith("_") ? fn.Substring(0, fn.Length - 1) + "?" : fn + ".out");
            }
            Description = FormatName + " compressed file";
        }

        public override IEnumerable<Entry> Entries()
        {
            var e = new Entry { Name = outName, Size = usize, Method = FormatName };
            e.Open = () =>
            {
                var sink = new Sink(usize, usize);
                try
                {
                    var inp = new ByteInput(src, dataOff, -1);
                    if (kind == 1 || kind == 3) Lzss(inp, sink, usize, kind == 3 ? 4096 - 18 : 4096 - 16);
                    else
                    {
                        switch (kwajMethod)
                        {
                            case 0: { var b = new byte[65536]; int n; while ((n = inp.Read(b, 0, b.Length)) > 0) sink.Write(b, 0, n); break; }
                            case 1: { var b = new byte[65536]; int n; while ((n = inp.Read(b, 0, b.Length)) > 0) { for (int i = 0; i < n; i++) b[i] ^= 0xFF; sink.Write(b, 0, n); } break; }
                            case 2: Lzss(inp, sink, usize, 4096 - 16); break;
                            case 4:
                                {
                                    // MSZIP blocks: each "CK" + deflate, 32K history kept
                                    var w = new LzWindow(15, sink, usize);
                                    while (true)
                                    {
                                        int a = inp.ReadByte(), b2 = inp.ReadByte();
                                        if (a < 0 || b2 < 0) break;
                                        // block length precedes "CK" in KWAJ MSZIP
                                        int c1 = inp.ReadByte(), c2 = inp.ReadByte();
                                        if (c1 != 'C' || c2 != 'K') break;
                                        int blen = a | (b2 << 8);
                                        var blk = new byte[Math.Max(0, blen - 2)];
                                        inp.Read(blk, 0, blk.Length);
                                        Inflate.Run(new BitReaderLsb(new ByteInput(blk)), w, false);
                                        if (w.Done) break;
                                    }
                                    w.Flush();
                                    break;
                                }
                            default: throw new UnsupportedException("KWAJ method " + kwajMethod);
                        }
                    }
                    return sink.ToSource();
                }
                catch { sink.Dispose(); throw; }
            };
            yield return e;
        }

        static void Lzss(ByteInput inp, Sink sink, long size, int startPos)
        {
            var w = new LzWindow(12, sink, size < 0 ? -1 : size, 0x20) { AllowPreHistory = true };
            int pos = startPos;   // ring position bookkeeping (window starts at 4096-16)
            w.Pos = startPos;
            while (!w.Done)
            {
                int ctl = inp.ReadByte();
                if (ctl < 0) break;
                for (int bit = 0; bit < 8 && !w.Done; bit++)
                {
                    if ((ctl & (1 << bit)) != 0)
                    {
                        int c = inp.ReadByte(); if (c < 0) { w.Flush(); return; }
                        w.Put((byte)c);
                    }
                    else
                    {
                        int a = inp.ReadByte(), b = inp.ReadByte(); if (a < 0 || b < 0) { w.Flush(); return; }
                        int mpos = a | ((b & 0xF0) << 4);
                        int len = (b & 0x0F) + 3;
                        w.CopyFrom(mpos, len);
                    }
                }
            }
            w.Flush();
        }
    }
}
