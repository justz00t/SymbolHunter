using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SymbolHunter.Core
{
    /// <summary>
    /// ACE 1.0/2.0 archives (Marcel Lemke, 1998+): stored, LZ77 and the ACE 2.0 "blocked" method with
    /// delta and EXE filters. Solid archives and multi-volume sets (.ACE, .C00, .C01 ...).
    /// Ported from acefile (Daniel Roethlisberger), which follows the original unace sources.
    /// </summary>
    public sealed class AceContainer : Container
    {
        sealed class Seg { public DataSource Src; public long Pos, Len; }
        sealed class Item
        {
            public string Name; public long Size; public uint Crc; public int CompType, Params, Flags; public uint Attr; public DateTime? Time;
            public List<Seg> Segs = new List<Seg>(); public bool Incomplete;
            public int DicBits { get { return (Params & 15) + 10; } }
        }

        const int FlagAddSize = 1, FlagComment = 2, Flag64 = 4, FlagMultiVolume = 1 << 11, FlagContPrev = 1 << 12, FlagContNext = 1 << 13, FlagPassword = 1 << 14, FlagSolid = 1 << 15;

        readonly List<Item> items = new List<Item>();
        bool solid;
        public override string FormatName { get { return "ACE"; } }

        public static long FindMainHeader(DataSource s, long maxScan)
        {
            var h = s.ReadBytes(0, (int)Math.Min(s.Length, maxScan));
            for (int i = Bin.IndexOf(h, "**ACE**", 0, h.Length); i >= 0; i = Bin.IndexOf(h, "**ACE**", i + 1, h.Length))
            {
                if (i < 7) continue;
                int hsize = Bin.U16(h, i - 5);
                if (hsize < 20 || i - 7 + 4 + hsize > h.Length) continue;
                if ((AceCrc.Crc32(h, i - 3, hsize) & 0xFFFF) == Bin.U16(h, i - 7) && h[i - 3] == 0) return i - 7;
            }
            return -1;
        }

        public AceContainer(DataSource s, string name, ISiblingProvider sib)
        {
            long start = FindMainHeader(s, 1024 * 1024);
            if (start < 0) throw new FormatException2("ACE main header not found");
            int mainFlags = Parse(s, start, true);
            solid = (mainFlags & FlagSolid) != 0;
            bool more = (mainFlags & FlagMultiVolume) != 0 && items.Count > 0 && (items[items.Count - 1].Flags & FlagContNext) != 0;
            if (more)
            {
                string fn = PathUtil.FileName(name ?? "");
                string stem = Path.GetFileNameWithoutExtension(fn);
                bool any = false;
                for (int v = 0; v < 999 && more; v++)
                {
                    string vn = stem + ".C" + v.ToString("00");
                    var vs = sib != null ? sib.GetSibling(vn) : null;
                    if (vs == null) { vn = stem + ".c" + v.ToString("00"); vs = sib != null ? sib.GetSibling(vn) : null; }
                    if (vs == null) break;
                    long vstart = FindMainHeader(vs, 4096);
                    if (vstart < 0) break;
                    ConsumedVolumes.Add(vn); any = true;
                    Parse(vs, vstart, false);
                    more = items.Count > 0 && (items[items.Count - 1].Flags & FlagContNext) != 0;
                }
                if (!any) Warnings.Add("multi-volume ACE: next volume not found");
            }
            foreach (var it in items) if ((it.Flags & FlagContNext) != 0) it.Incomplete = true;
            Description = "ACE archive, " + items.Count + " files" + (solid ? ", solid" : "") + (ConsumedVolumes.Count > 0 ? ", " + (ConsumedVolumes.Count + 1) + " volumes" : "");
        }

        int Parse(DataSource s, long pos, bool first)
        {
            int mainFlags = 0;
            int guard = 0;
            while (pos + 4 <= s.Length && guard++ < 200000)
            {
                var hh = s.ReadBytes(pos, 4);
                int hcrc = Bin.U16(hh, 0), hsize = Bin.U16(hh, 2);
                var b = s.ReadBytes(pos + 4, hsize);
                if (b.Length < hsize || hsize < 3) { Warnings.Add("archive is truncated"); break; }
                if ((AceCrc.Crc32(b, 0, hsize) & 0xFFFF) != hcrc) { Warnings.Add("damaged header at offset " + pos); break; }
                int type = b[0], flags = Bin.U16(b, 1);
                long addsize = 0;
                if (type == 0) mainFlags = flags;
                else if (type == 1 || type == 3)
                {
                    int i = 3;
                    long pack, orig;
                    if ((flags & Flag64) != 0) { pack = (long)Bin.U64(b, i); orig = (long)Bin.U64(b, i + 8); i += 16; }
                    else { pack = Bin.U32(b, i); orig = Bin.U32(b, i + 4); i += 8; }
                    uint dt = Bin.U32(b, i), attr = Bin.U32(b, i + 4), crc = Bin.U32(b, i + 8);
                    int comptype = b[i + 12], par = Bin.U16(b, i + 14), fnsz = Bin.U16(b, i + 18);
                    i += 20;
                    string fname = PathUtil.Clean(Cp437.Decode(b, i, Math.Min(fnsz, b.Length - i)).Replace('\\', '/'));
                    long dataPos = pos + 4 + hsize;
                    long avail = Math.Max(0, Math.Min(pack, s.Length - dataPos));
                    var seg = new Seg { Src = s, Pos = dataPos, Len = avail };
                    if ((flags & FlagContPrev) != 0 && items.Count > 0 && (items[items.Count - 1].Flags & FlagContNext) != 0)
                    {
                        var prev = items[items.Count - 1];
                        prev.Segs.Add(seg); prev.Flags = (prev.Flags & ~FlagContNext) | (flags & FlagContNext); prev.Crc = crc;
                    }
                    else
                    {
                        var it = new Item { Name = fname, Size = orig, Crc = crc, CompType = comptype, Params = par, Flags = flags, Attr = attr, Time = ZipContainer.DosTime((int)(dt >> 16), (int)(dt & 0xFFFF)) };
                        it.Segs.Add(seg);
                        if ((flags & FlagContPrev) != 0) it.Incomplete = true;
                        items.Add(it);
                    }
                    addsize = pack;
                    if (avail < pack) { items[items.Count - 1].Incomplete = true; Warnings.Add("archive is truncated"); break; }
                }
                else if ((flags & FlagAddSize) != 0) addsize = (flags & Flag64) != 0 ? (long)Bin.U64(b, 3) : Bin.U32(b, 3);
                pos += 4 + hsize + addsize;
            }
            return mainFlags;
        }

        AceDecoder dec;
        int lastDecoded = -1;

        public override IEnumerable<Entry> Entries()
        {
            for (int i = 0; i < items.Count; i++)
            {
                var it = items[i]; int idx = i;
                bool dir = (it.Attr & 0x10) != 0;
                var e = new Entry { Name = it.Name, Size = it.Size, IsDirectory = dir, Method = it.CompType == 0 ? "stored" : it.CompType == 1 ? "ACE 1.0 LZ77" : "ACE 2.0", Time = it.Time, IsEncrypted = (it.Flags & FlagPassword) != 0 };
                if (!dir) e.Open = () => OpenItem(idx, e);
                yield return e;
            }
        }

        DataSource OpenItem(int idx, Entry e)
        {
            if (dec == null || (solid && idx <= lastDecoded)) { dec = new AceDecoder(); lastDecoded = -1; }
            if (solid)
                for (int k = lastDecoded + 1; k < idx; k++)
                {
                    var p = items[k];
                    if ((p.Attr & 0x10) != 0 || p.Size == 0) { lastDecoded = k; continue; }
                    if ((p.Flags & FlagPassword) != 0) throw new UnsupportedException("solid archive with an encrypted earlier file");
                    string ign; using (Decode(k, out ign)) { }
                }
            string damage;
            var res = Decode(idx, out damage);
            var it = items[idx];
            if (damage != null) e.Note = "damaged data (" + damage + "); only the first " + res.Length + " of " + it.Size + " bytes recovered";
            else if (it.Incomplete) e.Note = "file is split across volumes and a volume is missing or truncated";
            else if (res.Length != it.Size) e.Note = "size mismatch (" + res.Length + " of " + it.Size + " bytes)";
            else if (AceCrc.Crc32(res) != it.Crc) e.Note = "CRC error";
            return res;
        }

        DataSource Decode(int idx, out string damage)
        {
            damage = null;
            var it = items[idx];
            lastDecoded = idx;
            if ((it.Flags & FlagPassword) != 0) throw new UnsupportedException("password-protected ACE entry");
            var packed = it.Segs.Count == 1 ? it.Segs[0].Src.Slice(it.Segs[0].Pos, it.Segs[0].Len) : new ConcatSource(it.Segs.Select(sg => sg.Src.Slice(sg.Pos, sg.Len)), true);
            var sink = new Sink(it.Size, it.Size + 65536);
            try
            {
                var data = packed.ReadBytes(0, (int)Math.Min(packed.Length, int.MaxValue - 16));
                try
                {
                    if (it.CompType == 0) { sink.Write(data, 0, (int)Math.Min(data.Length, it.Size)); dec.Register(data, 0, (int)Math.Min(data.Length, it.Size)); }
                    else if (it.CompType == 1) dec.DecodeLz77(data, it.Size, it.DicBits, sink);
                    else if (it.CompType == 2) dec.DecodeBlocked(data, it.Size, it.DicBits, sink);
                    else throw new UnsupportedException("ACE compression type " + it.CompType);
                }
                catch (UnsupportedException) { throw; }
                catch (Exception ex)
                {
                    if (sink.Length == 0) throw new FormatException2("ACE: " + ex.Message);
                    damage = ex.Message;
                }
                return sink.ToSource();
            }
            catch { sink.Dispose(); throw; }
            finally { packed.Dispose(); }
        }
    }

    public static class AceCrc
    {
        /// <summary>ACE CRC-32: standard CRC-32 without the final inversion.</summary>
        public static uint Crc32(byte[] b, int off, int n) { return ~Crc.Crc32(0, b, off, n); }
        public static uint Crc32(DataSource d)
        {
            uint c = 0; var buf = new byte[1 << 16];
            for (long pos = 0; pos < d.Length;)
            {
                int n = d.Read(pos, buf, 0, (int)Math.Min(buf.Length, d.Length - pos));
                if (n <= 0) break;
                c = Crc.Crc32(c, buf, 0, n); pos += n;
            }
            return ~c;
        }
    }

    /// <summary>ACE LZ77 / blocked decompression engine (state persists across files of a solid archive).</summary>
    public sealed class AceDecoder
    {
        // ---------------- bit stream: 32-bit little-endian words, MSB first
        sealed class Bits
        {
            readonly byte[] d; long pos; readonly long lenBits;
            public Bits(byte[] data) { d = data; lenBits = ((long)(data.Length + 3) / 4) * 32; }
            uint Word(long wi) { long o = wi * 4; if (o >= d.Length) return 0; uint v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | (o + i < d.Length ? d[o + i] : (byte)0); return v; }
            public uint Peek(int n)
            {
                if (n == 0) return 0;
                if (pos + n > lenBits + 31) throw new FormatException2("ACE: data ended early");
                long wi = pos >> 5; int bo = (int)(pos & 31);
                ulong two = ((ulong)Word(wi) << 32) | Word(wi + 1);
                return (uint)((two << bo) >> (64 - n));
            }
            public void Skip(int n) { pos += n; }
            public uint Read(int n) { uint v = Peek(n); pos += n; return v; }
            public uint KnownWidth(int bits) { if (bits < 2) return (uint)bits; bits--; return Read(bits) + (1u << bits); }
            public int GolombRice(int rbits, bool signed)
            {
                long value = rbits == 0 ? 0 : Read(rbits);
                int guard = 0;
                while (Read(1) == 1) { value += 1L << rbits; if (++guard > (1 << 20)) throw new FormatException2("ACE: bad Golomb code"); }
                if (!signed) return (int)value;
                return (value & 1) != 0 ? -(int)(value >> 1) - 1 : (int)(value >> 1);
            }
        }

        // ---------------- Huffman trees
        sealed class Tree
        {
            public int[] Codes; public int[] Widths; public int MaxWidth;
            public int Symbol(Bits bs)
            {
                uint c = bs.Peek(MaxWidth);
                if (c >= Codes.Length) throw new FormatException2("ACE: bad Huffman code");
                int s = Codes[c];
                bs.Skip(Widths[s]);
                return s;
            }
        }

        static void QuickSort(int[] keys, int[] vals, int left, int right)
        {
            int nl = left, nr = right, m = keys[right];
            while (true)
            {
                while (keys[nl] > m) nl++;
                while (keys[nr] < m) nr--;
                if (nl <= nr) { Swap(keys, nl, nr); Swap(vals, nl, nr); nl++; nr--; }
                if (nl >= nr) break;
            }
            if (left < nr)
            {
                if (left < nr - 1) QuickSort(keys, vals, left, nr);
                else if (keys[left] < keys[nr]) { Swap(keys, left, nr); Swap(vals, left, nr); }
            }
            if (right > nl)
            {
                if (nl < right - 1) QuickSort(keys, vals, nl, right);
                else if (keys[nl] < keys[right]) { Swap(keys, nl, right); Swap(vals, nl, right); }
            }
        }
        static void Swap(int[] a, int i, int j) { int t = a[i]; a[i] = a[j]; a[j] = t; }

        static Tree MakeTree(int[] widths, int maxWidth)
        {
            int n = widths.Length;
            var sw = (int[])widths.Clone(); var ss = Enumerable.Range(0, n).ToArray();
            if (n > 1) QuickSort(sw, ss, 0, n - 1);
            int used = 0;
            while (used < n && sw[used] != 0) used++;
            if (used < 2) { widths[ss[0]] = 1; sw[0] = 1; if (used == 0) used = 1; }
            var codes = new List<int>();
            int maxCodes = 1 << maxWidth;
            for (int k = used - 1; k >= 0; k--)
            {
                int sym = ss[k], wdt = sw[k];
                if (wdt > maxWidth) throw new FormatException2("ACE: Huffman width too large");
                int rep = 1 << (maxWidth - wdt);
                for (int r = 0; r < rep; r++) codes.Add(sym);
                if (codes.Count > maxCodes) throw new FormatException2("ACE: Huffman table overflow");
            }
            return new Tree { Codes = codes.ToArray(), Widths = widths, MaxWidth = maxWidth };
        }

        static Tree ReadTree(Bits bs, int maxWidth, int numCodes)
        {
            int numWidths = (int)bs.Read(9) + 1;
            if (numWidths > numCodes + 1) numWidths = numCodes + 1;
            int lower = (int)bs.Read(4), upper = (int)bs.Read(4);
            var ww = new int[upper + 1];
            for (int i = 0; i <= upper; i++) ww[i] = (int)bs.Read(3);
            var wtree = MakeTree(ww, 7);
            var widths = new List<int>();
            while (widths.Count < numWidths)
            {
                int sym = wtree.Symbol(bs);
                if (sym < upper) widths.Add(sym);
                else
                {
                    int len = (int)bs.Read(4) + 4;
                    len = Math.Min(len, numWidths - widths.Count);
                    for (int i = 0; i < len; i++) widths.Add(0);
                }
            }
            var w = widths.ToArray();
            if (upper > 0) for (int i = 1; i < w.Length; i++) w[i] = (w[i] + w[i - 1]) % upper;
            for (int i = 0; i < w.Length; i++) if (w[i] > 0) w[i] += lower;
            return MakeTree(w, maxWidth);
        }

        // ---------------- LZ77
        const int MaxCodeWidth = 11, MaxDistAtLen2 = 255, MaxDistAtLen3 = 8191, MaxDicBits = 22;
        const int TypeCode = 260 + MaxDicBits + 1, NumMainCodes = 260 + MaxDicBits + 2, NumLenCodes = 256 - 1;
        const int WinSize = 1 << MaxDicBits, WinMask = WinSize - 1;
        readonly byte[] win = new byte[WinSize];
        long total;
        Tree mainTree, lenTree; int symsToRead;
        readonly int[] hist = new int[4];

        sealed class Mode { public int Kind, DeltaDist, DeltaLen, ExeMode; }

        void Reinit() { symsToRead = 0; mainTree = null; lenTree = null; Array.Clear(hist, 0, 4); }

        public void Register(byte[] b, int off, int n) { for (int i = 0; i < n; i++) win[(total++) & WinMask] = b[off + i]; }

        int MainSymbol(Bits bs)
        {
            if (symsToRead == 0)
            {
                mainTree = ReadTree(bs, MaxCodeWidth, NumMainCodes);
                lenTree = ReadTree(bs, MaxCodeWidth, NumLenCodes);
                symsToRead = (int)bs.Read(15);
            }
            symsToRead--;
            return mainTree.Symbol(bs);
        }

        static Mode ReadMode(Bits bs)
        {
            var m = new Mode { Kind = (int)bs.Read(8) };
            if (m.Kind == 1) { m.DeltaDist = (int)bs.Read(8); m.DeltaLen = (int)bs.Read(17); }
            else if (m.Kind == 2) m.ExeMode = (int)bs.Read(8);
            return m;
        }

        /// <summary>Reads up to want bytes (stops early at a mode change); output goes to the window and to outList.</summary>
        int ReadLz(Bits bs, long want, List<byte> outList, out Mode next)
        {
            next = null;
            long have = 0;
            while (have < want)
            {
                int sym = MainSymbol(bs);
                if (sym <= 255) { win[(total++) & WinMask] = (byte)sym; outList.Add((byte)sym); have++; }
                else if (sym < TypeCode)
                {
                    int len, dist;
                    if (sym <= 259)
                    {
                        len = lenTree.Symbol(bs);
                        int off = sym & 3;
                        dist = hist[3 - off];
                        for (int k = 3 - off; k < 3; k++) hist[k] = hist[k + 1];
                        hist[3] = dist;
                        len += off > 1 ? 3 : 2;
                    }
                    else
                    {
                        dist = (int)bs.KnownWidth(sym - 260);
                        len = lenTree.Symbol(bs);
                        hist[0] = hist[1]; hist[1] = hist[2]; hist[2] = hist[3]; hist[3] = dist;
                        len += dist <= MaxDistAtLen2 ? 2 : dist <= MaxDistAtLen3 ? 3 : 4;
                    }
                    dist++;
                    if (have + len > want) throw new FormatException2("ACE: match runs past the end");
                    if (dist > total || dist > WinSize) throw new FormatException2("ACE: match before start of data");
                    for (int k = 0; k < len; k++) { byte v = win[(total - dist) & WinMask]; win[(total++) & WinMask] = v; outList.Add(v); }
                    have += len;
                }
                else if (sym == TypeCode) { next = ReadMode(bs); break; }
                else throw new FormatException2("ACE: bad symbol");
            }
            return (int)have;
        }

        // ---------------- SOUND (ACE 2.0 multimedia: 8/16/32-bit audio predictor)
        static readonly int[] soundQuant = MakeSoundQuant();
        static int[] MakeSoundQuant() { var q = new int[256]; for (int i = 1; i <= 128; i++) { int bl = 0; for (int v = i; v > 0; v >>= 1) bl++; q[i & 255] = bl; q[(256 - i) & 255] = bl; } return q; }
        static int SChar(int i) { return ((i + 128) & 255) - 128; }
        static readonly int[] soundChannels = { 1, 2, 3, 3 };
        static readonly int[][] useChannels = { new[] { 0, 0, 0, 0 }, new[] { 0, 1, 0, 1 }, new[] { 0, 1, 0, 2 }, new[] { 1, 0, 2, 0 } };
        const int SndRunLen = 32, SndTypeCode = 256 + SndRunLen, SndNumCodes = 256 + SndRunLen + 1, SndMaxWidth = 10;

        sealed class SoundState
        {
            public int Mode; public Tree[] Trees; public int SymsToRead; public SoundChannel[] Ch;
            public int Symbol(Bits bs, int model)
            {
                if (SymsToRead == 0) { for (int i = 0; i < Trees.Length; i++) Trees[i] = ReadTree(bs, SndMaxWidth, SndNumCodes); SymsToRead = (int)bs.Read(15); }
                SymsToRead--;
                return Trees[model].Symbol(bs);
            }
        }

        sealed class SoundChannel
        {
            readonly SoundState st; readonly int modelBase;
            readonly int[] predDifCnt = new int[2], lastPredDifCnt = new int[2], rarDifCnt = new int[4], rarCoeff = new int[4], rarDif = new int[9];
            int byteCount, lastSample, lastDelta, adaptCnt, adaptUse, getState, getCode;
            public SoundChannel(SoundState s, int idx) { st = s; modelBase = 3 * idx; }
            /// <summary>Returns the next value, or -1 with a mode change in next.</summary>
            public int Get(Bits bs, out Mode next)
            {
                next = null;
                int value = 0;
                if (getState != 2)
                {
                    int model = getState << 1; if (model == 0) model += adaptUse; model += modelBase;
                    getCode = st.Symbol(bs, model);
                    if (getCode == SndTypeCode) { next = ReadMode(bs); return -1; }
                }
                if (getState == 0)
                {
                    if (getCode >= SndRunLen) { value = getCode - SndRunLen; adaptCnt = (adaptCnt * 7 >> 3) + value; adaptUse = adaptCnt > 40 ? 1 : 0; }
                    else getState = 2;
                }
                else if (getState == 1) { value = getCode; getState = 0; }
                if (getState == 2) { if (getCode == 0) getState = 1; else getCode--; value = 0; }
                return (value & 1) != 0 ? 255 - (value >> 1) : value >> 1;
            }
            int Predicted() { return (8 * lastSample + rarCoeff[0] * rarDifCnt[0] + rarCoeff[1] * rarDifCnt[1] + rarCoeff[2] * rarDifCnt[2] + rarCoeff[3] * rarDifCnt[3]) >> 3 & 255; }
            public int Predict() { return predDifCnt[0] > predDifCnt[1] ? lastSample : Predicted(); }
            public void Adjust(int sample)
            {
                byteCount++;
                int predSample = Predicted();
                int predDif = SChar(predSample - sample) << 3;
                rarDif[0] += Math.Abs(predDif - rarDifCnt[0]); rarDif[1] += Math.Abs(predDif + rarDifCnt[0]);
                rarDif[2] += Math.Abs(predDif - rarDifCnt[1]); rarDif[3] += Math.Abs(predDif + rarDifCnt[1]);
                rarDif[4] += Math.Abs(predDif - rarDifCnt[2]); rarDif[5] += Math.Abs(predDif + rarDifCnt[2]);
                rarDif[6] += Math.Abs(predDif - rarDifCnt[3]); rarDif[7] += Math.Abs(predDif + rarDifCnt[3]);
                rarDif[8] += Math.Abs(predDif);
                lastDelta = SChar(sample - lastSample);
                predDifCnt[0] += soundQuant[(predDif >> 3) & 255];
                predDifCnt[1] += soundQuant[(lastSample - sample) & 255];
                lastSample = sample;
                if ((byteCount & 0x1F) == 0)
                {
                    int minDif = 0xFFFF, minPos = 8;
                    for (int i = 8; i >= 0; i--) { if (rarDif[i] <= minDif) { minDif = rarDif[i]; minPos = i; } rarDif[i] = 0; }
                    if (minPos != 8)
                    {
                        int i = minPos >> 1;
                        if ((minPos & 1) == 0) { if (rarCoeff[i] >= -16) rarCoeff[i]--; }
                        else { if (rarCoeff[i] <= 16) rarCoeff[i]++; }
                    }
                    if ((byteCount & 0xFF) == 0)
                        for (int i = 0; i < 2; i++) { predDifCnt[i] -= lastPredDifCnt[i]; lastPredDifCnt[i] = predDifCnt[i]; }
                }
                rarDifCnt[3] = rarDifCnt[2]; rarDifCnt[2] = rarDifCnt[1]; rarDifCnt[1] = lastDelta - rarDifCnt[0]; rarDifCnt[0] = lastDelta;
            }
        }

        SoundState sound;
        void SoundReinit(int mode)
        {
            int m = mode - 3;
            sound = new SoundState { Mode = m, Trees = new Tree[soundChannels[m] * 3] };
            sound.Ch = new SoundChannel[soundChannels[m]];
            for (int i = 0; i < sound.Ch.Length; i++) sound.Ch[i] = new SoundChannel(sound, i);
        }

        List<byte> SoundRead(Bits bs, long want, out Mode next)
        {
            next = null;
            var chunk = new List<byte>();
            long n = want & ~3L;
            for (long i = 0; i < n; i++)
            {
                int c = useChannels[sound.Mode][i % 4];
                Mode nm;
                int v = sound.Ch[c].Get(bs, out nm);
                if (nm != null) { next = nm; break; }
                int sample = (v + sound.Ch[c].Predict()) & 255;
                chunk.Add((byte)sample);
                sound.Ch[c].Adjust(SChar(sample));
            }
            return chunk;
        }

        // ---------------- PIC (ACE 2.0 multimedia: 2-D pixel predictor)
        static readonly int[] picDifBits = MakePicDifBits();
        static int BitLen(int v) { int n = 0; while (v > 0) { n++; v >>= 1; } return n; }
        static int[] MakePicDifBits() { var t = new int[256]; for (int i = 0; i < 128; i++) t[i] = BitLen(2 * i); for (int i = -128; i < 0; i++) t[i + 256] = BitLen(-2 * i - 1); return t; }
        static readonly int[] picQ = MakePicQ(1), picQ9 = MakePicQ(9), picQ81 = MakePicQ(81);
        static int[] MakePicQ(int mul)
        {
            var q = new List<int>();
            for (int i = -255; i < -20; i++) q.Add(-4); for (int i = -20; i < -6; i++) q.Add(-3); for (int i = -6; i < -2; i++) q.Add(-2); for (int i = -2; i < 0; i++) q.Add(-1);
            q.Add(0);
            for (int i = 1; i < 3; i++) q.Add(1); for (int i = 3; i < 7; i++) q.Add(2); for (int i = 7; i < 21; i++) q.Add(3); for (int i = 21; i < 256; i++) q.Add(4);
            return q.Select(x => x * mul).ToArray();
        }
        sealed class ErrCtx { public int Used, Pred, Avg = 4; public int[] Err = new int[4]; }

        sealed class PixelDec
        {
            public int Kind, A, B, C, D, X;
            public PixelDec(int kind) { Kind = kind; if (kind != 0) A = B = C = X = 128; }
            public void Shift() { C = A; A = D; B = X; }
            public void UpdateD(int thisD, int refD)
            {
                if (Kind == 0) D = thisD;
                else if (Kind == 1) D = (128 + thisD - refD) & 255;
                else D = (128 + thisD - (refD * 11 >> 4)) & 255;
            }
            public int Produce(int refX) { return Kind == 0 ? X : Kind == 1 ? (X + refX - 128) & 255 : (X + (refX * 11 >> 4) - 128) & 255; }
            public int Context() { return Math.Abs(picQ81[255 + D - A] + picQ9[255 + A - C] + picQ[255 + C - B]); }
            int PredictWith(int p) { return p == 0 ? A : p == 1 ? B : p == 2 ? (A + B) >> 1 : (A + B - C) & 255; }
            public void UpdateX(Bits bs, ErrCtx ctx)
            {
                ctx.Used++;
                int r = ctx.Avg / ctx.Used;
                int eps = bs.GolombRice(BitLen(r), true);
                X = (PredictWith(ctx.Pred) + eps) & 255;
                ctx.Avg += Math.Abs(eps);
                if (ctx.Used == 128) { ctx.Used >>= 1; ctx.Avg >>= 1; }
                int best = 0;
                for (int i = 0; i < 4; i++)
                {
                    ctx.Err[i] += picDifBits[(X - PredictWith(i)) & 255];
                    if (i == 0 || ctx.Err[i] < ctx.Err[best]) best = i;
                }
                ctx.Pred = best;
                if (ctx.Err.Any(e => e > 0x7F)) for (int i = 0; i < 4; i++) ctx.Err[i] >>= 1;
            }
        }

        int picWidth, picPlanes; ErrCtx[] picModel0, picModelN; int[] picPrev; readonly List<byte> picLeft = new List<byte>();

        void PicReinit(Bits bs)
        {
            picWidth = bs.GolombRice(12, false); picPlanes = bs.GolombRice(2, false);
            if (picWidth < 0 || picWidth > (1 << 20) || picPlanes < 0 || picPlanes > 64) throw new FormatException2("ACE: bad picture header");
            picModel0 = Enumerable.Range(0, 365).Select(_ => new ErrCtx()).ToArray();
            picModelN = Enumerable.Range(0, 365).Select(_ => new ErrCtx()).ToArray();
            picPrev = new int[picWidth + picPlanes];
            picLeft.Clear();
        }

        int[] PicRow(Bits bs)
        {
            int len = picWidth + picPlanes;
            var row = new int[len];
            for (int plane = 0; plane < picPlanes; plane++)
            {
                ErrCtx[] model; PixelDec dec;
                if (plane == 0) { model = picModel0; dec = new PixelDec(0); }
                else { model = picModelN; int k = (int)bs.Read(2); if (k > 2) throw new FormatException2("ACE: bad pixel decoder"); dec = new PixelDec(k); }
                dec.UpdateD(picPrev[plane], picPrev[plane - 1 < 0 ? len - 1 : plane - 1]);
                for (int col = plane; col < picWidth; col += picPlanes)
                {
                    dec.Shift();
                    dec.UpdateD(picPrev[col + picPlanes], picPrev[col + picPlanes - 1]);
                    var ctx = model[dec.Context()];
                    dec.UpdateX(bs, ctx);
                    row[col] = dec.Produce(row[col - 1 < 0 ? len - 1 : col - 1]);
                }
            }
            picPrev = row;
            return row;
        }

        List<byte> PicRead(Bits bs, long want, out Mode next)
        {
            next = null;
            var chunk = new List<byte>();
            if (picLeft.Count > 0) { chunk.AddRange(picLeft); picLeft.Clear(); }
            while (chunk.Count < want)
            {
                if (bs.Read(1) == 0) { next = ReadMode(bs); break; }
                var row = PicRow(bs);
                int n = (int)Math.Min(want - chunk.Count, picWidth);
                for (int i = 0; i < n; i++) chunk.Add((byte)row[i]);
                for (int i = n; i < picWidth; i++) picLeft.Add((byte)row[i]);
            }
            return chunk;
        }

        public void DecodeLz77(byte[] data, long size, int dicBits, Sink sink)
        {
            Reinit();
            var bs = new Bits(data);
            long produced = 0;
            var buf = new List<byte>(65536);
            while (produced < size)
            {
                buf.Clear();
                Mode nm;
                int n = ReadLz(bs, Math.Min(size - produced, 1 << 20), buf, out nm);
                if (nm != null) throw new FormatException2("ACE: mode change in an ACE 1.0 stream");
                if (n == 0) break;
                var arr = buf.ToArray(); sink.Write(arr, 0, arr.Length); produced += n;
            }
        }

        public void DecodeBlocked(byte[] data, long size, int dicBits, Sink sink)
        {
            Reinit();
            var bs = new Bits(data);
            long produced = 0;
            Mode mode = new Mode { Kind = 0 }, next = null;
            var exeLeft = new List<byte>();
            int lastDelta = 0;
            int guard = 0;
            while (produced < size)
            {
                if (++guard > 50000000) throw new FormatException2("ACE: no progress");
                if (next != null)
                {
                    if (mode.Kind != next.Kind)
                    {
                        if (next.Kind >= 3 && next.Kind <= 6) SoundReinit(next.Kind);
                        else if (next.Kind == 7) PicReinit(bs);
                    }
                    mode = next; next = null;
                }
                var outc = new List<byte>();
                if (mode.Kind == 1)
                {
                    var delta = new List<byte>();
                    while (delta.Count < mode.DeltaLen)
                    {
                        Mode nm;
                        ReadLz(bs, mode.DeltaLen - delta.Count, delta, out nm);
                        if (nm != null)
                        {
                            if (next != null) throw new FormatException2("ACE: delta block clobbers mode");
                            next = nm;
                            if (delta.Count == 0) break;
                        }
                    }
                    if (delta.Count == 0 && next != null) continue;
                    var dl = delta.ToArray();
                    for (int i = 0; i < dl.Length; i++) { dl[i] = (byte)(dl[i] + lastDelta); lastDelta = dl[i]; }
                    if (mode.DeltaDist == 0) throw new FormatException2("ACE: bad delta distance");
                    int planeSize = mode.DeltaLen / mode.DeltaDist;
                    for (int pp = 0; pp < planeSize; pp++)
                        for (int plane = 0; plane < mode.DeltaLen && plane + pp < dl.Length; plane += planeSize)
                            outc.Add(dl[plane + pp]);
                }
                else if (mode.Kind == 0 || mode.Kind == 2)
                {
                    if (exeLeft.Count > 0) { outc.AddRange(exeLeft); exeLeft.Clear(); }
                    long want = size - produced - outc.Count;
                    if (want > 0)
                    {
                        Mode nm;
                        ReadLz(bs, want, outc, out nm);
                        next = nm;
                    }
                    if (mode.Kind == 2)
                    {
                        int i = 0, cnt = outc.Count;
                        for (; i < cnt; i++)
                        {
                            if (i + 4 >= cnt) break;
                            if (outc[i] == 0xE8)
                            {
                                long pos = produced + i;
                                if (mode.ExeMode == 0)
                                {
                                    int r = outc[i + 1] | (outc[i + 2] << 8); r = (int)((r - pos) & 0xFFFF);
                                    outc[i + 1] = (byte)r; outc[i + 2] = (byte)(r >> 8); i += 2;
                                }
                                else
                                {
                                    uint r = (uint)(outc[i + 1] | (outc[i + 2] << 8) | (outc[i + 3] << 16) | (outc[i + 4] << 24));
                                    r = (uint)((r - pos) & 0xFFFFFFFF);
                                    outc[i + 1] = (byte)r; outc[i + 2] = (byte)(r >> 8); outc[i + 3] = (byte)(r >> 16); outc[i + 4] = (byte)(r >> 24); i += 4;
                                }
                            }
                            else if (outc[i] == 0xE9)
                            {
                                long pos = produced + i;
                                int r = outc[i + 1] | (outc[i + 2] << 8); r = (int)((r - pos) & 0xFFFF);
                                outc[i + 1] = (byte)r; outc[i + 2] = (byte)(r >> 8); i += 2;
                            }
                        }
                        // E8/E9 too close to the end: carry it to the next block (unless this is the end of the file)
                        if (produced + outc.Count < size)
                            for (int k = i + 1; k < outc.Count; k++)
                                if (outc[k] == 0xE8 || outc[k] == 0xE9) { exeLeft.AddRange(outc.GetRange(k, outc.Count - k)); outc.RemoveRange(k, outc.Count - k); break; }
                    }
                }
                else if (mode.Kind >= 3 && mode.Kind <= 6)
                {
                    if (sound == null) SoundReinit(mode.Kind);
                    outc = SoundRead(bs, size - produced, out next);
                    var a = outc.ToArray(); Register(a, 0, a.Length);
                }
                else if (mode.Kind == 7)
                {
                    if (picPrev == null) throw new FormatException2("ACE: picture block without header");
                    outc = PicRead(bs, size - produced, out next);
                    var a = outc.ToArray(); Register(a, 0, a.Length);
                }
                else throw new FormatException2("ACE: unknown block mode " + mode.Kind);
                if (outc.Count == 0 && next == null) throw new FormatException2("ACE: no data");
                var arr = outc.ToArray();
                sink.Write(arr, 0, arr.Length);
                produced += arr.Length;
            }
        }
    }
}
