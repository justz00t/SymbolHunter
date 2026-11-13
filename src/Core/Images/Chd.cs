using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SymbolHunter.Core
{
    /// <summary>
    /// MAME CHD (Compressed Hunks of Data) reader: versions 3, 4 and 5; codecs none, zlib, LZMA, Huffman,
    /// FLAC and the CD variants (cdzl, cdlz, cdfl). Hard disks become a disk image, CD-ROMs one ISO view per
    /// data track. Clone CHDs are read together with their parent when it is found nearby.
    /// Layouts follow MAME's chd.cpp / cdrom.cpp (and libchdr).
    /// </summary>
    public sealed class ChdFile : IDisposable
    {
        public const string Magic = "MComprHD";
        const uint CodecZlib = 0x7a6c6962, CodecLzma = 0x6c7a6d61, CodecHuff = 0x68756666, CodecFlac = 0x666c6163, CodecZstd = 0x7a737464,
                   CodecAvhu = 0x61766875, CodecCdzl = 0x63647a6c, CodecCdlz = 0x63646c7a, CodecCdfl = 0x6364666c, CodecCdzs = 0x63647a73;
        public const int CdFrameSize = 2448, CdSectorData = 2352, CdSubcode = 96;

        readonly DataSource src;
        public int Version;
        public long LogicalBytes;
        public int HunkBytes, UnitBytes;
        public long HunkCount;
        public uint[] Codecs = new uint[4];
        public byte[] Sha1 = new byte[20], ParentSha1 = new byte[20];
        public long MetaOffset;
        public ChdFile Parent;
        public bool NeedsParent;
        int v34Compression;
        byte[] rawMap;          // v5 compressed: 12 bytes per hunk; v5 uncompressed: 4 bytes; v3/v4: 16 bytes
        public readonly HashSet<string> UnsupportedCodecs = new HashSet<string>();
        public int FailedHunks;

        public static bool Probe(byte[] h) { return h.Length >= 16 && Bin.Match(h, 0, Magic) && Bin.U32BE(h, 12) >= 3 && Bin.U32BE(h, 12) <= 5; }

        public ChdFile(DataSource s)
        {
            src = s;
            var h = s.ReadBytes(0, 124);
            if (h.Length < 16 || !Bin.Match(h, 0, Magic)) throw new FormatException2("not a CHD file");
            uint hlen = Bin.U32BE(h, 8);
            Version = (int)Bin.U32BE(h, 12);
            if (Version == 5)
            {
                if (hlen != 124 || h.Length < 124) throw new FormatException2("CHD v5: bad header");
                for (int i = 0; i < 4; i++) Codecs[i] = Bin.U32BE(h, 16 + i * 4);
                LogicalBytes = (long)Bin.U64BE(h, 32);
                long mapOffset = (long)Bin.U64BE(h, 40);
                MetaOffset = (long)Bin.U64BE(h, 48);
                HunkBytes = (int)Bin.U32BE(h, 56);
                UnitBytes = (int)Bin.U32BE(h, 60);
                Array.Copy(h, 84, Sha1, 0, 20);
                Array.Copy(h, 104, ParentSha1, 0, 20);
                if (HunkBytes <= 0 || HunkBytes > 16 * 1024 * 1024 || UnitBytes <= 0) throw new FormatException2("CHD v5: bad hunk size");
                HunkCount = (LogicalBytes + HunkBytes - 1) / HunkBytes;
                if (HunkCount > 64 * 1024 * 1024) throw new FormatException2("CHD v5: too many hunks");
                NeedsParent = ParentSha1.Any(b => b != 0);
                if (Codecs[0] == 0) rawMap = s.ReadBytes(mapOffset, (int)(HunkCount * 4));
                else DecompressV5Map(mapOffset);
            }
            else if (Version == 3 || Version == 4)
            {
                int expect = Version == 3 ? 120 : 108;
                if (hlen != expect) throw new FormatException2("CHD v" + Version + ": bad header");
                h = s.ReadBytes(0, expect);
                uint flags = Bin.U32BE(h, 16);
                v34Compression = (int)Bin.U32BE(h, 20);
                HunkCount = Bin.U32BE(h, 24);
                LogicalBytes = (long)Bin.U64BE(h, 28);
                MetaOffset = (long)Bin.U64BE(h, 36);
                if (Version == 3) { HunkBytes = (int)Bin.U32BE(h, 76); Array.Copy(h, 80, Sha1, 0, 20); Array.Copy(h, 100, ParentSha1, 0, 20); }
                else { HunkBytes = (int)Bin.U32BE(h, 44); Array.Copy(h, 48, Sha1, 0, 20); Array.Copy(h, 68, ParentSha1, 0, 20); }
                UnitBytes = 512;
                if (HunkBytes <= 0 || HunkBytes > 16 * 1024 * 1024 || HunkCount > 64 * 1024 * 1024) throw new FormatException2("CHD: bad hunk size");
                NeedsParent = (flags & 1) != 0;
                rawMap = s.ReadBytes(expect, (int)(HunkCount * 16));
                if (v34Compression == 3) UnsupportedCodecs.Add("A/V (LaserDisc)");
            }
            else throw new UnsupportedException("CHD version " + Version);
            if (Version == 5) foreach (var c in Codecs)
            {
                if (c == CodecAvhu) UnsupportedCodecs.Add("A/V Huffman (LaserDisc)");
                if (c == CodecZstd || c == CodecCdzs) UnsupportedCodecs.Add("zstd");
            }
        }

        public void Dispose() { }

        static string Tag(uint t) { return new string(new[] { (char)(t >> 24), (char)((t >> 16) & 255), (char)((t >> 8) & 255), (char)(t & 255) }); }
        public string CodecNames { get { return Version == 5 ? string.Join(", ", Codecs.Where(c => c != 0).Select(Tag)) + (Codecs[0] == 0 ? "uncompressed" : "") : (v34Compression == 0 ? "uncompressed" : "zlib"); } }

        // ------------------------------------------------------------------ v5 map

        void DecompressV5Map(long mapOffset)
        {
            var mh = src.ReadBytes(mapOffset, 16);
            if (mh.Length < 16) throw new FormatException2("CHD map header missing");
            uint mapBytes = Bin.U32BE(mh, 0);
            long firstOffs = ((long)Bin.U16BE(mh, 4) << 32) | Bin.U32BE(mh, 6);
            int mapCrc = Bin.U16BE(mh, 10);
            int lengthBits = mh[12], selfBits = mh[13], parentBits = mh[14];
            if (lengthBits > 32 || selfBits > 32 || parentBits > 32) throw new FormatException2("CHD map: bad field widths");
            var comp = src.ReadBytes(mapOffset + 16, (int)Math.Min(mapBytes, int.MaxValue));
            var bits = new MsbBits(comp);
            var dec = new MameHuffman(16, 8);
            dec.ImportTreeRle(bits);
            rawMap = new byte[HunkCount * 12];
            int repcount = 0; byte lastcomp = 0;
            for (long h = 0; h < HunkCount; h++)
            {
                long p = h * 12;
                if (repcount > 0) { rawMap[p] = lastcomp; repcount--; }
                else
                {
                    int val = dec.Decode(bits);
                    if (val == 7) { rawMap[p] = lastcomp; repcount = 2 + dec.Decode(bits); }
                    else if (val == 8) { rawMap[p] = lastcomp; repcount = 2 + 16 + (dec.Decode(bits) << 4); repcount += dec.Decode(bits); }
                    else rawMap[p] = lastcomp = (byte)val;
                }
            }
            long curoffset = firstOffs; long lastSelf = 0, lastParent = 0;
            for (long h = 0; h < HunkCount; h++)
            {
                long p = h * 12;
                long offset = curoffset; long length = 0; int crc = 0;
                switch (rawMap[p])
                {
                    case 0: case 1: case 2: case 3: curoffset += length = bits.Read(lengthBits); crc = (int)bits.Read(16); break;
                    case 4: curoffset += length = HunkBytes; crc = (int)bits.Read(16); break;
                    case 5: lastSelf = offset = bits.Read(selfBits); break;
                    case 6: offset = bits.Read(parentBits); lastParent = offset; break;
                    case 10: lastSelf++; goto case 9;
                    case 9: rawMap[p] = 5; offset = lastSelf; break;
                    case 11: rawMap[p] = 6; lastParent = offset = h * (long)HunkBytes / UnitBytes; break;
                    case 13: lastParent += HunkBytes / UnitBytes; goto case 12;
                    case 12: rawMap[p] = 6; offset = lastParent; break;
                    default: throw new FormatException2("CHD map: bad entry type " + rawMap[p]);
                }
                rawMap[p + 1] = (byte)(length >> 16); rawMap[p + 2] = (byte)(length >> 8); rawMap[p + 3] = (byte)length;
                for (int i = 0; i < 6; i++) rawMap[p + 4 + i] = (byte)(offset >> (40 - 8 * i));
                rawMap[p + 10] = (byte)(crc >> 8); rawMap[p + 11] = (byte)crc;
            }
            if (Crc16(rawMap) != mapCrc) throw new FormatException2("CHD map CRC mismatch");
        }

        static int Crc16(byte[] d)
        {
            int crc = 0xFFFF;
            foreach (byte b in d)
            {
                crc ^= b << 8;
                for (int i = 0; i < 8; i++) crc = (crc & 0x8000) != 0 ? ((crc << 1) ^ 0x1021) & 0xFFFF : (crc << 1) & 0xFFFF;
            }
            return crc;
        }

        // ------------------------------------------------------------------ hunks

        readonly Dictionary<long, byte[]> cache = new Dictionary<long, byte[]>();
        readonly LinkedList<long> lru = new LinkedList<long>();
        const int CacheHunks = 96;
        readonly object sync = new object();

        public byte[] ReadHunk(long n) { return ReadHunk(n, 0); }

        byte[] ReadHunk(long n, int depth)
        {
            lock (sync)
            {
                byte[] got;
                if (cache.TryGetValue(n, out got)) return got;
            }
            var data = new byte[HunkBytes];
            if (n >= 0 && n < HunkCount && depth < 64)
            {
                try { DecodeHunk(n, data, depth); }
                catch (Exception ex) when (!(ex is System.Threading.ThreadAbortException))
                {
                    lock (sync) FailedHunks++;
                    Array.Clear(data, 0, data.Length);
                }
            }
            lock (sync)
            {
                if (!cache.ContainsKey(n))
                {
                    cache[n] = data; lru.AddLast(n);
                    if (lru.Count > CacheHunks) { cache.Remove(lru.First.Value); lru.RemoveFirst(); }
                }
            }
            return data;
        }

        void DecodeHunk(long n, byte[] dest, int depth)
        {
            if (Version == 5)
            {
                if (Codecs[0] == 0)
                {
                    long blk = Bin.U32BE(rawMap, (int)(n * 4));
                    if (blk != 0) src.ReadFull(blk * HunkBytes, dest, 0, HunkBytes);
                    else if (Parent != null) Parent.ReadBytes(n * (long)HunkBytes, dest, 0, HunkBytes);
                    return;
                }
                long p = n * 12;
                int type = rawMap[p];
                int length = (rawMap[p + 1] << 16) | (rawMap[p + 2] << 8) | rawMap[p + 3];
                long offset = 0; for (int i = 0; i < 6; i++) offset = (offset << 8) | rawMap[p + 4 + i];
                switch (type)
                {
                    case 0: case 1: case 2: case 3:
                    {
                        var comp = src.ReadBytes(offset, length);
                        if (comp.Length < length) throw new FormatException2("CHD hunk data truncated");
                        Decompress(Codecs[type], comp, dest);
                        break;
                    }
                    case 4: src.ReadFull(offset, dest, 0, HunkBytes); break;
                    case 5: Buffer.BlockCopy(ReadHunk(offset, depth + 1), 0, dest, 0, HunkBytes); break;
                    case 6:
                        if (Parent == null) throw new FormatException2("CHD needs its parent");
                        Parent.ReadBytes(offset * Parent.UnitBytes, dest, 0, HunkBytes);
                        break;
                }
            }
            else
            {
                int p = (int)(n * 16);
                long offset = (long)Bin.U64BE(rawMap, p);
                int length = Bin.U16BE(rawMap, p + 12) | (rawMap[p + 14] << 16);
                int flags = rawMap[p + 15] & 0x0F;
                switch (flags)
                {
                    case 1:
                        if (v34Compression == 3) throw new UnsupportedException("LaserDisc A/V hunk");
                        InflateRaw(src.ReadBytes(offset, length), 0, length, dest, 0, HunkBytes);
                        break;
                    case 2: src.ReadFull(offset, dest, 0, HunkBytes); break;
                    case 3:
                        for (int i = 0; i < 8 && i < HunkBytes; i++) dest[i] = (byte)(offset >> (56 - 8 * i));
                        for (int i = 8; i < HunkBytes; i++) dest[i] = dest[i - 8];
                        break;
                    case 4: Buffer.BlockCopy(ReadHunk(offset, depth + 1), 0, dest, 0, HunkBytes); break;
                    case 5:
                        if (Parent == null) throw new FormatException2("CHD needs its parent");
                        Buffer.BlockCopy(Parent.ReadHunk(offset), 0, dest, 0, HunkBytes);
                        break;
                    case 6: throw new UnsupportedException("secondary-compressed hunk");
                }
            }
        }

        /// <summary>Reads logical bytes (across hunks).</summary>
        public int ReadBytes(long pos, byte[] buf, int off, int count)
        {
            int done = 0;
            while (done < count && pos < LogicalBytes)
            {
                long hunk = pos / HunkBytes; int ho = (int)(pos % HunkBytes);
                int n = (int)Math.Min(Math.Min(count - done, HunkBytes - ho), LogicalBytes - pos);
                Buffer.BlockCopy(ReadHunk(hunk), ho, buf, off + done, n);
                done += n; pos += n;
            }
            return done;
        }

        void Decompress(uint codec, byte[] comp, byte[] dest)
        {
            switch (codec)
            {
                case CodecZlib: InflateRaw(comp, 0, comp.Length, dest, 0, dest.Length); break;
                case CodecLzma: Lzma(comp, 0, comp.Length, dest, 0, dest.Length, HunkBytes); break;
                case CodecHuff: HuffHunk(comp, dest); break;
                case CodecFlac: FlacHunk(comp, dest); break;
                case CodecCdzl: case CodecCdlz: case CodecCdfl: CdHunk(codec, comp, dest); break;
                default:
                    lock (sync) UnsupportedCodecs.Add(Tag(codec));
                    throw new UnsupportedException("CHD codec " + Tag(codec));
            }
        }

        static void InflateRaw(byte[] comp, int off, int len, byte[] dest, int doff, int dlen)
        {
            using (var ms = new MemoryStream(comp, off, len))
            using (var ds = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Decompress))
            {
                int got = 0;
                while (got < dlen) { int r = ds.Read(dest, doff + got, dlen - got); if (r <= 0) break; got += r; }
            }
        }

        static void Lzma(byte[] comp, int off, int len, byte[] dest, int doff, int dlen, int hunkBytes)
        {
            uint dict = 4096; while (dict < (uint)hunkBytes && dict < (1u << 30)) dict <<= 1;
            var props = new byte[] { 3 + 0 * 9 + 2 * 45, (byte)dict, (byte)(dict >> 8), (byte)(dict >> 16), (byte)(dict >> 24) };
            using (var ms = new MemoryStream(comp, off, len))
            using (var ls = new SharpCompress.Compressors.LZMA.LzmaStream(props, ms, len, dlen))
            {
                int got = 0;
                while (got < dlen) { int r = ls.Read(dest, doff + got, dlen - got); if (r <= 0) break; got += r; }
            }
        }

        static void HuffHunk(byte[] comp, byte[] dest)
        {
            var bits = new MsbBits(comp);
            var dec = new MameHuffman(256, 16);
            dec.ImportTreeHuffman(bits);
            for (int i = 0; i < dest.Length; i++) dest[i] = (byte)dec.Decode(bits);
        }

        void FlacHunk(byte[] comp, byte[] dest)
        {
            // first byte: 'L' (little-endian samples) or 'B' (big-endian)
            if (comp.Length < 1 || (comp[0] != 'L' && comp[0] != 'B')) throw new FormatException2("CHD FLAC hunk: bad header");
            int consumed;
            FlacFrames.DecodeStereo16(comp, 1, comp.Length - 1, dest, 0, dest.Length, comp[0] == 'B', FlacBlockSize(dest.Length), out consumed);
        }

        static int FlacBlockSize(int bytes)
        {
            int blocksize = bytes / 4;
            while (blocksize > 2048) blocksize /= 2;
            return blocksize;
        }

        void CdHunk(uint codec, byte[] src2, byte[] dest)
        {
            int frames = HunkBytes / CdFrameSize;
            var sectors = new byte[frames * CdSectorData];
            if (codec == CodecCdfl)
            {
                int consumed;
                FlacFrames.DecodeStereo16(src2, 0, src2.Length, sectors, 0, sectors.Length, true, FlacBlockSize(sectors.Length), out consumed);
            }
            else
            {
                int complenBytes = HunkBytes < 65536 ? 2 : 3;
                int eccBytes = (frames + 7) / 8;
                int headerBytes = eccBytes + complenBytes;
                if (src2.Length < headerBytes) throw new FormatException2("CHD CD hunk too short");
                int complenBase = (src2[eccBytes] << 8) | src2[eccBytes + 1];
                if (complenBytes > 2) complenBase = (complenBase << 8) | src2[eccBytes + 2];
                if (headerBytes + complenBase > src2.Length) throw new FormatException2("CHD CD hunk: bad length");
                if (codec == CodecCdzl) InflateRaw(src2, headerBytes, complenBase, sectors, 0, sectors.Length);
                else Lzma(src2, headerBytes, complenBase, sectors, 0, sectors.Length, frames * CdSectorData);
                // the stripped sync/ECC of raw sectors only matter for raw dumps; user data is complete
            }
            Array.Clear(dest, 0, dest.Length);
            for (int f = 0; f < frames; f++) Buffer.BlockCopy(sectors, f * CdSectorData, dest, f * CdFrameSize, CdSectorData);
        }

        // ------------------------------------------------------------------ metadata

        public sealed class Meta { public string Tag; public byte[] Data; }

        public List<Meta> Metadata()
        {
            var res = new List<Meta>();
            long off = MetaOffset; var seen = new HashSet<long>();
            while (off > 0 && off < src.Length && seen.Add(off) && res.Count < 10000)
            {
                var h = src.ReadBytes(off, 16);
                if (h.Length < 16) break;
                uint tag = Bin.U32BE(h, 0); int len = (int)(Bin.U32BE(h, 4) & 0xFFFFFF); long next = (long)Bin.U64BE(h, 8);
                res.Add(new Meta { Tag = Tag(tag), Data = src.ReadBytes(off + 16, Math.Min(len, 1 << 20)) });
                off = next;
            }
            return res;
        }

        // ------------------------------------------------------------------ CD layout

        public sealed class Track
        {
            public int Number, Frames, Pregap, ExtraFrames, DataSize, UserOffset; public string Type; public bool PregapStored;
            public long ChdFrameStart;
            public bool IsData { get { return Type != "AUDIO"; } }
        }

        public List<Track> CdTracks()
        {
            var tracks = new List<Track>();
            foreach (var m in Metadata())
            {
                if (m.Tag != "CHT2" && m.Tag != "CHTR" && m.Tag != "CHGD" && m.Tag != "CHGT") continue;
                string text = Encoding.ASCII.GetString(m.Data).TrimEnd('\0');
                var kv = new Dictionary<string, string>();
                foreach (var part in text.Split(' '))
                {
                    int c = part.IndexOf(':');
                    if (c > 0) kv[part.Substring(0, c)] = part.Substring(c + 1);
                }
                var t = new Track();
                int v;
                if (kv.ContainsKey("TRACK") && int.TryParse(kv["TRACK"], out v)) t.Number = v;
                t.Type = kv.ContainsKey("TYPE") ? kv["TYPE"] : "MODE1";
                if (kv.ContainsKey("FRAMES") && int.TryParse(kv["FRAMES"], out v)) t.Frames = v;
                if (kv.ContainsKey("PREGAP") && int.TryParse(kv["PREGAP"], out v)) t.Pregap = v;
                t.PregapStored = kv.ContainsKey("PGTYPE") && kv["PGTYPE"].StartsWith("V");
                if (m.Tag == "CHGD" || m.Tag == "CHGT") { if (kv.ContainsKey("PAD") && int.TryParse(kv["PAD"], out v)) t.ExtraFrames = v; }
                else t.ExtraFrames = ((t.Frames + 3) / 4) * 4 - t.Frames;
                switch (t.Type)
                {
                    case "MODE1": case "MODE1/2048": case "MODE2_FORM1": case "MODE2/2048": t.DataSize = 2048; t.UserOffset = 0; break;
                    case "MODE1_RAW": case "MODE1/2352": t.DataSize = 2352; t.UserOffset = 16; break;
                    case "MODE2": case "MODE2/2336": case "MODE2_FORM_MIX": t.DataSize = 2336; t.UserOffset = 8; break;
                    case "MODE2_FORM2": case "MODE2/2324": t.DataSize = 2324; t.UserOffset = 0; break;
                    case "MODE2_RAW": case "MODE2/2352": case "CDI/2352": t.DataSize = 2352; t.UserOffset = 24; break;
                    default: t.DataSize = 2352; t.UserOffset = 0; break;
                }
                tracks.Add(t);
            }
            tracks.Sort((a, b) => a.Number.CompareTo(b.Number));
            long ofs = 0;
            foreach (var t in tracks) { t.ChdFrameStart = ofs; ofs += t.Frames + t.ExtraFrames; }
            return tracks;
        }

        public bool IsCd { get { return Metadata().Any(m => m.Tag == "CHT2" || m.Tag == "CHTR" || m.Tag == "CHGD" || m.Tag == "CHGT" || m.Tag == "CHCD"); } }
        public bool IsHardDisk { get { return Metadata().Any(m => m.Tag == "GDDD"); } }
    }

    /// <summary>The logical bytes of a CHD as a data source.</summary>
    public sealed class ChdSource : DataSource
    {
        readonly ChdFile chd;
        public ChdSource(ChdFile c) { chd = c; }
        public override long Length { get { return chd.LogicalBytes; } }
        public override int Read(long pos, byte[] buf, int off, int count) { return pos >= chd.LogicalBytes ? 0 : chd.ReadBytes(pos, buf, off, count); }
    }

    /// <summary>One CD track's user data (2048 bytes per sector) taken from the CHD frames.</summary>
    public sealed class ChdTrackSource : DataSource
    {
        readonly ChdFile chd; readonly ChdFile.Track t; readonly long firstFrame, sectors;
        public ChdTrackSource(ChdFile c, ChdFile.Track track)
        {
            chd = c; t = track;
            int skip = t.PregapStored ? t.Pregap : 0;
            firstFrame = t.ChdFrameStart + skip;
            sectors = Math.Max(0, t.Frames - skip);
        }
        int SectorBytes { get { return t.DataSize == 2324 ? 2324 : 2048; } }
        public override long Length { get { return sectors * SectorBytes; } }
        public override int Read(long pos, byte[] buf, int off, int count)
        {
            int done = 0; int sb = SectorBytes;
            while (done < count && pos < Length)
            {
                long sec = pos / sb; int so = (int)(pos % sb);
                int n = (int)Math.Min(count - done, sb - so);
                long frameOffset = (firstFrame + sec) * ChdFile.CdFrameSize + t.UserOffset + so;
                int got = chd.ReadBytes(frameOffset, buf, off + done, n);
                if (got <= 0) break;
                done += got; pos += got;
            }
            return done;
        }
    }

    /// <summary>MSB-first bit reader used by MAME's Huffman code.</summary>
    public sealed class MsbBits
    {
        readonly byte[] d; int pos; uint buffer; int bits;
        public MsbBits(byte[] data) { d = data; }
        public uint Peek(int n)
        {
            if (n == 0) return 0;
            if (n > bits)
            {
                while (bits <= 24) { if (pos < d.Length) buffer |= (uint)d[pos] << (24 - bits); pos++; bits += 8; }
            }
            return buffer >> (32 - n);
        }
        public void Remove(int n) { buffer <<= n; bits -= n; }
        public long Read(int n)
        {
            if (n <= 24) { uint r = Peek(n); Remove(n); return r; }
            long hi = Read(n - 16); long lo = Read(16);
            return (hi << 16) | lo;
        }
        public bool Overflow { get { return pos - bits / 8 > d.Length; } }
        public int ByteOffset { get { return pos - bits / 8; } }
    }

    /// <summary>MAME's canonical Huffman decoder (lib/util/huffman.cpp).</summary>
    public sealed class MameHuffman
    {
        readonly int numCodes, maxBits;
        readonly int[] numBits; readonly uint[] codes; readonly int[] lookup;
        public MameHuffman(int numcodes, int maxbits)
        {
            numCodes = numcodes; maxBits = maxbits;
            numBits = new int[numcodes]; codes = new uint[numcodes]; lookup = new int[1 << maxbits];
        }

        public void ImportTreeRle(MsbBits b)
        {
            int nb = maxBits >= 16 ? 5 : maxBits >= 8 ? 4 : 3;
            int cur = 0;
            while (cur < numCodes)
            {
                int nodebits = (int)b.Read(nb);
                if (nodebits != 1) numBits[cur++] = nodebits;
                else
                {
                    nodebits = (int)b.Read(nb);
                    if (nodebits == 1) numBits[cur++] = nodebits;
                    else
                    {
                        int rep = (int)b.Read(nb) + 3;
                        if (rep + cur > numCodes) throw new FormatException2("Huffman: bad RLE tree");
                        while (rep-- > 0) numBits[cur++] = nodebits;
                    }
                }
            }
            Build();
        }

        public void ImportTreeHuffman(MsbBits b)
        {
            var small = new MameHuffman(24, 6);
            small.numBits[0] = (int)b.Read(3);
            int start = (int)b.Read(3) + 1, count = 0;
            for (int i = 1; i < 24; i++)
            {
                if (i < start || count == 7) small.numBits[i] = 0;
                else { count = (int)b.Read(3); small.numBits[i] = count == 7 ? 0 : count; }
            }
            small.Build();
            int rlefullbits = 0; uint temp = (uint)(numCodes - 9);
            while (temp != 0) { temp >>= 1; rlefullbits++; }
            int last = 0, cur = 0;
            while (cur < numCodes)
            {
                int value = small.Decode(b);
                if (value != 0) numBits[cur++] = last = value - 1;
                else
                {
                    int c = (int)b.Read(3) + 2;
                    if (c == 7 + 2) c += (int)b.Read(rlefullbits);
                    for (; c != 0 && cur < numCodes; c--) numBits[cur++] = last;
                }
            }
            Build();
        }

        void Build()
        {
            var histo = new uint[33];
            for (int i = 0; i < numCodes; i++) { if (numBits[i] > maxBits) throw new FormatException2("Huffman: code too long"); histo[numBits[i]]++; }
            uint curstart = 0;
            for (int len = 32; len > 0; len--)
            {
                uint next = (curstart + histo[len]) >> 1;
                if (len != 1 && next * 2 != curstart + histo[len]) throw new FormatException2("Huffman: bad code lengths");
                histo[len] = curstart; curstart = next;
            }
            for (int i = 0; i < numCodes; i++) if (numBits[i] > 0) codes[i] = histo[numBits[i]]++;
            for (int i = 0; i < numCodes; i++)
            {
                if (numBits[i] <= 0) continue;
                int shift = maxBits - numBits[i];
                int value = (i << 5) | numBits[i];
                long from = (long)codes[i] << shift, to = (((long)codes[i] + 1) << shift) - 1;
                if (to >= lookup.Length) throw new FormatException2("Huffman: bad table");
                for (long k = from; k <= to; k++) lookup[k] = value;
            }
        }

        public int Decode(MsbBits b)
        {
            uint bits = b.Peek(maxBits);
            int l = lookup[bits];
            b.Remove(l & 0x1f);
            return l >> 5;
        }
    }

    /// <summary>CHD container: hard disks become a disk image entry, CD-ROMs one ISO view per data track.</summary>
    public sealed class ChdContainer : Container
    {
        readonly ChdFile chd; readonly string baseName;
        public override string FormatName { get { return "MAME CHD"; } }

        public ChdContainer(DataSource s, string name, ISiblingProvider sib)
        {
            chd = new ChdFile(s);
            baseName = Path.GetFileNameWithoutExtension(PathUtil.FileName(name ?? "disk"));
            if (chd.NeedsParent)
            {
                var parent = ChdParents.Find(chd.ParentSha1, sib);
                if (parent != null) { chd.Parent = parent; Description = "parent found"; }
                else Warnings.Add("this CHD is a clone that stores only differences from its parent CHD, which was not found nearby; parts of the disk read as empty");
            }
            if (chd.UnsupportedCodecs.Count > 0) Warnings.Add("this CHD uses compression Symbol Hunter cannot read (" + string.Join(", ", chd.UnsupportedCodecs) + "); hunks stored that way read as empty");
            Description = "CHD v" + chd.Version + ", " + Fmt.Size(chd.LogicalBytes) + ", " + chd.CodecNames + (chd.NeedsParent ? (chd.Parent != null ? ", with parent" : ", parent missing") : "");
        }

        public override IEnumerable<Entry> Entries()
        {
            if (chd.IsCd)
            {
                foreach (var t in chd.CdTracks())
                {
                    if (!t.IsData) continue;
                    var tt = t;
                    var ts = new ChdTrackSource(chd, tt);
                    yield return new Entry { Name = baseName + string.Format(".track{0:00}.iso", t.Number), Size = ts.Length, Method = "CD " + t.Type, Open = () => Finish(new ChdTrackSource(chd, tt)) };
                }
            }
            else
            {
                string ext = chd.IsHardDisk ? ".img" : ".bin";
                yield return new Entry { Name = baseName + ext, Size = chd.LogicalBytes, Method = chd.CodecNames, Open = () => Finish(new ChdSource(chd)) };
            }
        }

        DataSource Finish(DataSource d) { return d; }

        public int FailedHunks { get { return chd.FailedHunks; } }
    }

    /// <summary>Finds a clone CHD's parent by SHA-1 in the same and neighbouring folders.</summary>
    public static class ChdParents
    {
        static readonly Dictionary<string, string> shaToPath = new Dictionary<string, string>();
        static readonly HashSet<string> scannedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public static ChdFile Find(byte[] sha1, ISiblingProvider sib)
        {
            string want = BitConverter.ToString(sha1).Replace("-", "");
            var dirSib = sib as IFolderSiblings;
            if (dirSib == null) return null;
            string dir = dirSib.FolderPath;
            if (dir == null) return null;
            var dirs = new List<string> { dir };
            try
            {
                var up = Path.GetDirectoryName(dir);
                if (up != null) { dirs.Add(up); dirs.AddRange(Directory.GetDirectories(up)); var up2 = Path.GetDirectoryName(up); if (up2 != null) dirs.AddRange(Directory.GetDirectories(up2).Take(4000)); }
            }
            catch { }
            lock (shaToPath)
            {
                foreach (var d in dirs)
                {
                    string p;
                    if (shaToPath.TryGetValue(want, out p)) break;
                    if (!scannedDirs.Add(d)) continue;
                    try
                    {
                        foreach (var f in Directory.EnumerateFiles(d, "*.chd"))
                        {
                            try
                            {
                                using (var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                                {
                                    var h = new byte[124]; int n = fs.Read(h, 0, h.Length);
                                    if (n < 48 || !Bin.Match(h, 0, ChdFile.Magic)) continue;
                                    int ver = (int)Bin.U32BE(h, 12);
                                    int so = ver == 5 ? 84 : ver == 4 ? 48 : ver == 3 ? 80 : -1;
                                    if (so < 0 || n < so + 20) continue;
                                    var s = new byte[20]; Array.Copy(h, so, s, 0, 20);
                                    string key = BitConverter.ToString(s).Replace("-", "");
                                    if (!shaToPath.ContainsKey(key)) shaToPath[key] = f;
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
                string path;
                if (!shaToPath.TryGetValue(want, out path)) return null;
                try
                {
                    var src = new FileSource(path);
                    var parent = new ChdFile(src);
                    if (parent.NeedsParent) { var gp = Find(parent.ParentSha1, new FolderOnly(Path.GetDirectoryName(path))); if (gp != null) parent.Parent = gp; }
                    return parent;
                }
                catch { return null; }
            }
        }

        sealed class FolderOnly : ISiblingProvider, IFolderSiblings
        {
            public FolderOnly(string d) { FolderPath = d; }
            public string FolderPath { get; private set; }
            public DataSource GetSibling(string name) { return null; }
            public IEnumerable<string> SiblingNames { get { return new string[0]; } }
        }
    }

    /// <summary>Sibling providers backed by a real folder expose its path (used to find CHD parents).</summary>
    public interface IFolderSiblings { string FolderPath { get; } }
}
