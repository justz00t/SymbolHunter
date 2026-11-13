using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace SymbolHunter.Core
{
    /// <summary>Thrown when compressed data or a container structure is invalid.</summary>
    public class FormatException2 : Exception
    {
        public FormatException2(string msg) : base(msg) { }
        public FormatException2(string msg, Exception inner) : base(msg, inner) { }
    }

    /// <summary>Thrown when a container uses a feature this program cannot decode.</summary>
    public class UnsupportedException : Exception
    {
        public UnsupportedException(string msg) : base(msg) { }
    }

    /// <summary>Random-access, read-only bytes (a file, a memory buffer, or a window into another source).</summary>
    public abstract class DataSource : IDisposable
    {
        public abstract long Length { get; }

        /// <summary>Reads up to count bytes at pos. Returns the number read (less than count only at end of data).</summary>
        public abstract int Read(long pos, byte[] buf, int off, int count);

        public virtual void Dispose() { }

        public byte[] ReadBytes(long pos, int count)
        {
            if (pos < 0 || pos >= Length || count <= 0) return new byte[0];
            long avail = Length - pos;
            if (count > avail) count = (int)avail;
            var b = new byte[count];
            int got = 0;
            while (got < count)
            {
                int n = Read(pos + got, b, got, count - got);
                if (n <= 0) break;
                got += n;
            }
            if (got < count) Array.Resize(ref b, got);
            return b;
        }

        /// <summary>Reads exactly count bytes or zero-fills the remainder.</summary>
        public void ReadFull(long pos, byte[] buf, int off, int count)
        {
            int got = 0;
            while (got < count)
            {
                int n = pos + got < Length ? Read(pos + got, buf, off + got, count - got) : 0;
                if (n <= 0) break;
                got += n;
            }
            if (got < count) Array.Clear(buf, off + got, count - got);
        }

        public byte[] ReadAll()
        {
            if (Length > int.MaxValue - 64) throw new UnsupportedException("data too large to load into memory");
            return ReadBytes(0, (int)Length);
        }

        public int U8(long pos)
        {
            var b = new byte[1];
            return Read(pos, b, 0, 1) == 1 ? b[0] : -1;
        }

        public int U16(long pos) { var b = ReadBytes(pos, 2); return b.Length < 2 ? -1 : b[0] | (b[1] << 8); }
        public long U32(long pos) { var b = ReadBytes(pos, 4); return b.Length < 4 ? -1 : (uint)(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)); }

        public DataSource Slice(long off, long len)
        {
            if (off < 0) off = 0;
            if (off > Length) off = Length;
            if (len < 0 || off + len > Length) len = Length - off;
            return new SubSource(this, off, len);
        }

        public Stream OpenStream() { return new DataSourceStream(this); }
    }

    public sealed class MemorySource : DataSource
    {
        readonly byte[] data; readonly int start; readonly int len;
        public MemorySource(byte[] data) : this(data, 0, data.Length) { }
        public MemorySource(byte[] data, int start, int len) { this.data = data; this.start = start; this.len = len; }
        public override long Length { get { return len; } }
        public byte[] Buffer { get { return data; } }
        public int Offset { get { return start; } }
        public override int Read(long pos, byte[] buf, int off, int count)
        {
            if (pos < 0 || pos >= len) return 0;
            int n = (int)Math.Min(count, len - pos);
            System.Buffer.BlockCopy(data, start + (int)pos, buf, off, n);
            return n;
        }
    }

    public class FileSource : DataSource
    {
        readonly FileStream fs; readonly long length; readonly object gate = new object();
        public readonly string Path;
        public FileSource(string path)
        {
            Path = path;
            fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.RandomAccess);
            length = fs.Length;
        }
        public override long Length { get { return length; } }
        public override int Read(long pos, byte[] buf, int off, int count)
        {
            if (pos < 0 || pos >= length) return 0;
            if (count > length - pos) count = (int)(length - pos);
            lock (gate)
            {
                fs.Position = pos;
                int got = 0;
                while (got < count)
                {
                    int n = fs.Read(buf, off + got, count - got);
                    if (n <= 0) break;
                    got += n;
                }
                return got;
            }
        }
        public override void Dispose() { fs.Dispose(); }
    }

    /// <summary>A temporary file that is deleted when disposed.</summary>
    public sealed class TempFileSource : FileSource
    {
        public TempFileSource(string path) : base(path) { }
        public override void Dispose()
        {
            base.Dispose();
            try { File.Delete(Path); } catch { }
        }
    }

    public sealed class SubSource : DataSource
    {
        readonly DataSource parent; readonly long off; readonly long len;
        public SubSource(DataSource parent, long off, long len) { this.parent = parent; this.off = off; this.len = len; }
        public override long Length { get { return len; } }
        public override int Read(long pos, byte[] buf, int o, int count)
        {
            if (pos < 0 || pos >= len) return 0;
            if (count > len - pos) count = (int)(len - pos);
            return parent.Read(off + pos, buf, o, count);
        }
    }

    /// <summary>Several sources glued end to end (multi-volume archives, sector maps).</summary>
    public sealed class ConcatSource : DataSource
    {
        readonly List<DataSource> parts = new List<DataSource>(); readonly List<long> starts = new List<long>(); long total; readonly bool owns;
        public ConcatSource(IEnumerable<DataSource> sources, bool ownsParts)
        {
            owns = ownsParts;
            foreach (var s in sources) { starts.Add(total); parts.Add(s); total += s.Length; }
        }
        public override long Length { get { return total; } }
        public override int Read(long pos, byte[] buf, int off, int count)
        {
            if (pos < 0 || pos >= total) return 0;
            int idx = starts.BinarySearch(pos);
            if (idx < 0) idx = ~idx - 1;
            int done = 0;
            while (count > 0 && idx < parts.Count)
            {
                long rel = pos - starts[idx];
                int n = parts[idx].Read(rel, buf, off, (int)Math.Min(count, parts[idx].Length - rel));
                if (n <= 0) { idx++; if (idx < parts.Count && pos < starts[idx]) break; continue; }
                done += n; pos += n; off += n; count -= n;
                if (pos >= starts[idx] + parts[idx].Length) idx++;
            }
            return done;
        }
        public override void Dispose() { if (owns) foreach (var p in parts) p.Dispose(); }
    }

    /// <summary>Read-only seekable Stream view over a DataSource.</summary>
    public sealed class DataSourceStream : Stream
    {
        readonly DataSource src; long pos;
        public DataSourceStream(DataSource s) { src = s; }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return true; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return src.Length; } }
        public override long Position { get { return pos; } set { pos = value; } }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = src.Read(pos, buffer, offset, count);
            if (n > 0) pos += n;
            return n;
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            if (origin == SeekOrigin.Begin) pos = offset; else if (origin == SeekOrigin.Current) pos += offset; else pos = src.Length + offset;
            return pos;
        }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    }

    /// <summary>Global knobs for memory use and temp files.</summary>
    public static class Limits
    {
        public static long MemoryThreshold = 192L * 1024 * 1024;   // larger outputs spill to temp files
        public static string TempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "SymbolHunter");
        static int tempCounter;
        /// <summary>Deletes leftover temporary files from this and earlier runs. Returns the number removed.</summary>
        public static int Cleanup()
        {
            int n = 0;
            try
            {
                if (!Directory.Exists(TempDir)) return 0;
                foreach (var f in Directory.GetFiles(TempDir, "sh*.tmp"))
                {
                    try { if (File.GetLastWriteTimeUtc(f) < DateTime.UtcNow.AddMinutes(-1) || f.Contains("sh" + System.Diagnostics.Process.GetCurrentProcess().Id + "_")) { File.Delete(f); n++; } } catch { }
                }
            }
            catch { }
            return n;
        }
        public static string NewTempFile()
        {
            Directory.CreateDirectory(TempDir);
            return System.IO.Path.Combine(TempDir, "sh" + System.Diagnostics.Process.GetCurrentProcess().Id + "_" + Interlocked.Increment(ref tempCounter) + ".tmp");
        }
    }

    /// <summary>Growable output buffer for decompressors; spills to a temp file when large.</summary>
    public sealed class Sink : IDisposable
    {
        byte[] mem; int memLen; FileStream file; string filePath; long length; readonly long limit;
        public long Length { get { return length; } }
        public long Limit { get { return limit; } }

        /// <param name="expected">expected output size, -1 if unknown</param>
        /// <param name="limit">hard limit of bytes accepted, -1 for none</param>
        public Sink(long expected, long limit = -1)
        {
            this.limit = limit;
            if (expected >= 0 && expected > Limits.MemoryThreshold) OpenFile();
            else mem = new byte[expected > 0 ? (int)Math.Min(expected, Limits.MemoryThreshold) : 4096];
        }

        void OpenFile()
        {
            filePath = Limits.NewTempFile();
            file = new FileStream(filePath, FileMode.Create, FileAccess.ReadWrite, FileShare.Read, 1 << 16);
            if (mem != null && memLen > 0) file.Write(mem, 0, memLen);
            mem = null; memLen = 0;
        }

        public bool Full { get { return limit >= 0 && length >= limit; } }

        public void Write(byte[] b, int off, int n)
        {
            if (n <= 0) return;
            if (limit >= 0 && length + n > limit) n = (int)Math.Max(0, limit - length);
            if (n == 0) return;
            if (file == null)
            {
                if ((long)memLen + n > Limits.MemoryThreshold) OpenFile();
                else
                {
                    if (memLen + n > mem.Length)
                    {
                        long ns = Math.Max((long)mem.Length * 2, (long)memLen + n);
                        if (ns > int.MaxValue - 64) ns = int.MaxValue - 64;
                        Array.Resize(ref mem, (int)ns);
                    }
                    Buffer.BlockCopy(b, off, mem, memLen, n);
                    memLen += n; length += n;
                    return;
                }
            }
            file.Write(b, off, n);
            length += n;
        }

        readonly byte[] one = new byte[1];
        public void WriteByte(byte v) { one[0] = v; Write(one, 0, 1); }

        /// <summary>Converts the collected bytes into a DataSource. The sink must not be used afterwards.</summary>
        public DataSource ToSource()
        {
            if (file != null)
            {
                file.Flush();
                file.Dispose();
                file = null;
                var s = new TempFileSource(filePath);
                filePath = null;
                return s;
            }
            var m = mem; mem = null;
            return new MemorySource(m ?? new byte[0], 0, memLen);
        }

        public byte[] ToArray()
        {
            if (file != null) { file.Flush(); file.Position = 0; var b = new byte[file.Length]; file.Read(b, 0, b.Length); return b; }
            var r = new byte[memLen]; Buffer.BlockCopy(mem, 0, r, 0, memLen); return r;
        }

        public void Dispose()
        {
            if (file != null) { file.Dispose(); file = null; }
            if (filePath != null) { try { File.Delete(filePath); } catch { } filePath = null; }
            mem = null;
        }
    }

    /// <summary>Sequential byte reader over a DataSource range with buffering.</summary>
    public sealed class ByteInput
    {
        readonly DataSource src; long pos; readonly long end; readonly byte[] buf = new byte[1 << 16]; int bpos, blen;
        public long Overrun;   // bytes requested past the end
        public ByteInput(DataSource s, long start, long length)
        {
            src = s; pos = start;
            end = length < 0 ? s.Length : Math.Min(s.Length, start + length);
        }
        public ByteInput(byte[] data) : this(new MemorySource(data), 0, data.Length) { }
        public long Position { get { return pos - (blen - bpos); } }
        public long Remaining { get { return end - Position; } }
        public bool AtEnd { get { return bpos >= blen && pos >= end; } }

        bool Fill()
        {
            if (pos >= end) return false;
            int want = (int)Math.Min(buf.Length, end - pos);
            int n = src.Read(pos, buf, 0, want);
            if (n <= 0) return false;
            pos += n; bpos = 0; blen = n;
            return true;
        }

        /// <summary>Returns the next byte or -1 at end.</summary>
        public int ReadByte()
        {
            if (bpos >= blen && !Fill()) { Overrun++; return -1; }
            return buf[bpos++];
        }

        public int Read(byte[] b, int off, int count)
        {
            int done = 0;
            while (done < count)
            {
                if (bpos >= blen && !Fill()) break;
                int n = Math.Min(count - done, blen - bpos);
                Buffer.BlockCopy(buf, bpos, b, off + done, n);
                bpos += n; done += n;
            }
            return done;
        }

        public void Skip(long n)
        {
            while (n > 0)
            {
                if (bpos >= blen) { long left = end - pos; long jump = Math.Min(n, left); pos += jump; n -= jump; return; }
                int k = (int)Math.Min(n, blen - bpos); bpos += k; n -= k;
            }
        }
    }

    /// <summary>MSB-first bit reader (LHA, ARJ, Teledisk LZHUF, LZX-style 16-bit reads are separate).</summary>
    public sealed class BitReaderMsb
    {
        readonly ByteInput inp; ulong buf; int cnt;
        public BitReaderMsb(ByteInput i) { inp = i; }
        public long Overrun { get { return inp.Overrun; } }
        void Need(int n)
        {
            while (cnt < n)
            {
                int b = inp.ReadByte();
                buf = (buf << 8) | (uint)(b < 0 ? 0 : b);
                cnt += 8;
            }
        }
        /// <summary>Reads n bits (0..32).</summary>
        public int Get(int n)
        {
            if (n == 0) return 0;
            Need(n);
            cnt -= n;
            return (int)((buf >> cnt) & ((1UL << n) - 1));
        }
        public int Peek(int n)
        {
            if (n == 0) return 0;
            Need(n);
            return (int)((buf >> (cnt - n)) & ((1UL << n) - 1));
        }
        public void Skip(int n) { Need(n); cnt -= n; }
        public int Bit() { return Get(1); }
    }

    /// <summary>LSB-first bit reader (Deflate, Implode, Shrink, Reduce, DCL, LZW variants).</summary>
    public sealed class BitReaderLsb
    {
        readonly ByteInput inp; ulong buf; int cnt;
        public BitReaderLsb(ByteInput i) { inp = i; }
        public long Overrun { get { return inp.Overrun; } }
        public ByteInput Input { get { return inp; } }
        void Need(int n)
        {
            while (cnt < n)
            {
                int b = inp.ReadByte();
                buf |= (ulong)(uint)(b < 0 ? 0 : b) << cnt;
                cnt += 8;
            }
        }
        public int Get(int n)
        {
            if (n == 0) return 0;
            Need(n);
            int v = (int)(buf & ((1UL << n) - 1));
            buf >>= n; cnt -= n;
            return v;
        }
        public int Peek(int n) { Need(n); return (int)(buf & ((1UL << n) - 1)); }
        public void Skip(int n) { Need(n); buf >>= n; cnt -= n; }
        public int Bit() { return Get(1); }
        /// <summary>Discards bits up to the next byte boundary.</summary>
        public void AlignToByte() { int r = cnt & 7; buf >>= r; cnt -= r; }
        public int BitsInBuffer { get { return cnt; } }
        /// <summary>True when all input bytes were consumed and no buffered bits remain (excluding padding).</summary>
        public bool InputExhausted { get { return inp.AtEnd; } }
    }

    /// <summary>Canonical Huffman decoder built from code lengths (shorter codes numerically smaller).</summary>
    public sealed class Huffman
    {
        readonly short[] count;      // codes per length
        readonly short[] symbol;     // symbols ordered by code
        readonly int maxLen;
        // fast tables
        readonly int tableBits;
        readonly short[] fastSym; readonly byte[] fastLen;   // MSB-indexed
        readonly short[] fastSymL; readonly byte[] fastLenL; // LSB-indexed (bit reversed)
        public readonly int NumSymbols;
        public bool Empty { get { return NumSymbols == 0; } }
        public readonly bool Incomplete;
        public readonly int UsedSymbols;

        public Huffman(int[] lengths, int n, int fastBits = 10) : this(ToBytes(lengths, n), n, fastBits) { }
        static byte[] ToBytes(int[] l, int n) { var b = new byte[n]; for (int i = 0; i < n; i++) b[i] = (byte)l[i]; return b; }

        public Huffman(byte[] lengths, int n, int fastBits = 10)
        {
            NumSymbols = n;
            int ml = 0;
            for (int i = 0; i < n; i++) if (lengths[i] > ml) ml = lengths[i];
            maxLen = ml;
            count = new short[Math.Max(ml, 1) + 1];
            for (int i = 0; i < n; i++) count[lengths[i]]++;
            count[0] = 0;
            int left = 1;
            for (int len = 1; len <= ml; len++)
            {
                left <<= 1; left -= count[len];
                if (left < 0) throw new FormatException2("over-subscribed Huffman code");
            }
            Incomplete = left > 0;
            var offs = new short[ml + 2];
            for (int len = 1; len <= ml; len++) offs[len + 1] = (short)(offs[len] + count[len]);
            symbol = new short[n];
            int used = 0;
            for (int i = 0; i < n; i++) if (lengths[i] != 0) { symbol[offs[lengths[i]]++] = (short)i; used++; }
            UsedSymbols = used;
            tableBits = Math.Min(fastBits, Math.Max(ml, 1));
            int size = 1 << tableBits;
            fastSym = new short[size]; fastLen = new byte[size];
            fastSymL = new short[size]; fastLenL = new byte[size];
            // assign canonical codes
            int code = 0; int k = 0;
            for (int len = 1; len <= ml; len++)
            {
                for (int c = 0; c < count[len]; c++, k++, code++)
                {
                    if (len <= tableBits)
                    {
                        int sym = symbol[k];
                        int fill = 1 << (tableBits - len);
                        int baseIdx = code << (tableBits - len);
                        for (int f = 0; f < fill; f++) { fastSym[baseIdx + f] = (short)sym; fastLen[baseIdx + f] = (byte)len; }
                        int rev = Reverse(code, len);
                        for (int f = 0; f < fill; f++) { int idx = rev | (f << len); fastSymL[idx] = (short)sym; fastLenL[idx] = (byte)len; }
                    }
                }
                code <<= 1;
            }
        }

        static int Reverse(int v, int bits) { int r = 0; for (int i = 0; i < bits; i++) { r = (r << 1) | (v & 1); v >>= 1; } return r; }

        public int MaxLength { get { return maxLen; } }

        /// <summary>Decodes one symbol reading bits MSB-first.</summary>
        public int Decode(BitReaderMsb br)
        {
            if (UsedSymbols == 1 && maxLen <= 1) { br.Skip(maxLen); return symbol[0]; }
            int p = br.Peek(tableBits);
            int l = fastLen[p];
            if (l != 0) { br.Skip(l); return fastSym[p]; }
            int code = 0, first = 0, index = 0;
            for (int len = 1; len <= maxLen; len++)
            {
                code |= br.Bit();
                int c = count[len];
                if (code - c < first) return symbol[index + (code - first)];
                index += c; first += c; first <<= 1; code <<= 1;
            }
            throw new FormatException2("invalid Huffman code");
        }

        /// <summary>Decodes one symbol using a bit callback (codes read MSB-first, one bit at a time).</summary>
        public int DecodeBits(Func<int> bit)
        {
            int code = 0, first = 0, index = 0;
            for (int len = 1; len <= maxLen; len++)
            {
                code |= bit();
                int c = count[len];
                if (code - c < first) return symbol[index + (code - first)];
                index += c; first += c; first <<= 1; code <<= 1;
            }
            throw new FormatException2("invalid Huffman code");
        }

        /// <summary>Decodes one symbol reading bits LSB-first (Deflate order). invert flips every bit (Implode/DCL).</summary>
        public int Decode(BitReaderLsb br, bool invert = false)
        {
            if (!invert)
            {
                int p = br.Peek(tableBits);
                int l = fastLenL[p];
                if (l != 0) { br.Skip(l); return fastSymL[p]; }
            }
            int code = 0, first = 0, index = 0;
            for (int len = 1; len <= maxLen; len++)
            {
                code |= br.Bit() ^ (invert ? 1 : 0);
                int c = count[len];
                if (code - c < first) return symbol[index + (code - first)];
                index += c; first += c; first <<= 1; code <<= 1;
            }
            throw new FormatException2("invalid Huffman code");
        }
    }

    /// <summary>Sliding-window LZ77 output helper writing into a Sink.</summary>
    public sealed class LzWindow
    {
        readonly byte[] win; readonly int mask; int pos; readonly Sink sink; long total; readonly long limit;
        readonly byte[] outBuf = new byte[1 << 15]; int outLen;
        public long Total { get { return total; } }
        /// <summary>Allow back-references before the first output byte (window pre-filled).</summary>
        public bool AllowPreHistory;
        public bool Done { get { return limit >= 0 && total >= limit; } }

        public LzWindow(int bits, Sink s, long limit, byte fill = 0)
        {
            win = new byte[1 << bits]; mask = win.Length - 1; sink = s; this.limit = limit;
            if (fill != 0) for (int i = 0; i < win.Length; i++) win[i] = fill;
        }

        public byte[] Buffer { get { return win; } }
        public int Pos { get { return pos; } set { pos = value & mask; } }

        public void Put(byte b)
        {
            if (limit >= 0 && total >= limit) return;
            win[pos] = b; pos = (pos + 1) & mask; total++;
            outBuf[outLen++] = b;
            if (outLen == outBuf.Length) FlushOut();
        }

        /// <summary>Copies len bytes starting dist bytes back (dist=1 is the previous byte).</summary>
        public void Copy(int dist, int len)
        {
            int src = (pos - dist) & mask;
            for (int i = 0; i < len; i++)
            {
                if (limit >= 0 && total >= limit) return;
                byte b = win[src]; src = (src + 1) & mask;
                win[pos] = b; pos = (pos + 1) & mask; total++;
                outBuf[outLen++] = b;
                if (outLen == outBuf.Length) FlushOut();
            }
        }

        /// <summary>Copies from an absolute window position (ARJ/LHA style).</summary>
        public void CopyFrom(int srcPos, int len)
        {
            int src = srcPos & mask;
            for (int i = 0; i < len; i++)
            {
                if (limit >= 0 && total >= limit) return;
                byte b = win[src]; src = (src + 1) & mask;
                win[pos] = b; pos = (pos + 1) & mask; total++;
                outBuf[outLen++] = b;
                if (outLen == outBuf.Length) FlushOut();
            }
        }

        void FlushOut() { sink.Write(outBuf, 0, outLen); outLen = 0; }
        public void Flush() { if (outLen > 0) FlushOut(); }
    }

    public static class Crc
    {
        static readonly uint[] t32 = MakeReflected(0xEDB88320u);
        static readonly ushort[] t16arc = MakeReflected16(0xA001);

        static uint[] MakeReflected(uint poly)
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++) { uint c = i; for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? (c >> 1) ^ poly : c >> 1; t[i] = c; }
            return t;
        }
        static ushort[] MakeReflected16(int poly)
        {
            var t = new ushort[256];
            for (int i = 0; i < 256; i++) { int c = i; for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? (c >> 1) ^ poly : c >> 1; t[i] = (ushort)c; }
            return t;
        }

        public static uint Crc32(uint crc, byte[] b, int off, int n)
        {
            crc = ~crc;
            for (int i = 0; i < n; i++) crc = t32[(crc ^ b[off + i]) & 0xFF] ^ (crc >> 8);
            return ~crc;
        }

        public static uint Crc32(DataSource s)
        {
            uint crc = 0; var buf = new byte[1 << 16]; long p = 0;
            while (p < s.Length) { int n = s.Read(p, buf, 0, buf.Length); if (n <= 0) break; crc = Crc32(crc, buf, 0, n); p += n; }
            return crc;
        }

        /// <summary>CRC-16/ARC (used by ARC, LZH, ZOO).</summary>
        public static int Crc16Arc(int crc, byte[] b, int off, int n)
        {
            for (int i = 0; i < n; i++) crc = t16arc[(crc ^ b[off + i]) & 0xFF] ^ (crc >> 8);
            return crc & 0xFFFF;
        }

        public static int Crc16Arc(DataSource s)
        {
            int crc = 0; var buf = new byte[1 << 16]; long p = 0;
            while (p < s.Length) { int n = s.Read(p, buf, 0, buf.Length); if (n <= 0) break; crc = Crc16Arc(crc, buf, 0, n); p += n; }
            return crc;
        }

        /// <summary>Teledisk CRC: polynomial 0xA097, MSB-first, initial 0.</summary>
        public static int CrcTd0(byte[] b, int off, int n, int crc = 0)
        {
            for (int i = 0; i < n; i++)
            {
                crc ^= b[off + i] << 8;
                for (int k = 0; k < 8; k++) crc = (crc & 0x8000) != 0 ? ((crc << 1) ^ 0xA097) : crc << 1;
                crc &= 0xFFFF;
            }
            return crc;
        }
    }

    public static class Bin
    {
        public static int U16(byte[] b, int o) { return o + 2 <= b.Length && o >= 0 ? b[o] | (b[o + 1] << 8) : 0; }
        public static int U16BE(byte[] b, int o) { return o + 2 <= b.Length && o >= 0 ? (b[o] << 8) | b[o + 1] : 0; }
        public static uint U32(byte[] b, int o) { return o + 4 <= b.Length && o >= 0 ? (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) : 0; }
        public static uint U32BE(byte[] b, int o) { return o + 4 <= b.Length && o >= 0 ? (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) : 0; }
        public static ulong U64BE(byte[] b, int o) { return ((ulong)U32BE(b, o) << 32) | U32BE(b, o + 4); }
        public static long U64(byte[] b, int o) { return o + 8 <= b.Length && o >= 0 ? (long)(U32(b, o) | ((ulong)U32(b, o + 4) << 32)) : 0; }
        public static int I32(byte[] b, int o) { return (int)U32(b, o); }

        public static bool Match(byte[] b, int o, string ascii)
        {
            if (o < 0 || o + ascii.Length > b.Length) return false;
            for (int i = 0; i < ascii.Length; i++) if (b[o + i] != (byte)ascii[i]) return false;
            return true;
        }
        public static bool Match(byte[] b, int o, byte[] pat)
        {
            if (o < 0 || o + pat.Length > b.Length) return false;
            for (int i = 0; i < pat.Length; i++) if (b[o + i] != pat[i]) return false;
            return true;
        }

        public static int IndexOf(byte[] b, byte[] pat, int start, int end)
        {
            if (pat.Length == 0) return -1;
            end = Math.Min(end, b.Length - pat.Length + 1);
            byte f = pat[0];
            for (int i = Math.Max(0, start); i < end; i++)
            {
                if (b[i] != f) continue;
                int k = 1;
                while (k < pat.Length && b[i + k] == pat[k]) k++;
                if (k == pat.Length) return i;
            }
            return -1;
        }
        public static int IndexOf(byte[] b, string ascii, int start, int end) { return IndexOf(b, Encoding.ASCII.GetBytes(ascii), start, end); }

        public static bool IsPrintable(byte[] b, int o, int n)
        {
            if (o < 0 || o + n > b.Length) return false;
            for (int i = 0; i < n; i++) if (b[o + i] < 0x20 || b[o + i] > 0x7E) return false;
            return true;
        }

        public static string Ascii(byte[] b, int o, int n)
        {
            if (o < 0) return "";
            n = Math.Max(0, Math.Min(n, b.Length - o));
            var sb = new StringBuilder(n);
            for (int i = 0; i < n; i++) { byte c = b[o + i]; if (c == 0) break; sb.Append(c >= 0x20 && c < 0x7F ? (char)c : '?'); }
            return sb.ToString();
        }

        public static string Hex(long v) { return "0x" + v.ToString("X"); }
    }

    /// <summary>IBM PC code page 437, used by DOS archivers for file names.</summary>
    public static class Cp437
    {
        const string hi =
            "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";
        public static string Decode(byte[] b, int off, int n)
        {
            var sb = new StringBuilder(n);
            for (int i = 0; i < n && off + i < b.Length; i++)
            {
                byte c = b[off + i];
                if (c == 0) break;
                sb.Append(c < 0x80 ? (char)c : hi[c - 0x80]);
            }
            return sb.ToString();
        }
        public static string Decode(byte[] b) { return Decode(b, 0, b.Length); }
    }

    public static class Fmt
    {
        public static string Size(long n)
        {
            if (n < 1024) return n + " B";
            if (n < 1024 * 1024) return (n / 1024.0).ToString("0.#") + " KB";
            if (n < 1024L * 1024 * 1024) return (n / 1048576.0).ToString("0.#") + " MB";
            return (n / 1073741824.0).ToString("0.##") + " GB";
        }
    }
}
