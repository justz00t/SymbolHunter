using System;

namespace SymbolHunter.Core
{
    /// <summary>
    /// Minimal FLAC frame decoder (no stream header) for CHD hunks: 16-bit stereo, all subframe types
    /// (constant, verbatim, fixed, LPC), Rice/Rice2 residuals and stereo decorrelation.
    /// </summary>
    public static class FlacFrames
    {
        sealed class Bits
        {
            readonly byte[] d; readonly int end; public long Pos;   // bit position
            public Bits(byte[] data, int off, int len) { d = data; Pos = (long)off * 8; end = off + len; }
            public bool Eof { get { return (Pos >> 3) >= end; } }
            public uint Read(int n)
            {
                uint v = 0;
                for (int i = 0; i < n; i++)
                {
                    long byteIdx = Pos >> 3;
                    int bit = byteIdx < end ? (d[byteIdx] >> (7 - (int)(Pos & 7))) & 1 : 0;
                    v = (v << 1) | (uint)bit; Pos++;
                }
                return v;
            }
            public int ReadSigned(int n)
            {
                if (n == 0) return 0;
                uint v = Read(n);
                if (n < 32 && (v & (1u << (n - 1))) != 0) v |= ~((1u << n) - 1);
                return (int)v;
            }
            public int Unary()
            {
                int q = 0;
                while (true)
                {
                    long byteIdx = Pos >> 3;
                    if (byteIdx >= end) throw new FormatException2("FLAC: data ended inside a code");
                    // fast path: whole zero byte
                    if ((Pos & 7) == 0 && d[byteIdx] == 0) { q += 8; Pos += 8; continue; }
                    int bit = (d[byteIdx] >> (7 - (int)(Pos & 7))) & 1; Pos++;
                    if (bit == 1) return q;
                    q++;
                    if (q > (1 << 24)) throw new FormatException2("FLAC: bad unary code");
                }
            }
            public void AlignByte() { Pos = (Pos + 7) & ~7L; }
        }

        /// <summary>Decodes frames until dlen bytes of interleaved 16-bit stereo samples are produced.</summary>
        public static void DecodeStereo16(byte[] src, int off, int len, byte[] dest, int doff, int dlen, bool bigEndian, int defaultBlockSize, out int consumed)
        {
            var b = new Bits(src, off, len);
            int outPos = doff, outEnd = doff + dlen;
            var ch = new int[2][];
            while (outPos < outEnd)
            {
                if (b.Eof) throw new FormatException2("FLAC: data ended early");
                uint sync = b.Read(14);
                if (sync != 0x3FFE) throw new FormatException2("FLAC: lost frame sync");
                b.Read(1); b.Read(1);                 // reserved, blocking strategy
                int bsCode = (int)b.Read(4), srCode = (int)b.Read(4), chanCode = (int)b.Read(4), ssCode = (int)b.Read(3);
                b.Read(1);
                // frame/sample number (UTF-8 style)
                uint first = b.Read(8);
                int extra = 0;
                if ((first & 0x80) == 0) extra = 0; else if ((first & 0xE0) == 0xC0) extra = 1; else if ((first & 0xF0) == 0xE0) extra = 2;
                else if ((first & 0xF8) == 0xF0) extra = 3; else if ((first & 0xFC) == 0xF8) extra = 4; else if ((first & 0xFE) == 0xFC) extra = 5; else if (first == 0xFE) extra = 6;
                else throw new FormatException2("FLAC: bad frame number");
                for (int i = 0; i < extra; i++) b.Read(8);
                int blockSize;
                switch (bsCode)
                {
                    case 0: blockSize = defaultBlockSize; break;
                    case 1: blockSize = 192; break;
                    case 2: case 3: case 4: case 5: blockSize = 576 << (bsCode - 2); break;
                    case 6: blockSize = (int)b.Read(8) + 1; break;
                    case 7: blockSize = (int)b.Read(16) + 1; break;
                    default: blockSize = 256 << (bsCode - 8); break;
                }
                if (srCode == 12) b.Read(8); else if (srCode == 13 || srCode == 14) b.Read(16);
                b.Read(8);                            // CRC-8
                int bps = ssCode == 0 ? 16 : ssCode == 1 ? 8 : ssCode == 2 ? 12 : ssCode == 4 ? 16 : ssCode == 5 ? 20 : ssCode == 6 ? 24 : ssCode == 7 ? 32 : 16;
                int channels = chanCode < 8 ? chanCode + 1 : 2;
                if (channels != 2) throw new FormatException2("FLAC: expected stereo");
                for (int c = 0; c < 2; c++)
                {
                    if (ch[c] == null || ch[c].Length < blockSize) ch[c] = new int[blockSize];
                    int cbps = bps;
                    if ((chanCode == 8 && c == 1) || (chanCode == 9 && c == 0) || (chanCode == 10 && c == 1)) cbps++;
                    Subframe(b, ch[c], blockSize, cbps);
                }
                // decorrelate
                var l = ch[0]; var r = ch[1];
                for (int i = 0; i < blockSize; i++)
                {
                    int a = l[i], s = r[i];
                    int left, right;
                    switch (chanCode)
                    {
                        case 8: left = a; right = a - s; break;               // left/side
                        case 9: right = s; left = a + s; break;               // side/right: ch0 = side, ch1 = right
                        case 10: { int mid = (a << 1) | (s & 1); left = (mid + s) >> 1; right = (mid - s) >> 1; break; }
                        default: left = a; right = s; break;
                    }
                    if (outPos + 4 > outEnd) { outPos = outEnd; break; }
                    if (bigEndian) { dest[outPos] = (byte)(left >> 8); dest[outPos + 1] = (byte)left; dest[outPos + 2] = (byte)(right >> 8); dest[outPos + 3] = (byte)right; }
                    else { dest[outPos] = (byte)left; dest[outPos + 1] = (byte)(left >> 8); dest[outPos + 2] = (byte)right; dest[outPos + 3] = (byte)(right >> 8); }
                    outPos += 4;
                }
                b.AlignByte();
                b.Read(16);                           // CRC-16
            }
            consumed = (int)(b.Pos / 8) - off;
        }

        static void Subframe(Bits b, int[] s, int n, int bps)
        {
            b.Read(1);
            int type = (int)b.Read(6);
            int wasted = 0;
            if (b.Read(1) == 1) wasted = b.Unary() + 1;
            bps -= wasted;
            if (type == 0)
            {
                int v = b.ReadSigned(bps);
                for (int i = 0; i < n; i++) s[i] = v;
            }
            else if (type == 1)
            {
                for (int i = 0; i < n; i++) s[i] = b.ReadSigned(bps);
            }
            else if (type >= 8 && type <= 12)
            {
                int order = type - 8;
                for (int i = 0; i < order; i++) s[i] = b.ReadSigned(bps);
                Residual(b, s, n, order);
                for (int i = order; i < n; i++)
                {
                    switch (order)
                    {
                        case 1: s[i] += s[i - 1]; break;
                        case 2: s[i] += 2 * s[i - 1] - s[i - 2]; break;
                        case 3: s[i] += 3 * s[i - 1] - 3 * s[i - 2] + s[i - 3]; break;
                        case 4: s[i] += 4 * s[i - 1] - 6 * s[i - 2] + 4 * s[i - 3] - s[i - 4]; break;
                    }
                }
            }
            else if (type >= 32)
            {
                int order = (type & 31) + 1;
                for (int i = 0; i < order; i++) s[i] = b.ReadSigned(bps);
                int prec = (int)b.Read(4) + 1;
                if (prec == 16) throw new FormatException2("FLAC: bad LPC precision");
                int shift = b.ReadSigned(5);
                var coef = new int[order];
                for (int i = 0; i < order; i++) coef[i] = b.ReadSigned(prec);
                Residual(b, s, n, order);
                for (int i = order; i < n; i++)
                {
                    long sum = 0;
                    for (int j = 0; j < order; j++) sum += (long)coef[j] * s[i - 1 - j];
                    s[i] += (int)(shift >= 0 ? sum >> shift : sum << -shift);
                }
            }
            else throw new FormatException2("FLAC: reserved subframe type");
            if (wasted > 0) for (int i = 0; i < n; i++) s[i] <<= wasted;
        }

        static void Residual(Bits b, int[] s, int n, int order)
        {
            int method = (int)b.Read(2);
            if (method > 1) throw new FormatException2("FLAC: bad residual coding");
            int paramBits = method == 0 ? 4 : 5, escape = method == 0 ? 15 : 31;
            int partOrder = (int)b.Read(4);
            int parts = 1 << partOrder;
            int idx = order;
            for (int p = 0; p < parts; p++)
            {
                int count = (n >> partOrder) - (p == 0 ? order : 0);
                if (count < 0) throw new FormatException2("FLAC: bad partition");
                int param = (int)b.Read(paramBits);
                if (param == escape)
                {
                    int raw = (int)b.Read(5);
                    for (int i = 0; i < count; i++) s[idx++] = b.ReadSigned(raw);
                }
                else
                {
                    for (int i = 0; i < count; i++)
                    {
                        uint q = (uint)b.Unary();
                        uint u = (q << param) | (param > 0 ? b.Read(param) : 0);
                        s[idx++] = (int)(u >> 1) ^ -(int)(u & 1);
                    }
                }
            }
        }
    }
}
