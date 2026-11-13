using System;

namespace SymbolHunter.Core
{
    /// <summary>LZ77 + static Huffman (LHA -lh4- .. -lh7-, ARJ methods 1-3, ZOO method 2).</summary>
    public sealed class LzhStatic
    {
        const int NC = 510, NT = 19, TBIT = 5, CBIT = 9;
        readonly BitReaderMsb br; readonly int np, pbit;
        int blockSize;
        Huffman cH, pH, ptH; int cConst = -1, pConst = -1, ptConst = -1;
        byte[] ptLen;

        public LzhStatic(BitReaderMsb br, int np, int pbit) { this.br = br; this.np = np; this.pbit = pbit; }

        /// <summary>LHA method parameters by dictionary bits.</summary>
        public static LzhStatic ForDicbit(BitReaderMsb br, int dicbit)
        {
            switch (dicbit)
            {
                case 12: case 13: return new LzhStatic(br, 14, 4);
                case 15: return new LzhStatic(br, 16, 5);
                case 16: return new LzhStatic(br, 17, 5);
                default: throw new UnsupportedException("LZH dictionary " + dicbit);
            }
        }

        void ReadPtLen(int nn, int nbit, int special, out Huffman h, out int constSym)
        {
            int n = br.Get(nbit);
            h = null; constSym = -1;
            if (n == 0) { constSym = br.Get(nbit); return; }
            if (n > nn) throw new FormatException2("LZH: bad pt table size");
            var len = new byte[nn];
            int i = 0;
            while (i < n)
            {
                int c = br.Peek(3);
                br.Skip(3);
                if (c == 7)
                {
                    int guard = 0;
                    while (br.Get(1) == 1) { c++; if (++guard > 16) throw new FormatException2("LZH: bad bit length"); }
                }
                len[i++] = (byte)c;
                if (i == special)
                {
                    int z = br.Get(2);
                    while (--z >= 0 && i < nn) len[i++] = 0;
                }
            }
            ptLen = len;
            h = MakeTable(len, nn);
            if (h == null) constSym = SingleSymbol(len);
        }

        static Huffman MakeTable(byte[] len, int n)
        {
            int used = 0; for (int i = 0; i < n; i++) if (len[i] != 0) used++;
            if (used == 0) throw new FormatException2("LZH: empty code table");
            return new Huffman(len, n, 12);
        }
        static int SingleSymbol(byte[] len) { for (int i = 0; i < len.Length; i++) if (len[i] != 0) return i; return 0; }

        void ReadCLen()
        {
            int n = br.Get(CBIT);
            cH = null; cConst = -1;
            if (n == 0) { cConst = br.Get(CBIT); return; }
            if (n > NC) throw new FormatException2("LZH: bad c table size");
            var len = new byte[NC];
            int i = 0;
            while (i < n)
            {
                int c = ptConst >= 0 ? ptConst : ptH.Decode(br);
                if (c <= 2)
                {
                    int z = c == 0 ? 1 : c == 1 ? br.Get(4) + 3 : br.Get(CBIT) + 20;
                    while (--z >= 0 && i < NC) len[i++] = 0;
                }
                else len[i++] = (byte)(c - 2);
            }
            cH = MakeTable(len, NC);
        }

        public int DecodeC()
        {
            if (blockSize == 0)
            {
                blockSize = br.Get(16);
                ReadPtLen(NT, TBIT, 3, out ptH, out ptConst);
                ReadCLen();
                ReadPtLen(np, pbit, -1, out pH, out pConst);
            }
            blockSize--;
            return cConst >= 0 ? cConst : cH.Decode(br);
        }

        public int DecodeP()
        {
            int j = pConst >= 0 ? pConst : pH.Decode(br);
            if (j != 0) j = (1 << (j - 1)) + br.Get(j - 1);
            return j;
        }

        public void Run(Sink sink, long size, byte fill = 0x20)
        {
            var w = new LzWindow(16, sink, size, fill) { AllowPreHistory = true };
            while (!w.Done)
            {
                if (br.Overrun > 64) { w.Flush(); throw new FormatException2("LZH: unexpected end of data"); }
                int c = DecodeC();
                if (c < 256) w.Put((byte)c);
                else
                {
                    int len = c - 253;
                    int off = DecodeP() + 1;
                    w.Copy(off, len);
                }
            }
            w.Flush();
        }
    }

    /// <summary>Okumura/Yoshizaki LZHUF: adaptive Huffman + 4K window (LHarc -lh1-, Teledisk advanced compression).</summary>
    public sealed class Lzhuf
    {
        const int N = 4096, F = 60, THRESHOLD = 2, N_CHAR = 256 - THRESHOLD + F, T = N_CHAR * 2 - 1, R = T - 1, MAX_FREQ = 0x8000;
        readonly int[] freq = new int[T + 1], prnt = new int[T + N_CHAR], son = new int[T];
        readonly BitReaderMsb br;
        static Huffman posCode;

        public Lzhuf(BitReaderMsb br)
        {
            this.br = br;
            for (int i = 0; i < N_CHAR; i++) { freq[i] = 1; son[i] = i + T; prnt[i + T] = i; }
            int a = 0, j = N_CHAR;
            while (j <= R) { freq[j] = freq[a] + freq[a + 1]; son[j] = a; prnt[a] = prnt[a + 1] = j; a += 2; j++; }
            freq[T] = 0xFFFF; prnt[R] = 0;
            if (posCode == null)
            {
                // fixed code for the upper 6 bits of a position: 1x3, 3x4, 8x5, 12x6, 24x7, 16x8 bits
                var l = new byte[64]; int k = 0;
                int[] cnt = { 1, 3, 8, 12, 24, 16 }; int[] bits = { 3, 4, 5, 6, 7, 8 };
                for (int g = 0; g < 6; g++) for (int c = 0; c < cnt[g]; c++) l[k++] = (byte)bits[g];
                posCode = new Huffman(l, 64);
            }
        }

        void Reconst()
        {
            int j = 0;
            for (int i = 0; i < T; i++) if (son[i] >= T) { freq[j] = (freq[i] + 1) / 2; son[j] = son[i]; j++; }
            for (int i = 0, jj = N_CHAR; jj < T; i += 2, jj++)
            {
                int k = i + 1;
                int f = freq[jj] = freq[i] + freq[k];
                for (k = jj - 1; f < freq[k]; k--) { }
                k++;
                int l = jj - k;
                Array.Copy(freq, k, freq, k + 1, l); freq[k] = f;
                Array.Copy(son, k, son, k + 1, l); son[k] = i;
            }
            for (int i = 0; i < T; i++)
            {
                int k = son[i];
                if (k >= T) prnt[k] = i; else prnt[k] = prnt[k + 1] = i;
            }
        }

        void Update(int c)
        {
            if (freq[R] == MAX_FREQ) Reconst();
            c = prnt[c + T];
            do
            {
                int k = ++freq[c];
                int l = c + 1;
                if (k > freq[l])
                {
                    while (k > freq[++l]) { }
                    l--;
                    freq[c] = freq[l]; freq[l] = k;
                    int i = son[c]; prnt[i] = l; if (i < T) prnt[i + 1] = l;
                    int j = son[l]; son[l] = i;
                    prnt[j] = c; if (j < T) prnt[j + 1] = c;
                    son[c] = j;
                    c = l;
                }
            } while ((c = prnt[c]) != 0);
        }

        public int DecodeChar()
        {
            int c = son[R];
            while (c < T) { c += br.Get(1); c = son[c]; }
            c -= T;
            Update(c);
            return c;
        }

        public int DecodePosition()
        {
            int hi = posCode.Decode(br);
            return (hi << 6) | br.Get(6);
        }

        public void Run(Sink sink, long size)
        {
            var w = new LzWindow(12, sink, size, 0x20) { AllowPreHistory = true };
            while (!w.Done)
            {
                if (br.Overrun > 64) { w.Flush(); throw new FormatException2("LZHUF: unexpected end of data"); }
                int c = DecodeChar();
                if (c < 256) w.Put((byte)c);
                else
                {
                    int pos = DecodePosition();
                    w.Copy(pos + 1, c - 255 + THRESHOLD);
                }
            }
            w.Flush();
        }
    }

    public static class LzhSimple
    {
        /// <summary>LArc -lzs-: 2K window, 1 flag bit, 11-bit position, 4-bit length.</summary>
        public static void Lzs(BitReaderMsb br, Sink sink, long size)
        {
            var w = new LzWindow(11, sink, size, 0x20) { AllowPreHistory = true };
            int loc = 0;
            while (!w.Done)
            {
                if (br.Overrun > 8) { w.Flush(); throw new FormatException2("lzs: unexpected end of data"); }
                if (br.Get(1) == 1) { w.Put((byte)br.Get(8)); loc++; }
                else
                {
                    int matchpos = br.Get(11);
                    int len = br.Get(4) + 2;
                    int off = ((loc - matchpos - 18) & 0x7FF) + 1;
                    w.Copy(off, len); loc += len;
                }
            }
            w.Flush();
        }

        /// <summary>LArc -lz5-: 4K window with a pre-initialised dictionary, LZSS flag bytes.</summary>
        public static void Lz5(ByteInput inp, Sink sink, long size)
        {
            var w = new LzWindow(12, sink, size, 0x20) { AllowPreHistory = true };
            var d = w.Buffer;
            for (int i = 0; i < 256; i++) for (int k = 0; k < 13; k++) d[i * 13 + 18 + k] = (byte)i;
            for (int i = 0; i < 256; i++) d[256 * 13 + 18 + i] = (byte)i;
            for (int i = 0; i < 256; i++) d[256 * 13 + 256 + 18 + i] = (byte)(255 - i);
            for (int i = 0; i < 128; i++) d[256 * 13 + 512 + 18 + i] = 0;
            for (int i = 0; i < 128 - 18; i++) d[256 * 13 + 512 + 128 + 18 + i] = 0x20;
            int loc = 0, flags = 0, flagCnt = 0;
            while (!w.Done)
            {
                if (flagCnt == 0) { flags = inp.ReadByte(); if (flags < 0) break; flagCnt = 8; }
                flagCnt--;
                int c = inp.ReadByte();
                if (c < 0) break;
                if ((flags & 1) != 0) { w.Put((byte)c); loc++; }
                else
                {
                    int c2 = inp.ReadByte();
                    if (c2 < 0) break;
                    int matchpos = c | ((c2 & 0xF0) << 4);
                    int len = (c2 & 0x0F) + 3;
                    int off = ((loc - matchpos - 19) & 0xFFF) + 1;
                    w.Copy(off, len); loc += len;
                }
                flags >>= 1;
            }
            w.Flush();
            if (w.Total < size) throw new FormatException2("lz5: unexpected end of data");
        }

        /// <summary>ARJ method 4: LZ77 with unary-prefixed lengths and positions.</summary>
        public static void ArjFast(BitReaderMsb br, Sink sink, long size)
        {
            var w = new LzWindow(16, sink, size) { AllowPreHistory = true };
            while (!w.Done)
            {
                if (br.Overrun > 8) { w.Flush(); throw new FormatException2("ARJ m4: unexpected end of data"); }
                int c = Unary(br, 0, 7);
                if (c == 0) w.Put((byte)br.Get(8));
                else
                {
                    int len = c - 1 + 3;
                    int pos = Unary(br, 9, 13);
                    w.Copy(pos + 1, len);
                }
            }
            w.Flush();
        }

        static int Unary(BitReaderMsb br, int start, int stop)
        {
            int plus = 0, pwr = 1 << start, width;
            for (width = start; width < stop; width++)
            {
                if (br.Get(1) == 0) break;
                plus += pwr; pwr <<= 1;
            }
            int c = width != 0 ? br.Get(width) : 0;
            return c + plus;
        }
    }
}
