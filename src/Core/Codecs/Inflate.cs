using System;

namespace SymbolHunter.Core
{
    /// <summary>Deflate / Deflate64 decoder writing into an LzWindow (window persists across calls for MSZIP).</summary>
    public static class Inflate
    {
        static readonly int[] lenBase = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
        static readonly int[] lenExtra = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
        static readonly int[] distBase = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153 };
        static readonly int[] distExtra = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14 };
        static readonly int[] clOrder = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
        static Huffman fixedLit, fixedDist;

        static void InitFixed()
        {
            if (fixedLit != null) return;
            var l = new byte[288];
            for (int i = 0; i < 144; i++) l[i] = 8;
            for (int i = 144; i < 256; i++) l[i] = 9;
            for (int i = 256; i < 280; i++) l[i] = 7;
            for (int i = 280; i < 288; i++) l[i] = 8;
            fixedLit = new Huffman(l, 288);
            var d = new byte[32];
            for (int i = 0; i < 32; i++) d[i] = 5;
            fixedDist = new Huffman(d, 32);
        }

        /// <summary>Decodes a complete deflate stream (until the final block). Returns false if the stream ended early.</summary>
        public static bool Run(BitReaderLsb br, LzWindow w, bool deflate64 = false)
        {
            InitFixed();
            bool last;
            do
            {
                if (w.Done) return true;
                last = br.Get(1) == 1;
                int type = br.Get(2);
                if (type == 0)
                {
                    br.AlignToByte();
                    int len = br.Get(16), nlen = br.Get(16);
                    if ((len ^ 0xFFFF) != nlen) throw new FormatException2("deflate: bad stored block length");
                    for (int i = 0; i < len; i++) w.Put((byte)br.Get(8));
                    if (br.Overrun > 4) return false;
                }
                else if (type == 1) Codes(br, w, fixedLit, fixedDist, deflate64);
                else if (type == 2)
                {
                    int hlit = br.Get(5) + 257, hdist = br.Get(5) + 1, hclen = br.Get(4) + 4;
                    var cl = new byte[19];
                    for (int i = 0; i < hclen; i++) cl[clOrder[i]] = (byte)br.Get(3);
                    var clh = new Huffman(cl, 19, 7);
                    var lens = new byte[hlit + hdist];
                    int n = 0;
                    while (n < hlit + hdist)
                    {
                        int sym = clh.Decode(br);
                        if (sym < 16) lens[n++] = (byte)sym;
                        else
                        {
                            int rep; byte val = 0;
                            if (sym == 16) { if (n == 0) throw new FormatException2("deflate: repeat with no previous length"); val = lens[n - 1]; rep = 3 + br.Get(2); }
                            else if (sym == 17) rep = 3 + br.Get(3);
                            else rep = 11 + br.Get(7);
                            if (n + rep > hlit + hdist) throw new FormatException2("deflate: too many code lengths");
                            while (rep-- > 0) lens[n++] = val;
                        }
                        if (br.Overrun > 8) return false;
                    }
                    if (lens[256] == 0) throw new FormatException2("deflate: no end-of-block code");
                    var ll = new byte[hlit]; Array.Copy(lens, ll, hlit);
                    var dl = new byte[hdist]; Array.Copy(lens, hlit, dl, 0, hdist);
                    Codes(br, w, new Huffman(ll, hlit), new Huffman(dl, hdist), deflate64);
                }
                else throw new FormatException2("deflate: invalid block type");
                if (br.Overrun > 8) return false;
            } while (!last);
            return true;
        }

        static void Codes(BitReaderLsb br, LzWindow w, Huffman lit, Huffman dist, bool d64)
        {
            while (true)
            {
                int sym = lit.Decode(br);
                if (sym < 256) { w.Put((byte)sym); if (w.Done) return; }
                else if (sym == 256) return;
                else
                {
                    sym -= 257;
                    if (sym >= 29) throw new FormatException2("deflate: bad length code");
                    int len = (d64 && sym == 28) ? 3 + br.Get(16) : lenBase[sym] + br.Get(lenExtra[sym]);
                    int ds = dist.Decode(br);
                    if (ds >= (d64 ? 32 : 30)) throw new FormatException2("deflate: bad distance code");
                    int d = distBase[ds] + br.Get(distExtra[ds]);
                    if (d > w.Total && !w.AllowPreHistory) throw new FormatException2("deflate: distance too far back");
                    w.Copy(d, len);
                    if (w.Done) return;
                }
                if (br.Overrun > 8) throw new FormatException2("deflate: unexpected end of data");
            }
        }
    }
}
