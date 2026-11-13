using System;
using System.Collections.Generic;

namespace SymbolHunter.Core
{
    /// <summary>PKWARE Data Compression Library "implode" streams (used by InstallShield 3, ZIP method 10, many installers).</summary>
    public static class Dcl
    {
        static readonly byte[] litlen = {
            11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8,
            9, 7, 6, 7, 8, 7, 6, 55, 8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5,
            7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8, 25, 11, 8, 11, 9, 12,
            8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27,
            44, 253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45,
            44, 173 };
        static readonly byte[] lenlen = { 2, 35, 36, 53, 38, 23 };
        static readonly byte[] distlen = { 2, 20, 53, 230, 247, 151, 248 };
        static readonly int[] lbase = { 3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264 };
        static readonly int[] lextra = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
        static Huffman litH, lenH, distH;

        static Huffman Build(byte[] rep)
        {
            var l = new List<byte>();
            foreach (var b in rep) { int cnt = (b >> 4) + 1; for (int i = 0; i < cnt; i++) l.Add((byte)(b & 15)); }
            return new Huffman(l.ToArray(), l.Count);
        }

        /// <summary>Returns true if the bytes look like the start of a DCL stream.</summary>
        public static bool Probe(byte[] h, int off = 0)
        {
            return h.Length >= off + 3 && h[off] <= 1 && h[off + 1] >= 4 && h[off + 1] <= 6;
        }

        public static void Explode(BitReaderLsb br, Sink sink, long outSize)
        {
            if (litH == null) { litH = Build(litlen); lenH = Build(lenlen); distH = Build(distlen); }
            int lit = br.Get(8), dict = br.Get(8);
            if (lit > 1 || dict < 4 || dict > 6) throw new FormatException2("DCL: bad header");
            var w = new LzWindow(13, sink, outSize);
            while (!w.Done)
            {
                if (br.Overrun > 4) throw new FormatException2("DCL: unexpected end of data");
                if (br.Get(1) == 1)
                {
                    int sym = lenH.Decode(br, true);
                    int len = lbase[sym] + br.Get(lextra[sym]);
                    if (len == 519) break;
                    int sh = len == 2 ? 2 : dict;
                    int dist = (distH.Decode(br, true) << sh) + br.Get(sh) + 1;
                    if (dist > w.Total) throw new FormatException2("DCL: distance too far back");
                    w.Copy(dist, len);
                }
                else
                {
                    int b = lit == 1 ? litH.Decode(br, true) : br.Get(8);
                    w.Put((byte)b);
                }
            }
            w.Flush();
        }
    }
}
