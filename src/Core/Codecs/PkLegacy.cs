using System;

namespace SymbolHunter.Core
{
    /// <summary>PKZIP 0.9-1.10 compression methods: Shrink (1), Reduce (2-5) and Implode (6).</summary>
    public static class PkLegacy
    {
        // ---------------------------------------------------------------- Shrink: dynamic LZW 9..13 bits with partial clearing
        const int MaxCode = 8191, Invalid = -1, Control = 256;

        public static void Unshrink(BitReaderLsb br, Sink sink, long outSize)
        {
            if (outSize <= 0) return;
            if (outSize > 1L << 30) throw new UnsupportedException("shrunk entry too large");
            var dst = new byte[outSize];
            var prefix = new int[MaxCode + 1]; var ext = new byte[MaxCode + 1]; var len = new int[MaxCode + 1]; var last = new long[MaxCode + 1];
            for (int i = 0; i <= MaxCode; i++) prefix[i] = Invalid;
            for (int i = 0; i < 256; i++) { prefix[i] = i; ext[i] = (byte)i; len[i] = 1; last[i] = -1; }
            var queue = new int[MaxCode + 2]; int qSize = 0, qNext = 0;
            for (int i = Control + 1; i <= MaxCode; i++) queue[qSize++] = i;
            queue[qSize] = Invalid;
            int codeSize = 9;

            Func<int> readCode = null;
            readCode = () =>
            {
                while (true)
                {
                    if (br.Overrun > 2) return -2;
                    int code = br.Get(codeSize);
                    if (code != Control) return code;
                    int ctrl = br.Get(codeSize);
                    if (ctrl == 1 && codeSize < 13) { codeSize++; continue; }
                    if (ctrl == 2)
                    {
                        var isPrefix = new bool[MaxCode + 1];
                        for (int i = Control + 1; i <= MaxCode; i++) if (prefix[i] != Invalid) isPrefix[prefix[i]] = true;
                        qSize = 0;
                        for (int i = Control + 1; i <= MaxCode; i++) if (!isPrefix[i]) { prefix[i] = Invalid; queue[qSize++] = i; }
                        queue[qSize] = Invalid; qNext = 0;
                        continue;
                    }
                    throw new FormatException2("shrink: bad control code");
                }
            };

            int c0 = readCode();
            if (c0 < 0 || c0 > 255) throw new FormatException2("shrink: bad first code");
            dst[0] = (byte)c0; last[c0] = 0;
            long pos = 1; int prev = c0;
            while (pos < outSize)
            {
                int cur = readCode();
                if (cur < 0) break;
                if (cur == queue[qNext])
                {
                    if (prefix[prev] == Invalid) throw new FormatException2("shrink: KwKwK with invalid previous code");
                    prefix[cur] = prev;
                    ext[cur] = dst[last[prev]];
                    len[cur] = len[prev] + 1;
                    last[cur] = last[prev];
                }
                else if (prefix[cur] == Invalid) throw new FormatException2("shrink: code not in table");
                int l = len[cur];
                long from = last[cur];
                // string(cur) = previous occurrence of its first l-1 bytes, then the extension byte
                for (int i = 0; i < l - 1 && pos + i < outSize; i++) dst[pos + i] = dst[from + i];
                if (pos + l - 1 < outSize) dst[pos + l - 1] = ext[cur];
                if (pos + l > outSize) l = (int)(outSize - pos);
                // add new code: previous string + first byte of current string
                int nc = queue[qNext];
                if (nc != Invalid)
                {
                    qNext++;
                    prefix[nc] = prev;
                    ext[nc] = dst[pos];
                    len[nc] = len[prev] + 1;
                    last[nc] = last[prev];
                }
                last[cur] = pos;
                prev = cur;
                pos += l;
            }
            sink.Write(dst, 0, (int)Math.Min(pos, outSize));
        }

        // ---------------------------------------------------------------- Reduce: follower sets + DLE-coded LZ77
        static int FollowerBits(int n) { return n > 16 ? 5 : n > 8 ? 4 : n > 4 ? 3 : n > 2 ? 2 : n > 0 ? 1 : 0; }

        public static void Expand(BitReaderLsb br, Sink sink, long outSize, int factor)
        {
            var fsize = new int[256]; var fol = new byte[256, 32];
            for (int i = 255; i >= 0; i--)
            {
                int n = br.Get(6);
                if (n > 32) throw new FormatException2("reduce: bad follower set");
                fsize[i] = n;
                for (int j = 0; j < n; j++) fol[i, j] = (byte)br.Get(8);
            }
            var w = new LzWindow(16, sink, outSize) { AllowPreHistory = true };
            int cur = 0;
            Func<int> next = () =>
            {
                int n = fsize[cur];
                if (n == 0) cur = br.Get(8);
                else if (br.Get(1) == 1) cur = br.Get(8);
                else
                {
                    int idx = br.Get(FollowerBits(n));
                    if (idx >= n) throw new FormatException2("reduce: bad follower index");
                    cur = fol[cur, idx];
                }
                return cur;
            };
            int lenMask = 0xFF >> factor;
            while (!w.Done)
            {
                if (br.Overrun > 4) break;
                int c = next();
                if (c != 0x90) { w.Put((byte)c); continue; }
                c = next();
                if (c == 0) { w.Put(0x90); continue; }
                int v = c;
                int len = v & lenMask;
                if (len == lenMask) len += next();
                len += 3;
                int dist = ((v >> (8 - factor)) << 8) + next() + 1;
                w.Copy(dist, len);
            }
            w.Flush();
        }

        // ---------------------------------------------------------------- Implode: Shannon-Fano trees + LZ77
        static Huffman ReadSfTree(BitReaderLsb br, int n)
        {
            int bytes = br.Get(8) + 1;
            var lens = new byte[n]; int k = 0;
            for (int i = 0; i < bytes; i++)
            {
                int b = br.Get(8);
                int cnt = (b >> 4) + 1, bl = (b & 15) + 1;
                for (int j = 0; j < cnt; j++)
                {
                    if (k >= n) throw new FormatException2("implode: tree too large");
                    lens[k++] = (byte)bl;
                }
            }
            if (k != n) throw new FormatException2("implode: incomplete tree");
            return new Huffman(lens, n);
        }

        public static void Explode(BitReaderLsb br, Sink sink, long outSize, int flags)
        {
            bool dict8k = (flags & 2) != 0, litTree = (flags & 4) != 0;
            Huffman lit = litTree ? ReadSfTree(br, 256) : null;
            Huffman lenT = ReadSfTree(br, 64), distT = ReadSfTree(br, 64);
            int minMatch = litTree ? 3 : 2, lowBits = dict8k ? 7 : 6;
            var w = new LzWindow(14, sink, outSize) { AllowPreHistory = true };
            while (!w.Done)
            {
                if (br.Overrun > 4) break;
                if (br.Get(1) == 1)
                {
                    int b = litTree ? lit.Decode(br, true) : br.Get(8);
                    w.Put((byte)b);
                }
                else
                {
                    int low = br.Get(lowBits);
                    int high = distT.Decode(br, true);
                    int dist = ((high << lowBits) | low) + 1;
                    int len = lenT.Decode(br, true);
                    if (len == 63) len += br.Get(8);
                    len += minMatch;
                    w.Copy(dist, len);
                }
            }
            w.Flush();
        }
    }
}
