using System;

namespace SymbolHunter.Core
{
    /// <summary>
    /// Quantum decoder (David Stafford's arithmetic-coded LZ77, as used in Microsoft CAB folders of type 2).
    /// Each CAB data block is one frame: the range coder restarts per block, models and window persist.
    /// Ported from the published descriptions (libmspack qtmd.c / 7-Zip QuantumDecoder).
    /// </summary>
    public sealed class QuantumDecoder
    {
        const int UpdateStep = 8, FreqSumMax = 3800, ReorderStart = 4, ReorderEvery = 50;

        sealed class Model
        {
            public int NumItems, ReorderCount;
            public readonly ushort[] Freqs = new ushort[65];
            public readonly byte[] Vals = new byte[64];

            public void Init(int numItems, int startVal)
            {
                NumItems = numItems; ReorderCount = ReorderStart;
                for (int i = 0; i < numItems; i++) { Freqs[i] = (ushort)(numItems - i); Vals[i] = (byte)(startVal + i); }
                Freqs[numItems] = 0;
            }

            public int Decode(RangeDecoder rc)
            {
                if (Freqs[0] > FreqSumMax)
                {
                    if (--ReorderCount == 0)
                    {
                        ReorderCount = ReorderEvery;
                        int next = 0;
                        for (int i = NumItems - 1; i >= 0; i--) { int freq = Freqs[i]; Freqs[i] = (ushort)((freq - next + 1) >> 1); next = freq; }
                        for (int i = 0; i < NumItems - 1; i++)
                        {
                            int freq = Freqs[i];
                            for (int k = i + 1; k < NumItems; k++)
                                if (freq < Freqs[k])
                                {
                                    int f2 = Freqs[k]; Freqs[k] = (ushort)freq; Freqs[i] = (ushort)f2; freq = f2;
                                    byte v = Vals[i]; Vals[i] = Vals[k]; Vals[k] = v;
                                }
                        }
                        int acc = 0;
                        for (int i = NumItems - 1; i >= 0; i--) { acc += Freqs[i]; Freqs[i] = (ushort)acc; }
                    }
                    else
                    {
                        int next = 1;
                        for (int i = NumItems - 1; i >= 0; i--) { int freq = Freqs[i] >> 1; if (freq < next) freq = next; Freqs[i] = (ushort)freq; next = freq + 1; }
                    }
                }
                int freq0 = Freqs[0];
                Freqs[0] = (ushort)(freq0 + UpdateStep);
                uint threshold = rc.Threshold((uint)freq0);
                int idx = 1;
                int f = Freqs[idx];
                while (f > threshold && idx < NumItems) { Freqs[idx] = (ushort)(f + UpdateStep); idx++; f = Freqs[idx]; }
                int res = Vals[idx - 1];
                rc.Decode((uint)f, (uint)(Freqs[idx - 1] - UpdateStep), (uint)freq0);
                return res;
            }
        }

        sealed class RangeDecoder
        {
            uint low, range, code;
            byte[] buf; int lim, pos, bitOffset;

            int At(int i) { return i < lim ? buf[i] : 0; }

            public void Init(byte[] data, int len)
            {
                buf = data; lim = len; bitOffset = 0;
                code = (uint)((At(0) << 8) | At(1)); pos = 2;
                low = 0; range = 0x10000;
            }

            /// <summary>True when decoding has run far past the end of the block (damaged data).</summary>
            public bool Overrun { get { return pos > lim + 8; } }

            public uint ReadBits(int n)
            {
                if (n <= 0) return 0;
                uint v = (uint)((At(pos) << 24) | (At(pos + 1) << 16) | (At(pos + 2) << 8) | At(pos + 3));
                uint res = v << bitOffset;
                bitOffset += n;
                pos += bitOffset >> 3;
                bitOffset &= 7;
                return res >> (32 - n);
            }

            public uint Threshold(uint total) { return unchecked(((code + 1) * total - 1) / range); }

            public void Decode(uint start, uint end, uint total)
            {
                unchecked
                {
                    if (total == 0) throw new FormatException2("Quantum: bad model state");
                    uint hi = 0 - (low + end * range / total);
                    uint offset = start * range / total;
                    uint lo = low + offset;
                    code -= offset;
                    int numBits = 0;
                    lo ^= hi;
                    while ((lo & (1u << 15)) != 0 && numBits < 32) { lo <<= 1; hi <<= 1; numBits++; }
                    lo ^= hi;
                    uint an = lo & hi;
                    while ((an & (1u << 14)) != 0 && numBits < 32) { an <<= 1; lo <<= 1; hi <<= 1; numBits++; }
                    low = lo;
                    range = ((~hi - lo) & 0xffff) + 1;
                    while (numBits > 0) { int n = Math.Min(numBits, 16); code = (code << n) + ReadBits(n); numBits -= n; }
                }
            }
        }

        readonly int dictBits;
        readonly byte[] window;
        readonly int mask;
        long total;                       // bytes produced so far
        bool initialised;
        readonly Model selector = new Model(), lenSlot = new Model();
        readonly Model[] literals = { new Model(), new Model(), new Model(), new Model() };
        readonly Model[] posSlot = { new Model(), new Model(), new Model() };
        readonly RangeDecoder rc = new RangeDecoder();
        readonly byte[] outBuf = new byte[1 << 15];

        public QuantumDecoder(int windowBits)
        {
            if (windowBits > 21) throw new UnsupportedException("Quantum window of 2^" + windowBits + " bytes");
            dictBits = windowBits;
            int size = 1 << Math.Max(15, windowBits);
            window = new byte[size]; mask = size - 1;
        }

        void InitModels()
        {
            selector.Init(7, 0);
            for (int i = 0; i < 4; i++) literals[i].Init(64, i * 64);
            int numItems = dictBits == 0 ? 1 : dictBits * 2;
            int[] maxItems = { 24, 36, 42 };
            for (int i = 0; i < 3; i++) posSlot[i].Init(Math.Min(numItems, maxItems[i]), 0);
            lenSlot.Init(27, 3 + 3 - 1);
            initialised = true;
        }

        /// <summary>Decodes one CAB data block (one Quantum frame) producing exactly outLen bytes.</summary>
        public void DecodeFrame(byte[] input, int outLen, Sink sink)
        {
            if (!initialised) InitModels();
            if (input.Length < 2) throw new FormatException2("Quantum: block too short");
            rc.Init(input, input.Length);
            int outPos = 0;
            int remaining = outLen;
            while (remaining > 0)
            {
                if (rc.Overrun) throw new FormatException2("Quantum: block data ended early");
                int sel = selector.Decode(rc);
                if (sel < 4)
                {
                    byte b = (byte)literals[sel].Decode(rc);
                    Put(b, ref outPos, sink);
                    remaining--;
                    continue;
                }
                if (sel > 6) throw new FormatException2("Quantum: bad selector");
                int len = sel - 4 + 3;
                if (sel == 6)
                {
                    len = lenSlot.Decode(rc);
                    if (len >= 6 + 3 + 3 - 1)
                    {
                        len -= 6 - 4 + 3 + 3 - 1;
                        int nb = len >> 2;
                        len = ((4 | (len & 3)) << nb) - (4 << 1) + 6 + 3 + 3 - 1;
                        if (nb < 6) len += (int)rc.ReadBits(nb);
                    }
                }
                long dist = posSlot[sel - 4].Decode(rc);
                if (dist >= 4)
                {
                    int nb = (int)((dist >> 1) - 1);
                    dist = ((2 | (dist & 1)) << nb) + rc.ReadBits(nb);
                }
                if (len > remaining) throw new FormatException2("Quantum: match runs past the end of the frame");
                long src = total - dist - 1;
                if (src < 0) throw new FormatException2("Quantum: match before start of data");
                if (dist + 1 > window.Length) throw new FormatException2("Quantum: match distance beyond window");
                for (int k = 0; k < len; k++) Put(window[(int)((src + k) & mask)], ref outPos, sink);
                remaining -= len;
            }
            if (outPos > 0) sink.Write(outBuf, 0, outPos);
        }

        void Put(byte b, ref int outPos, Sink sink)
        {
            window[(int)(total & mask)] = b;
            total++;
            outBuf[outPos++] = b;
            if (outPos == outBuf.Length) { sink.Write(outBuf, 0, outPos); outPos = 0; }
        }
    }
}
