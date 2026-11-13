using System;

namespace SymbolHunter.Core
{
    /// <summary>Microsoft LZX decoder (CAB flavour): 32K frames, verbatim/aligned/uncompressed blocks, E8 translation.</summary>
    public sealed class LzxDecoder
    {
        const int LenMax = 249, PreMax = 20, MinMatch = 2;
        static readonly int[] extraBits = new int[52];
        static readonly uint[] posBase = new uint[52];
        static LzxDecoder()
        {
            for (int i = 0, j = 0; i < 52; i += 2) { extraBits[i] = j; extraBits[i + 1] = j; if (i != 0 && j < 17) j++; }
            uint b = 0;
            for (int i = 0; i < 52; i++) { posBase[i] = b; b += 1u << extraBits[i]; }
        }

        readonly int windowSize, posSlots, mask;
        readonly byte[] window;
        long decoded, emitted;
        uint r0 = 1, r1 = 1, r2 = 1;
        readonly byte[] mainLen, lenLen = new byte[LenMax], alignLen = new byte[8];
        Huffman mainH, lenH, alignH;
        int blockType, blockRemaining; bool blockOdd;
        bool headerRead, intelStarted; uint intelSize;
        long frameCount;

        byte[] inBuf; int inPos, inEnd; uint bitBuf; int bitsLeft;

        public LzxDecoder(int windowBits)
        {
            if (windowBits < 15 || windowBits > 21) throw new UnsupportedException("LZX window " + windowBits);
            windowSize = 1 << windowBits; mask = windowSize - 1;
            window = new byte[windowSize];
            posSlots = windowBits == 20 ? 42 : windowBits == 21 ? 50 : windowBits * 2;
            mainLen = new byte[256 + posSlots * 8];
        }

        void Ensure(int n)
        {
            while (bitsLeft < n)
            {
                int lo = inPos < inEnd ? inBuf[inPos] : 0, hi = inPos + 1 < inEnd ? inBuf[inPos + 1] : 0;
                inPos += 2;
                bitBuf |= (uint)((hi << 8) | lo) << (16 - bitsLeft);
                bitsLeft += 16;
            }
        }
        int Read(int n)
        {
            if (n == 0) return 0;
            Ensure(n);
            int v = (int)(bitBuf >> (32 - n));
            bitBuf <<= n; bitsLeft -= n;
            return v;
        }
        int ReadBit() { return Read(1); }

        void ReadLengths(byte[] lens, int first, int last)
        {
            var pre = new byte[PreMax];
            for (int i = 0; i < PreMax; i++) pre[i] = (byte)Read(4);
            var preH = new Huffman(pre, PreMax);
            for (int x = first; x < last; )
            {
                int z = preH.DecodeBits(ReadBit);
                if (z == 17) { int y = Read(4) + 4; while (y-- > 0 && x < last) lens[x++] = 0; }
                else if (z == 18) { int y = Read(5) + 20; while (y-- > 0 && x < last) lens[x++] = 0; }
                else if (z == 19)
                {
                    int y = Read(1) + 4;
                    z = preH.DecodeBits(ReadBit);
                    int v = lens[x] - z; if (v < 0) v += 17;
                    while (y-- > 0 && x < last) lens[x++] = (byte)v;
                }
                else { int v = lens[x] - z; if (v < 0) v += 17; lens[x++] = (byte)v; }
            }
        }

        static Huffman Build(byte[] l, int n)
        {
            for (int i = 0; i < n; i++) if (l[i] != 0) return new Huffman(l, n, 11);
            return null;
        }

        /// <summary>Decompresses one CAB data block (one frame of up to 32K output).</summary>
        public void DecodeFrame(byte[] input, int len, int outLen, Sink sink)
        {
            inBuf = input; inPos = 0; inEnd = len; bitBuf = 0; bitsLeft = 0;
            if (!headerRead)
            {
                if (Read(1) == 1) { int hi = Read(16), lo = Read(16); intelSize = (uint)((hi << 16) | lo); }
                headerRead = true;
            }
            long frameEnd = emitted + outLen;
            while (decoded < frameEnd)
            {
                if (blockRemaining == 0)
                {
                    if (blockType == 3 && blockOdd) { inPos++; blockOdd = false; }
                    blockType = Read(3);
                    int hi = Read(16), lo = Read(8);
                    blockRemaining = (hi << 8) | lo;
                    if (blockType == 2)
                    {
                        for (int i = 0; i < 8; i++) alignLen[i] = (byte)Read(3);
                        alignH = Build(alignLen, 8);
                    }
                    if (blockType == 1 || blockType == 2)
                    {
                        ReadLengths(mainLen, 0, 256);
                        ReadLengths(mainLen, 256, mainLen.Length);
                        mainH = Build(mainLen, mainLen.Length);
                        if (mainLen[0xE8] != 0) intelStarted = true;
                        ReadLengths(lenLen, 0, LenMax);
                        lenH = Build(lenLen, LenMax);
                        if (mainH == null) throw new FormatException2("LZX: empty main tree");
                    }
                    else if (blockType == 3)
                    {
                        intelStarted = true;
                        if (bitsLeft == 0) inPos += 2;
                        bitsLeft = 0; bitBuf = 0;
                        r0 = Bin.U32(inBuf, inPos); r1 = Bin.U32(inBuf, inPos + 4); r2 = Bin.U32(inBuf, inPos + 8);
                        inPos += 12;
                        blockOdd = (blockRemaining & 1) != 0;
                    }
                    else throw new FormatException2("LZX: bad block type " + blockType);
                    if (blockRemaining == 0) throw new FormatException2("LZX: empty block");
                }
                long want = Math.Min(blockRemaining, frameEnd - decoded);
                long produced = 0;
                if (blockType == 3)
                {
                    for (int i = 0; i < want; i++) { window[(int)(decoded & mask)] = inPos < inEnd ? inBuf[inPos] : (byte)0; inPos++; decoded++; }
                    produced = want;
                }
                else
                {
                    while (produced < want)
                    {
                        int sym = mainH.DecodeBits(ReadBit);
                        if (sym < 256) { window[(int)(decoded & mask)] = (byte)sym; decoded++; produced++; continue; }
                        sym -= 256;
                        int matchLen = sym & 7;
                        if (matchLen == 7) { if (lenH == null) throw new FormatException2("LZX: no length tree"); matchLen += lenH.DecodeBits(ReadBit); }
                        matchLen += MinMatch;
                        int slot = sym >> 3;
                        uint off;
                        if (slot == 0) off = r0;
                        else if (slot == 1) { off = r1; r1 = r0; r0 = off; }
                        else if (slot == 2) { off = r2; r2 = r0; r0 = off; }
                        else
                        {
                            int eb = extraBits[slot];
                            if (blockType == 2 && eb >= 3)
                                off = posBase[slot] - 2 + ((uint)Read(eb - 3) << 3) + (uint)alignH.DecodeBits(ReadBit);
                            else off = posBase[slot] - 2 + (uint)Read(eb);
                            r2 = r1; r1 = r0; r0 = off;
                        }
                        long src = decoded - off;
                        for (int i = 0; i < matchLen; i++) { window[(int)(decoded & mask)] = window[(int)(src & mask)]; decoded++; src++; }
                        produced += matchLen;
                    }
                }
                blockRemaining -= (int)Math.Min(produced, blockRemaining);
                if (inPos > inEnd + 4) throw new FormatException2("LZX: unexpected end of data");
            }
            var frame = new byte[outLen];
            for (int i = 0; i < outLen; i++) frame[i] = window[(int)((emitted + i) & mask)];
            if (intelStarted && intelSize != 0 && frameCount < 32768 && outLen > 10) E8(frame, outLen, emitted);
            frameCount++;
            emitted = frameEnd;
            sink.Write(frame, 0, outLen);
        }

        void E8(byte[] d, int n, long curPos)
        {
            for (int i = 0; i < n - 10; )
            {
                if (d[i] != 0xE8) { i++; continue; }
                int abs = (int)Bin.U32(d, i + 1);
                long pos = curPos + i;
                if (abs >= -pos && abs < intelSize)
                {
                    int rel = abs >= 0 ? (int)(abs - pos) : (int)(abs + intelSize);
                    d[i + 1] = (byte)rel; d[i + 2] = (byte)(rel >> 8); d[i + 3] = (byte)(rel >> 16); d[i + 4] = (byte)(rel >> 24);
                }
                i += 5;
            }
        }
    }
}
