using System;
using System.IO;
using System.Linq;
using SharpCompress.Common.SevenZip;
using SharpCompress.Compressors.BZip2;
using SharpCompress.Compressors.Deflate;
using SharpCompress.Compressors.Filters;
using SharpCompress.Compressors.LZMA.Utilites;
using SharpCompress.Compressors.PPMd;

namespace SharpCompress.Compressors.LZMA
{
    internal static class DecoderRegistry
    {
        private const uint K_COPY = 0x0;
        private const uint K_DELTA = 3;
        private const uint K_LZMA2 = 0x21;
        private const uint K_LZMA = 0x030101;
        private const uint K_PPMD = 0x030401;
        private const uint K_BCJ = 0x03030103;
        private const uint K_BCJ2 = 0x0303011B;
        private const uint K_DEFLATE = 0x040108;
        private const uint K_B_ZIP2 = 0x040202;

        internal static Stream CreateDecoderStream(CMethodId id, Stream[] inStreams, byte[] info, IPasswordProvider pass,
                                                   long limit)
        {
            switch (id._id)
            {
                case K_COPY:
                    if (info != null)
                    {
                        throw new NotSupportedException();
                    }
                    return inStreams.Single();
                case K_LZMA:
                case K_LZMA2:
                    return new LzmaStream(info, inStreams.Single(), -1, limit);
#if !NO_CRYPTO
                case CMethodId.K_AES_ID:
                    return new AesDecoderStream(inStreams.Single(), info, pass, limit);
#endif
                case K_BCJ:
                    return new BCJFilter(false, inStreams.Single());
                case K_BCJ2:
                    return new Bcj2DecoderStream(inStreams, info, limit);
                case K_B_ZIP2:
                    return new BZip2Stream(inStreams.Single(), CompressionMode.Decompress, true);
                case K_PPMD:
                    return new PpmdStream(new PpmdProperties(info), inStreams.Single(), false);
                case K_DEFLATE:
                    return new DeflateStream(inStreams.Single(), CompressionMode.Decompress);
                case K_DELTA:
                    return new DeltaDecoderStream(inStreams.Single(), info);
                default:
                    throw new NotSupportedException("7z coder 0x" + id._id.ToString("X") + " is not supported");
            }
        }
    }

    /// <summary>7z Delta filter (Symbol Hunter addition): out[i] = in[i] + out[i - distance].</summary>
    internal sealed class DeltaDecoderStream : Stream
    {
        private readonly Stream _base; private readonly int _dist; private readonly byte[] _hist = new byte[256]; private int _pos;
        public DeltaDecoderStream(Stream b, byte[] info) { _base = b; _dist = (info != null && info.Length > 0 ? info[0] : 0) + 1; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = _base.Read(buffer, offset, count);
            for (int i = 0; i < n; i++)
            {
                byte v = (byte)(buffer[offset + i] + _hist[(_pos - _dist) & 255]);
                buffer[offset + i] = v; _hist[_pos & 255] = v; _pos++;
            }
            return n;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _base.Dispose(); base.Dispose(disposing); }
    }
}
