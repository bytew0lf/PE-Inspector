using System;
using System.Text;
using PECoff;
using Xunit;

public class SevenZipLzmaDecoderTests
{
    [Fact]
    public void Lzma2_Decodes_Uncompressed_Chunk()
    {
        byte[] payload = Encoding.ASCII.GetBytes("HELLO");
        byte[] stream = new byte[1 + 2 + payload.Length + 1];
        int offset = 0;
        stream[offset++] = 0x01; // uncompressed, reset dict
        stream[offset++] = (byte)((payload.Length - 1) & 0xFF);
        stream[offset++] = (byte)(((payload.Length - 1) >> 8) & 0xFF);
        Array.Copy(payload, 0, stream, offset, payload.Length);
        offset += payload.Length;
        stream[offset] = 0x00; // end

        bool ok = SevenZipLzmaDecoder.TryDecodeLzma2(stream, new byte[] { 0 }, (ulong)payload.Length, out byte[] decoded);
        Assert.True(ok);
        Assert.Equal(payload, decoded);
    }

    [Fact]
    public void Lzma2_Rejects_Oversized_UnpackSize()
    {
        byte[] payload = Encoding.ASCII.GetBytes("A");
        byte[] stream = new byte[1 + 2 + payload.Length + 1];
        int offset = 0;
        stream[offset++] = 0x01;
        stream[offset++] = 0x00;
        stream[offset++] = 0x00;
        Array.Copy(payload, 0, stream, offset, payload.Length);
        offset += payload.Length;
        stream[offset] = 0x00;

        bool ok = SevenZipLzmaDecoder.TryDecodeLzma2(
            stream,
            new byte[] { 0 },
            (ulong)SevenZipLzmaDecoder.MaxDecodedBytes + 1UL,
            out _);

        Assert.False(ok);
    }

    [Fact]
    public void Lzma2_Rejects_Oversized_Dictionary()
    {
        byte[] payload = Encoding.ASCII.GetBytes("A");
        byte[] stream = new byte[1 + 2 + payload.Length + 1];
        int offset = 0;
        stream[offset++] = 0x01;
        stream[offset++] = 0x00;
        stream[offset++] = 0x00;
        Array.Copy(payload, 0, stream, offset, payload.Length);
        offset += payload.Length;
        stream[offset] = 0x00;

        // prop 40 maps to a multi-gigabyte dictionary and should be rejected.
        bool ok = SevenZipLzmaDecoder.TryDecodeLzma2(stream, new byte[] { 40 }, 1, out _);

        Assert.False(ok);
    }
}
