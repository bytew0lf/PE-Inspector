using System.Text;
using PECoff;
using Xunit;

public class PdbStreamParsingTests
{
    [Fact]
    public void Pdb_Dbi_Stream_Parses_Header()
    {
        byte[] data = new byte[64];
        WriteInt32(data, 0, 0x11223344);
        WriteInt32(data, 4, 0x0000100B);
        WriteInt32(data, 8, 7);
        WriteUInt16(data, 12, 5);
        WriteUInt16(data, 14, 0x1200);
        WriteUInt16(data, 16, 6);
        WriteUInt16(data, 18, 0x2200);
        WriteUInt16(data, 20, 7);
        WriteUInt16(data, 22, 0x3300);
        WriteInt32(data, 24, 0x10);
        WriteInt32(data, 28, 0x20);
        WriteInt32(data, 32, 0x30);
        WriteInt32(data, 36, 0x40);
        WriteInt32(data, 40, 0x50);
        WriteInt32(data, 44, 0x60);
        WriteInt32(data, 48, 0x70);
        WriteInt32(data, 52, 0x80);
        WriteUInt16(data, 56, 0x01);
        WriteUInt16(data, 58, 0x8664);
        WriteInt32(data, 60, 0);

        bool parsed = PECOFF.TryParsePdbDbiStreamForTest(data, out PdbDbiInfo info);

        Assert.True(parsed);
        Assert.Equal(0x11223344, info.Signature);
        Assert.Equal(0x0000100B, info.Version);
        Assert.Equal(7, info.Age);
        Assert.Equal(5, info.GlobalStreamIndex);
        Assert.Equal(6, info.PublicStreamIndex);
        Assert.Equal(7, info.SymRecordStreamIndex);
        Assert.Equal(0x8664, info.Machine);
    }

    [Fact]
    public void Pdb_Tpi_Stream_Parses_Header()
    {
        byte[] data = new byte[56];
        WriteUInt32(data, 0, 0x0000131);
        WriteUInt32(data, 4, 56);
        WriteUInt32(data, 8, 0x1000);
        WriteUInt32(data, 12, 0x1005);
        WriteUInt32(data, 16, 0x200);
        WriteUInt16(data, 20, 3);
        WriteUInt16(data, 22, 4);
        WriteUInt32(data, 24, 4);
        WriteUInt32(data, 28, 10);
        WriteUInt32(data, 32, 0x40);
        WriteUInt32(data, 36, 0x80);
        WriteUInt32(data, 40, 0xC0);
        WriteUInt32(data, 44, 0x20);
        WriteUInt32(data, 48, 0xE0);
        WriteUInt32(data, 52, 0x10);

        bool parsed = PECOFF.TryParsePdbTpiStreamForTest(data, false, out PdbTpiInfo info);

        Assert.True(parsed);
        Assert.Equal(0x0000131u, info.Version);
        Assert.Equal(56u, info.HeaderSize);
        Assert.Equal(0x1000u, info.TypeIndexBegin);
        Assert.Equal(0x1005u, info.TypeIndexEnd);
        Assert.Equal(5, info.TypeCount);
        Assert.Equal(10u, info.HashBucketCount);
    }

    [Fact]
    public void Pdb_Gsi_Stream_Extracts_Publics()
    {
        byte[] data = Encoding.ASCII.GetBytes("PUBLICS\0foo\0bar\0");

        bool parsed = PECOFF.TryParsePdbGsiStreamForTest(data, out PdbGsiInfo info);

        Assert.True(parsed);
        Assert.Equal("Publics", info.Kind);
        Assert.Contains("foo", info.Names);
        Assert.Contains("bar", info.Names);
    }

    private static void WriteUInt16(byte[] buffer, int offset, ushort value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }

    private static void WriteInt32(byte[] buffer, int offset, int value)
    {
        WriteUInt32(buffer, offset, unchecked((uint)value));
    }
}
