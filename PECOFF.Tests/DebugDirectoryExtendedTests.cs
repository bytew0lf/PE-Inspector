using System;
using PECoff;
using Xunit;

public class DebugDirectoryExtendedTests
{
    [Fact]
    public void EmbeddedPortablePdb_Parses_Header()
    {
        byte[] data = new byte[12];
        data[0] = (byte)'M';
        data[1] = (byte)'P';
        data[2] = (byte)'D';
        data[3] = (byte)'B';
        WriteUInt32(data, 4, 0x10);
        data[8] = 0x01;
        data[9] = 0x02;
        data[10] = 0x03;
        data[11] = 0x04;

        bool parsed = PECOFF.TryParseDebugEmbeddedPortablePdbDataForTest(data, out DebugEmbeddedPortablePdbInfo info);

        Assert.True(parsed);
        Assert.Equal("MPDB", info.Signature);
        Assert.Equal(0x10u, info.UncompressedSize);
        Assert.Equal(4u, info.CompressedSize);
        Assert.False(string.IsNullOrWhiteSpace(info.PayloadHash));
    }

    [Fact]
    public void PdbHash_Parses_Algorithm_And_Hash()
    {
        byte[] data = new byte[4 + 20];
        WriteUInt32(data, 0, 1);
        for (int i = 0; i < 20; i++)
        {
            data[4 + i] = (byte)(i + 1);
        }

        bool parsed = PECOFF.TryParseDebugPdbHashDataForTest(data, out DebugPdbHashInfo info);

        Assert.True(parsed);
        Assert.Equal("SHA1", info.AlgorithmName);
        Assert.Equal(40, info.Hash.Length);
    }

    [Fact]
    public void Spgo_Parses_Raw_Info()
    {
        byte[] data = new byte[] { 1, 2, 3, 4, 5 };

        bool parsed = PECOFF.TryParseDebugSpgoDataForTest(data, out DebugSpgoInfo info);

        Assert.True(parsed);
        Assert.Equal(5u, info.DataLength);
        Assert.False(string.IsNullOrWhiteSpace(info.Hash));
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
