using PECoff;
using Xunit;

public class DataDirectoryDeepDecodeTests
{
    [Fact]
    public void ArchitectureDirectory_Parses_Entries_From_Buffer()
    {
        byte[] data = new byte[24 + 16];
        WriteUInt32(data, 0, 0x12345678);
        WriteUInt32(data, 4, 1);
        WriteUInt32(data, 8, 0);
        WriteUInt32(data, 12, 16);
        WriteUInt32(data, 16, 24);
        WriteUInt32(data, 20, 2);
        WriteUInt32(data, 24, 0x1000);
        WriteUInt32(data, 28, 0xAABBCCDD);
        WriteUInt32(data, 32, 0x2000);
        WriteUInt32(data, 36, 0x11223344);

        bool parsed = PECOFF.TryParseArchitectureDirectoryDataForTest(data, out ArchitectureDirectoryInfo info);

        Assert.True(parsed);
        Assert.True(info.Parsed);
        Assert.Equal((uint)2, info.NumberOfEntries);
        Assert.Equal(2, info.ParsedEntryCount);
        Assert.Equal(0x1000u, info.Entries[0].FixupRva);
    }

    [Fact]
    public void GlobalPtr_Computes_Rva_From_Va_Or_Rva()
    {
        bool okRva = PECOFF.TryComputeRvaFromPointerForTest(0x1000, 0x400000, 0x20000, out uint rva, out string kind);
        Assert.True(okRva);
        Assert.Equal(0x1000u, rva);
        Assert.Equal("RVA", kind);

        bool okVa = PECOFF.TryComputeRvaFromPointerForTest(0x401000, 0x400000, 0x20000, out uint rva2, out string kind2);
        Assert.True(okVa);
        Assert.Equal(0x1000u, rva2);
        Assert.Equal("VA", kind2);
    }

    [Fact]
    public void IatSamples_Parse_Entries_From_Buffer()
    {
        byte[] data = new byte[12];
        WriteUInt32(data, 0, 0x00001000);
        WriteUInt32(data, 4, 0x00401000);
        WriteUInt32(data, 8, 0);

        bool parsed = PECOFF.TryParseIatSamplesForTest(data, false, 0x00400000, 0x20000, out IatEntryInfo[] samples, out uint mappedCount);

        Assert.True(parsed);
        Assert.Equal(3, samples.Length);
        Assert.Equal(2u, mappedCount);
        Assert.True(samples[0].HasRva);
        Assert.True(samples[1].HasRva);
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
