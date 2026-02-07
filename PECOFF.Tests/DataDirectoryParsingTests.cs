using PECoff;
using Xunit;

public class DataDirectoryParsingTests
{
    [Fact]
    public void ArchitectureDirectory_Header_Parses()
    {
        byte[] data = new byte[24];
        WriteUInt32(data, 0, 0x12345678);
        WriteUInt32(data, 4, 2);
        WriteUInt32(data, 8, 1);
        WriteUInt32(data, 12, 64);
        WriteUInt32(data, 16, 0x2000);
        WriteUInt32(data, 20, 4);

        bool parsed = PECOFF.TryParseArchitectureHeaderForTest(
            data,
            out uint magic,
            out uint major,
            out uint minor,
            out uint sizeOfData,
            out uint firstEntry,
            out uint entries);

        Assert.True(parsed);
        Assert.Equal((uint)0x12345678, magic);
        Assert.Equal((uint)2, major);
        Assert.Equal((uint)1, minor);
        Assert.Equal((uint)64, sizeOfData);
        Assert.Equal((uint)0x2000, firstEntry);
        Assert.Equal((uint)4, entries);
    }

    [Fact]
    public void GlobalPtr_Value_Parses()
    {
        byte[] data = new byte[8];
        data[0] = 0x78;
        data[1] = 0x56;
        data[2] = 0x34;
        data[3] = 0x12;

        bool parsed = PECOFF.TryParseGlobalPtrValueForTest(data, isPe32Plus: false, out ulong value);

        Assert.True(parsed);
        Assert.Equal((ulong)0x12345678, value);
    }

    [Fact]
    public void Iat_Entry_Counts()
    {
        byte[] data = new byte[12];
        WriteUInt32(data, 0, 1);
        WriteUInt32(data, 4, 0);
        WriteUInt32(data, 8, 2);

        bool parsed = PECOFF.TryCountIatEntriesForTest(data, isPe32Plus: false, out uint nonZero, out uint zero);

        Assert.True(parsed);
        Assert.Equal((uint)2, nonZero);
        Assert.Equal((uint)1, zero);
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
