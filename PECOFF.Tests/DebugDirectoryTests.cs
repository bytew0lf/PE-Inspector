using PECoff;
using Xunit;

public class DebugDirectoryTests
{
    [Fact]
    public void Debug_Borland_Parses_Header_And_Offsets()
    {
        byte[] data = new byte[16];
        WriteUInt32(data, 0, 1);
        WriteUInt32(data, 4, 2);
        WriteUInt32(data, 8, 0x10);
        WriteUInt32(data, 12, 0x20);

        bool parsed = PECOFF.TryParseDebugBorlandDataForTest(data, out DebugBorlandInfo info);

        Assert.True(parsed);
        Assert.Equal((uint)1, info.Version);
        Assert.Equal((uint)2, info.Flags);
        Assert.Equal(2, info.Offsets.Count);
        Assert.Equal((uint)0x10, info.Offsets[0]);
        Assert.Equal((uint)0x20, info.Offsets[1]);
    }

    [Fact]
    public void Debug_Reserved_Parses_Header_And_Offsets()
    {
        byte[] data = new byte[12];
        WriteUInt32(data, 0, 3);
        WriteUInt32(data, 4, 4);
        WriteUInt32(data, 8, 0x30);

        bool parsed = PECOFF.TryParseDebugReservedDataForTest(data, out DebugReservedInfo info);

        Assert.True(parsed);
        Assert.Equal((uint)3, info.Version);
        Assert.Equal((uint)4, info.Flags);
        Assert.Single(info.Offsets);
        Assert.Equal((uint)0x30, info.Offsets[0]);
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
