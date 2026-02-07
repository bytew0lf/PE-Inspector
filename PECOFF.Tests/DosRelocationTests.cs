using PECoff;
using Xunit;

public class DosRelocationTests
{
    [Fact]
    public void DosRelocations_Parse_From_Header()
    {
        byte[] data = new byte[0x50];
        WriteUInt16(data, 0x00, 0x5A4D); // MZ
        WriteUInt16(data, 0x06, 2); // e_crlc
        WriteUInt16(data, 0x18, 0x40); // e_lfarlc
        WriteUInt32(data, 0x3C, 0x80); // e_lfanew

        WriteUInt16(data, 0x40, 0x0010);
        WriteUInt16(data, 0x42, 0x0020);
        WriteUInt16(data, 0x44, 0x0030);
        WriteUInt16(data, 0x46, 0x0040);

        bool parsed = PECOFF.TryParseDosRelocationsForTest(data, out DosRelocationInfo info);

        Assert.True(parsed);
        Assert.Equal(2, info.DeclaredCount);
        Assert.Equal(0x40u, info.TableOffset);
        Assert.False(info.IsTruncated);
        Assert.Equal(2, info.Entries.Count);
        Assert.Equal((ushort)0x0010, info.Entries[0].Offset);
        Assert.Equal((ushort)0x0020, info.Entries[0].Segment);
        Assert.Equal(0x0210u, info.Entries[0].LinearAddress);
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
}
