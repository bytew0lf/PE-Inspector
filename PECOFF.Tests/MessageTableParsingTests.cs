using PECoff;
using Xunit;

public class MessageTableParsingTests
{
    [Fact]
    public void MessageTable_Parse_Reads_Entries_And_Range()
    {
        byte[] data = BuildSingleEntryMessageTable();

        bool parsed = PECOFF.TryParseMessageTableForTest(data, out MessageTableEntryInfo[] entries, out uint minId, out uint maxId);

        Assert.True(parsed);
        Assert.Single(entries);
        Assert.Equal(1u, minId);
        Assert.Equal(1u, maxId);

        MessageTableEntryInfo entry = entries[0];
        Assert.Equal(1u, entry.Id);
        Assert.Equal("OK", entry.Text);
        Assert.False(entry.IsUnicode);
        Assert.Equal(8, entry.Length);
        Assert.Equal(0, entry.Flags);
    }

    private static byte[] BuildSingleEntryMessageTable()
    {
        byte[] data = new byte[24];

        WriteUInt32(data, 0, 1); // block count
        WriteUInt32(data, 4, 1); // low ID
        WriteUInt32(data, 8, 1); // high ID
        WriteUInt32(data, 12, 16); // offset to entries

        WriteUInt16(data, 16, 8); // length
        WriteUInt16(data, 18, 0); // flags
        data[20] = (byte)'O';
        data[21] = (byte)'K';
        data[22] = 0;
        data[23] = 0;

        return data;
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)((value >> 16) & 0xFF);
        data[offset + 3] = (byte)((value >> 24) & 0xFF);
    }

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
    }
}
