using System;
using PECoff;
using Xunit;

public class LoadConfigAdvancedMetadataTests
{
    [Fact]
    public void DynamicRelocationMetadata_Parses_Entries()
    {
        byte[] data = new byte[24];
        WriteUInt32(data, 0, 1); // version
        WriteUInt32(data, 4, 24); // size
        WriteUInt32(data, 8, 0x1000);
        WriteUInt32(data, 12, 0x10);
        WriteUInt32(data, 16, 0x2000);
        WriteUInt32(data, 20, 0x20);

        DynamicRelocationMetadataInfo info = PECOFF.ParseDynamicRelocationMetadataForTest(data);

        Assert.Equal(1u, info.Version);
        Assert.Equal(24u, info.Size);
        Assert.False(info.IsMalformed);
        Assert.Empty(info.Issues);
        Assert.Equal(2, info.Entries.Count);
        Assert.Equal(0x1000u, info.Entries[0].Symbol);
        Assert.Equal(0x10u, info.Entries[0].BaseRelocSize);
    }

    [Fact]
    public void DynamicRelocationMetadata_Flags_Short_Size()
    {
        byte[] data = new byte[8];
        WriteUInt32(data, 0, 1);
        WriteUInt32(data, 4, 4); // invalid: smaller than header

        DynamicRelocationMetadataInfo info = PECOFF.ParseDynamicRelocationMetadataForTest(data);

        Assert.True(info.IsMalformed);
        Assert.Contains(info.Issues, issue => issue.Contains("smaller than the header", StringComparison.Ordinal));
    }

    [Fact]
    public void ChpeMetadata_Parses_Code_Ranges()
    {
        byte[] data = new byte[28];
        WriteUInt32(data, 0, 2); // version
        WriteUInt32(data, 4, 12); // code range offset
        WriteUInt32(data, 8, 2); // count
        WriteUInt32(data, 12, 0x1000);
        WriteUInt32(data, 16, 0x1100);
        WriteUInt32(data, 20, 0x2000);
        WriteUInt32(data, 24, 0x2200);

        ChpeMetadataInfo info = PECOFF.ParseChpeMetadataForTest(data);

        Assert.Equal(2u, info.Version);
        Assert.Equal(12u, info.CodeRangeOffset);
        Assert.Equal(2u, info.CodeRangeCount);
        Assert.False(info.IsMalformed);
        Assert.Equal(2, info.CodeRanges.Count);
        Assert.Equal(0x1000u, info.CodeRanges[0].StartRva);
        Assert.Equal(0x1100u, info.CodeRanges[0].EndRva);
    }

    [Fact]
    public void ChpeMetadata_Flags_Invalid_Range_Offset()
    {
        byte[] data = new byte[20];
        WriteUInt32(data, 0, 1);
        WriteUInt32(data, 4, 8); // invalid: before header end
        WriteUInt32(data, 8, 1);

        ChpeMetadataInfo info = PECOFF.ParseChpeMetadataForTest(data);

        Assert.True(info.IsMalformed);
        Assert.Contains(info.Issues, issue => issue.Contains("offset is invalid", StringComparison.Ordinal));
    }

    [Fact]
    public void VolatileMetadata_Parses_Header()
    {
        byte[] data = new byte[24];
        WriteUInt32(data, 0, 24); // size
        WriteUInt32(data, 4, 1); // version
        WriteUInt32(data, 8, 0x3000); // access table rva
        WriteUInt32(data, 12, 0x20); // access table size
        WriteUInt32(data, 16, 0x4000); // range table rva
        WriteUInt32(data, 20, 0x30); // range table size

        VolatileMetadataInfo info = PECOFF.ParseVolatileMetadataForTest(data);

        Assert.False(info.IsMalformed);
        Assert.Empty(info.Issues);
        Assert.Equal(24u, info.Size);
        Assert.Equal(1u, info.Version);
        Assert.Equal(0x3000u, info.AccessTableRva);
        Assert.Equal(0x30u, info.InfoRangeTableSize);
    }

    [Fact]
    public void VolatileMetadata_Flags_Zero_Rva_With_NonZero_Size()
    {
        byte[] data = new byte[24];
        WriteUInt32(data, 0, 24);
        WriteUInt32(data, 4, 1);
        WriteUInt32(data, 8, 0); // invalid
        WriteUInt32(data, 12, 0x20);
        WriteUInt32(data, 16, 0);
        WriteUInt32(data, 20, 0x10);

        VolatileMetadataInfo info = PECOFF.ParseVolatileMetadataForTest(data);

        Assert.True(info.IsMalformed);
        Assert.Contains(info.Issues, issue => issue.Contains("access table", StringComparison.Ordinal));
        Assert.Contains(info.Issues, issue => issue.Contains("info-range table", StringComparison.Ordinal));
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)((value >> 16) & 0xFF);
        data[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
