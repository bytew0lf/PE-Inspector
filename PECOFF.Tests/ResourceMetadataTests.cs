using PECoff;
using Xunit;

public class ResourceMetadataTests
{
    [Fact]
    public void BitmapHeader_Parse_Returns_Metadata()
    {
        byte[] data = new byte[40];
        // BITMAPINFOHEADER size
        data[0] = 40;
        // width = 16, height = 32
        data[4] = 16;
        data[8] = 32;
        // planes
        data[12] = 1;
        // bitcount = 32
        data[14] = 32;
        // compression = BI_RGB
        data[16] = 0;
        // image size
        data[20] = 0x40;

        bool parsed = PECOFF.TryParseBitmapInfoHeaderForTest(data, out int width, out int height, out ushort bitCount, out uint compression, out uint imageSize);

        Assert.True(parsed);
        Assert.Equal(16, width);
        Assert.Equal(32, height);
        Assert.Equal((ushort)32, bitCount);
        Assert.Equal((uint)0, compression);
        Assert.Equal((uint)0x40, imageSize);
    }

    [Fact]
    public void CursorGroup_Parse_Returns_Entries()
    {
        byte[] data = new byte[6 + 14];
        // reserved = 0
        // type = 2
        data[2] = 2;
        // count = 1
        data[4] = 1;
        // entry width/height
        data[6] = 32;
        data[7] = 32;
        // hotspot X=1, Y=2
        data[10] = 1;
        data[12] = 2;
        // bytesInRes = 0x20
        data[14] = 0x20;
        // resourceId = 5
        data[18] = 5;

        bool parsed = PECOFF.TryParseCursorGroupForTest(data, out ResourceCursorGroupInfo group);

        Assert.True(parsed);
        Assert.NotNull(group);
        Assert.Single(group.Entries);
        Assert.True(group.HeaderValid);
        Assert.Equal(14, group.EntrySize);
        Assert.False(group.EntriesTruncated);
        Assert.Equal((byte)32, group.Entries[0].Width);
        Assert.Equal((byte)32, group.Entries[0].Height);
        Assert.Equal((ushort)1, group.Entries[0].HotspotX);
        Assert.Equal((ushort)2, group.Entries[0].HotspotY);
        Assert.Equal((ushort)5, group.Entries[0].ResourceId);
    }

    [Fact]
    public void IconGroup_Parse_Allows_Variant_Header()
    {
        byte[] data = new byte[6 + 14];
        // reserved = 1 (non-standard)
        data[0] = 1;
        // type = 1
        data[2] = 1;
        // count = 1
        data[4] = 1;
        // entry width/height
        data[6] = 16;
        data[7] = 16;
        // planes
        data[10] = 1;
        // bitcount = 32
        data[12] = 32;
        // bytesInRes = 0x20
        data[14] = 0x20;
        // resourceId = 7
        data[18] = 7;

        bool parsed = PECOFF.TryParseIconGroupForTest(data, out IconGroupInfo group);

        Assert.True(parsed);
        Assert.NotNull(group);
        Assert.Single(group.Entries);
        Assert.False(group.HeaderValid);
        Assert.Equal((ushort)1, group.DeclaredEntryCount);
        Assert.Equal(14, group.EntrySize);
        Assert.Equal((ushort)7, group.Entries[0].ResourceId);
    }
}
