using System;
using PECoff;
using Xunit;

public class ResourceParsingTests
{
    [Fact]
    public void TryParseMenuTemplateBytes_Parses_Simple_Menu_Item()
    {
        byte[] data =
        {
            0x80, 0x00, // flags (end)
            0x01, 0x00, // id
            0x46, 0x00, // F
            0x69, 0x00, // i
            0x6C, 0x00, // l
            0x65, 0x00, // e
            0x00, 0x00  // terminator
        };

        bool parsed = PECOFF.TryParseMenuTemplateBytes(data, out ResourceMenuInfo menu);

        Assert.True(parsed);
        Assert.NotNull(menu);
        Assert.False(menu.IsExtended);
        Assert.Equal(1, menu.ItemCount);
        Assert.Single(menu.ItemTexts);
        Assert.Equal("File", menu.ItemTexts[0]);
    }

    [Fact]
    public void TryParseToolbarResourceBytes_Parses_Item_Ids()
    {
        byte[] data =
        {
            0x01, 0x00, // version
            0x10, 0x00, // width
            0x10, 0x00, // height
            0x02, 0x00, // item count
            0x64, 0x00, // 100
            0x65, 0x00  // 101
        };

        bool parsed = PECOFF.TryParseToolbarResourceBytes(data, out ResourceToolbarInfo toolbar);

        Assert.True(parsed);
        Assert.NotNull(toolbar);
        Assert.Equal((ushort)1, toolbar.Version);
        Assert.Equal((ushort)16, toolbar.Width);
        Assert.Equal((ushort)16, toolbar.Height);
        Assert.Equal((ushort)2, toolbar.ItemCount);
        Assert.Equal(new ushort[] { 100, 101 }, toolbar.ItemIds);
    }

    [Fact]
    public void TryParseMenuTemplateBytes_Rejects_Unterminated_String()
    {
        byte[] data =
        {
            0x80, 0x00, // flags (end)
            0x01, 0x00, // id
            0x46, 0x00, // F
            0x69, 0x00  // i (no terminator)
        };

        bool parsed = PECOFF.TryParseMenuTemplateBytes(data, out ResourceMenuInfo menu);

        Assert.False(parsed);
        Assert.Null(menu);
    }

    [Fact]
    public void TryParseToolbarResourceBytes_Rejects_Truncated_Header()
    {
        byte[] data =
        {
            0x01, 0x00, // version
            0x10, 0x00  // width (missing remaining header)
        };

        bool parsed = PECOFF.TryParseToolbarResourceBytes(data, out ResourceToolbarInfo toolbar);

        Assert.False(parsed);
        Assert.Null(toolbar);
    }

    [Fact]
    public void ResourceParsing_Fuzz_Does_Not_Throw()
    {
        Random rng = new Random(1234);
        for (int i = 0; i < 100; i++)
        {
            int size = rng.Next(0, 128);
            byte[] data = new byte[size];
            rng.NextBytes(data);

            Exception? ex = Record.Exception(() =>
            {
                PECOFF.TryParseMenuTemplateBytes(data, out _);
                PECOFF.TryParseToolbarResourceBytes(data, out _);
            });

            Assert.Null(ex);
        }
    }
}
