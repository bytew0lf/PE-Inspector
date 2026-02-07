using System;
using System.Text;
using PECoff;
using Xunit;

public class ResourceFontParsingTests
{
    [Fact]
    public void FontFormat_Detects_TrueType()
    {
        byte[] data = { 0x00, 0x01, 0x00, 0x00 };
        Assert.Equal("TrueType", PECOFF.DetectFontFormatForTest(data));
    }

    [Fact]
    public void FontDirectory_Parses_FaceName()
    {
        byte[] data = new byte[140];
        BitConverter.GetBytes((ushort)1).CopyTo(data, 0); // count
        BitConverter.GetBytes((ushort)2).CopyTo(data, 2); // ordinal

        int entryStart = 4;
        int faceOffsetField = entryStart + 105;
        BitConverter.GetBytes(120u).CopyTo(data, faceOffsetField);
        Encoding.ASCII.GetBytes("TestFont").CopyTo(data, entryStart + 120);
        data[entryStart + 120 + "TestFont".Length] = 0;

        bool parsed = PECOFF.TryParseFontDirectoryForTest(data, out ushort count, out ResourceFontDirEntryInfo[] entries);
        Assert.True(parsed);
        Assert.Equal((ushort)1, count);
        Assert.Single(entries);
        Assert.Equal((ushort)2, entries[0].Ordinal);
        Assert.Equal("TestFont", entries[0].FaceName);
    }
}
