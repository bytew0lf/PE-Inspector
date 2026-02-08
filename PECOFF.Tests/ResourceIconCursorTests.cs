using System.IO;
using PECoff;
using Xunit;

public class ResourceIconCursorTests
{
    [Fact]
    public void IconResource_Parses_Dib_Header()
    {
        byte[] data = BuildBitmapInfoHeader(32, 64, 32);
        ResourceIconInfo info = PECOFF.TryParseIconResourceForTest(data);

        Assert.NotNull(info);
        Assert.False(info.IsPng);
        Assert.Equal(32, info.Width);
        Assert.Equal(32, info.Height);
        Assert.Equal((ushort)32, info.BitCount);
    }

    [Fact]
    public void CursorResource_Parses_Hotspot_And_Dib()
    {
        byte[] header = BuildBitmapInfoHeader(16, 32, 8);
        byte[] data = new byte[4 + header.Length];
        data[0] = 0x02;
        data[1] = 0x00;
        data[2] = 0x03;
        data[3] = 0x00;
        Buffer.BlockCopy(header, 0, data, 4, header.Length);

        ResourceCursorInfo info = PECOFF.TryParseCursorResourceForTest(data);

        Assert.NotNull(info);
        Assert.Equal((ushort)2, info.HotspotX);
        Assert.Equal((ushort)3, info.HotspotY);
        Assert.Equal(16, info.Width);
        Assert.Equal(16, info.Height);
        Assert.Equal((ushort)8, info.BitCount);
    }

    private static byte[] BuildBitmapInfoHeader(int width, int height, ushort bitCount)
    {
        byte[] data = new byte[40];
        using MemoryStream stream = new MemoryStream(data);
        using BinaryWriter writer = new BinaryWriter(stream);
        writer.Write(40u); // header size
        writer.Write(width);
        writer.Write(height);
        writer.Write((ushort)1); // planes
        writer.Write(bitCount);
        writer.Write(0u); // compression
        writer.Write(0u); // image size
        writer.Write(0u); // x ppm
        writer.Write(0u); // y ppm
        writer.Write(0u); // clr used
        writer.Write(0u); // clr important
        return data;
    }
}
