using PECoff;
using Xunit;

public class IconPngTests
{
    [Fact]
    public void TryParsePngIcon_Detects_IHDR_Dimensions()
    {
        byte[] pngData = new byte[]
        {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D,
            0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x20,
            0x00, 0x00, 0x00, 0x10
        };

        Assert.True(PECOFF.TryParsePngIconForTest(pngData, out uint width, out uint height));
        Assert.Equal(32u, width);
        Assert.Equal(16u, height);
    }
}
