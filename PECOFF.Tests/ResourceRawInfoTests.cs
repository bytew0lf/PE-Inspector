using System;
using System.Text;
using PECoff;
using Xunit;

public class ResourceRawInfoTests
{
    [Fact]
    public void RawResource_Builds_Hash_And_Preview()
    {
        byte[] data = Encoding.ASCII.GetBytes("<html>test</html>");
        ResourceEntry entry = new ResourceEntry(23, "HTML", 1, "1", 0x0409, 0, 0, (uint)data.Length, 0);

        ResourceRawInfo info = PECOFF.BuildResourceRawInfoForTest(entry, data);
        Assert.NotNull(info);
        Assert.Equal((uint)data.Length, info.Size);
        Assert.True(info.IsText);
        Assert.Contains("html", info.Preview, StringComparison.OrdinalIgnoreCase);
        Assert.False(string.IsNullOrWhiteSpace(info.Sha256));
    }
}
