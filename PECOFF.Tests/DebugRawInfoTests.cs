using PECoff;
using Xunit;

public class DebugRawInfoTests
{
    [Fact]
    public void DebugRawInfo_Uses_Hash_And_Preview()
    {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        DebugRawInfo info = PECOFF.BuildDebugRawInfoForTest(data);

        Assert.NotNull(info);
        Assert.Equal((uint)data.Length, info.DataLength);
        Assert.Equal("01020304", info.Preview);
        Assert.False(string.IsNullOrWhiteSpace(info.Sha256));
    }
}
