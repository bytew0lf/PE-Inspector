using PECoff;
using Xunit;

public class LoadConfigVersioningTests
{
    [Fact]
    public void LoadConfigVersionInfo_Reports_Base_Layout()
    {
        byte[] data = BuildLoadConfigBuffer(148);

        bool parsed = PECOFF.TryParseLoadConfigVersionInfoForTest(data, isPe32Plus: true, out LoadConfigVersionInfo info);

        Assert.True(parsed);
        Assert.NotNull(info);
        Assert.Equal(0u, info.TrailingBytes);
        Assert.Contains("Base", info.FieldGroups);
        Assert.Equal("pre-Win8", info.VersionHint);
    }

    [Fact]
    public void LoadConfigVersionInfo_Detects_Xfg_And_Trailing()
    {
        byte[] data = BuildLoadConfigBuffer(312);

        bool parsed = PECOFF.TryParseLoadConfigVersionInfoForTest(data, isPe32Plus: true, out LoadConfigVersionInfo info);

        Assert.True(parsed);
        Assert.NotNull(info);
        Assert.Contains("XFG", info.FieldGroups);
        Assert.True(info.TrailingBytes > 0);
        Assert.Contains("Win11", info.VersionHint);
        Assert.False(string.IsNullOrWhiteSpace(info.TrailingPreview));
    }

    private static byte[] BuildLoadConfigBuffer(int size)
    {
        byte[] data = new byte[size];
        BitConverter.GetBytes((uint)size).CopyTo(data, 0);
        for (int i = 4; i < data.Length; i++)
        {
            data[i] = (byte)(i & 0xFF);
        }

        return data;
    }
}
