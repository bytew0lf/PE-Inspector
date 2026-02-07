using System;
using PECoff;
using Xunit;

public class Ia64UnwindParsingTests
{
    [Fact]
    public void Ia64UnwindInfo_Parses_Header()
    {
        ExceptionFunctionInfo func = new ExceptionFunctionInfo(0x1000, 0x1200, 0x3000);
        uint header = 0xAABBCCDDu;

        byte[] data = new byte[16];
        BitConverter.GetBytes(header).CopyTo(data, 0);
        for (int i = 4; i < data.Length; i++)
        {
            data[i] = (byte)(i + 1);
        }

        Ia64UnwindInfoDetail detail = PECOFF.BuildIa64UnwindInfoDetailForTest(func, data);
        Assert.NotNull(detail);
        Assert.Equal(header, detail.Header);
        Assert.Equal(16, detail.SizeBytes);
        Assert.Equal((byte)(header & 0x07), detail.Version);
        Assert.Equal((byte)((header >> 3) & 0x1F), detail.Flags);
        Assert.True(detail.DescriptorCount >= 1);
        Assert.False(string.IsNullOrWhiteSpace(detail.RawPreview));
    }
}
