using System;
using PECoff;
using Xunit;

public class Arm64UnwindParsingTests
{
    [Fact]
    public void Arm64UnwindInfo_Parses_Header_Fields()
    {
        ExceptionFunctionInfo func = new ExceptionFunctionInfo(0x1000, 0x1100, 0x2000);
        int functionLength = 4;
        byte version = 1;
        int epilogCount = 2;
        int codeWords = 3;
        uint header = (uint)(functionLength & 0x3FFFF);
        header |= (uint)(version << 18);
        header |= 1u << 20;
        header |= (uint)(epilogCount << 22);
        header |= (uint)(codeWords << 27);

        byte[] data = new byte[4 + (codeWords * 4)];
        BitConverter.GetBytes(header).CopyTo(data, 0);

        Arm64UnwindInfoDetail detail = PECOFF.BuildArm64UnwindInfoDetailForTest(func, data);
        Assert.NotNull(detail);
        Assert.Equal(header, detail.Header);
        Assert.Equal(functionLength * 4, detail.FunctionLengthBytes);
        Assert.True(detail.HasXFlag);
        Assert.False(detail.HasEpilogFlag);
        Assert.Equal(epilogCount, detail.EpilogCount);
        Assert.Equal(codeWords, detail.CodeWords);
        Assert.Equal(4 + (codeWords * 4), detail.SizeBytes);
    }
}
