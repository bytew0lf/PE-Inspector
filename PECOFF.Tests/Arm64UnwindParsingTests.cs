using System;
using PECoff;
using Xunit;

public class Arm64UnwindParsingTests
{
    [Fact]
    public void Arm64UnwindInfo_Parses_Header_Fields()
    {
        ExceptionFunctionInfo func = new ExceptionFunctionInfo(0x1000, 0x1100, 0x2000);
        int functionLength = 2;
        byte version = 1;
        int epilogCount = 1;
        int codeWords = 1;
        uint header = (uint)(functionLength & 0x3FFFF);
        header |= (uint)(version << 18);
        header |= (uint)(epilogCount << 22);
        header |= (uint)(codeWords << 27);

        byte[] data = new byte[4 + (epilogCount * 4) + (codeWords * 4)];
        BitConverter.GetBytes(header).CopyTo(data, 0);
        BitConverter.GetBytes(0x00000001u).CopyTo(data, 4);
        data[8] = 0x00;
        data[9] = 0xE4;
        data[10] = 0xE3;
        data[11] = 0xE1;

        Arm64UnwindInfoDetail detail = PECOFF.BuildArm64UnwindInfoDetailForTest(func, data);
        Assert.NotNull(detail);
        Assert.Equal(header, detail.Header);
        Assert.Equal(functionLength * 4, detail.FunctionLengthBytes);
        Assert.False(detail.HasXFlag);
        Assert.False(detail.HasEpilogFlag);
        Assert.Equal(epilogCount, detail.EpilogCount);
        Assert.Equal(codeWords, detail.CodeWords);
        Assert.Equal(4 + (epilogCount * 4) + (codeWords * 4), detail.SizeBytes);
        Assert.Single(detail.EpilogScopes);
        Assert.True(detail.UnwindCodes.Count >= 4);
        Assert.Equal("alloc_s", detail.UnwindCodes[0].OpCode);
    }
}
