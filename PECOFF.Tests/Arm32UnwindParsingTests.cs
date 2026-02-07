using System;
using PECoff;
using Xunit;

public class Arm32UnwindParsingTests
{
    [Fact]
    public void Arm32UnwindInfo_Parses_Header_And_CodeWords()
    {
        ExceptionFunctionInfo func = new ExceptionFunctionInfo(0x1000, 0x1100, 0x2000);
        int functionLength = 2;
        byte version = 1;
        int epilogCount = 1;
        int codeWords = 1;
        uint header = (uint)(functionLength & 0x7FF);
        header |= (uint)(version << 11);
        header |= (uint)(epilogCount << 16);
        header |= (uint)(codeWords << 21);

        byte[] data = new byte[4 + (epilogCount * 4) + (codeWords * 4)];
        BitConverter.GetBytes(header).CopyTo(data, 0);
        BitConverter.GetBytes(0x12345678u).CopyTo(data, 4);
        BitConverter.GetBytes(0x000000B0u).CopyTo(data, 8);

        Arm32UnwindInfoDetail detail = PECOFF.BuildArm32UnwindInfoDetailForTest(func, data);
        Assert.NotNull(detail);
        Assert.Equal(header, detail.Header);
        Assert.Equal(functionLength * 4, detail.FunctionLengthBytes);
        Assert.Equal(epilogCount, detail.EpilogCount);
        Assert.Equal(codeWords, detail.CodeWords);
        Assert.Single(detail.EpilogScopes);
        Assert.Single(detail.UnwindCodeWords);
        Assert.True(detail.OpcodeCount > 0);
        Assert.True(detail.HasFinishOpcode);
    }
}
