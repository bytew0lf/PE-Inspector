using PECoff;
using Xunit;

public class UnwindInfoDetailTests
{
    [Fact]
    public void BuildUnwindInfoDetail_Parses_Header_And_Codes()
    {
        ExceptionFunctionInfo func = new ExceptionFunctionInfo(0x1000, 0x1100, 0x2000);
        byte[] data = new byte[]
        {
            0x01, // version=1, flags=0
            0x20, // prolog size
            0x02, // code count
            0x23, // frame reg=3, frame offset=2
            0x10, 0x01,
            0x08, 0x21
        };

        UnwindInfoDetail detail = PECOFF.BuildUnwindInfoDetailForTest(func, data);
        Assert.NotNull(detail);
        Assert.Equal((byte)1, detail.Version);
        Assert.Equal((byte)0, detail.Flags);
        Assert.Equal((byte)0x20, detail.PrologSize);
        Assert.Equal((byte)2, detail.CodeCount);
        Assert.Equal((byte)3, detail.FrameRegister);
        Assert.Equal((byte)2, detail.FrameOffset);
        Assert.Equal(2, detail.UnwindCodes.Count);
        Assert.False(detail.PrologSizeExceedsFunction);
    }
}
