using System.IO;
using PECoff;
using Xunit;

public class UnwindEdgeCaseTests
{
    [Fact]
    public void Arm64UnwindInfo_ReservedBits_AreDetected()
    {
        ExceptionFunctionInfo func = new ExceptionFunctionInfo(0x1000, 0x1100, 0x2000);
        uint header = 0;
        header |= 4u; // function length (words)
        header |= (1u << 22); // epilog count
        header |= (1u << 27); // code words

        byte[] data = new byte[12];
        using (MemoryStream stream = new MemoryStream(data))
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(header);
            uint scope = (1u << 18); // reserved bits set
            writer.Write(scope);
            writer.Write(0u);
        }

        Arm64UnwindInfoDetail detail = PECOFF.BuildArm64UnwindInfoDetailForTest(func, data);
        Assert.NotNull(detail);
        Assert.Single(detail.EpilogScopes);
        Assert.False(detail.EpilogScopes[0].ReservedBitsValid);
    }

    [Fact]
    public void Arm32UnwindInfo_ReservedBits_AreDetected()
    {
        ExceptionFunctionInfo func = new ExceptionFunctionInfo(0x1000, 0x1100, 0x2000);
        uint header = 0;
        header |= (0x3Fu << 26);

        byte[] data = new byte[4];
        using (MemoryStream stream = new MemoryStream(data))
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(header);
        }

        Arm32UnwindInfoDetail detail = PECOFF.BuildArm32UnwindInfoDetailForTest(func, data);
        Assert.NotNull(detail);
        Assert.False(detail.ReservedBitsValid);
    }
}
