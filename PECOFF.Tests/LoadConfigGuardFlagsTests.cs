using PECoff;
using Xunit;

public class LoadConfigGuardFlagsTests
{
    [Fact]
    public void DecodeGuardFlags_Maps_Flags()
    {
        uint flags = 0x00000100 | 0x00000400 | 0x00001000;
        LoadConfigGuardFlagsInfo info = PECOFF.DecodeGuardFlagsForTest(flags);

        Assert.True(info.CfInstrumented);
        Assert.True(info.CfFunctionTablePresent);
        Assert.True(info.ProtectDelayLoadIat);
        Assert.Contains("IMAGE_GUARD_CF_INSTRUMENTED", info.Flags);
        Assert.Contains("IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT", info.Flags);
    }
}
