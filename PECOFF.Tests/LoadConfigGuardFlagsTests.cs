using PECoff;
using Xunit;

public class LoadConfigGuardFlagsTests
{
    [Fact]
    public void DecodeGuardFlags_Maps_Flags()
    {
        uint flags = 0x00000100 | 0x00000400 | 0x00001000 | 0x00800000 | 0x01000000;
        LoadConfigGuardFlagsInfo info = PECOFF.DecodeGuardFlagsForTest(flags);

        Assert.True(info.CfInstrumented);
        Assert.True(info.CfFunctionTablePresent);
        Assert.True(info.ProtectDelayLoadIat);
        Assert.True(info.XfgEnabled);
        Assert.True(info.XfgTablePresent);
        Assert.Contains("IMAGE_GUARD_CF_INSTRUMENTED", info.Flags);
        Assert.Contains("IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT", info.Flags);
        Assert.Contains("IMAGE_GUARD_XFG_ENABLED", info.Flags);
        Assert.Contains("IMAGE_GUARD_XFG_TABLE_PRESENT", info.Flags);
    }
}
