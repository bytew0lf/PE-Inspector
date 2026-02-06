using PECoff;
using Xunit;

public class LoadConfigGlobalFlagsTests
{
    [Fact]
    public void DecodeGlobalFlags_ReturnsKnownFlags()
    {
        uint flags = 0x00000010 | 0x00000100;
        LoadConfigGlobalFlagsInfo info = PECOFF.DecodeGlobalFlagsForTest(0, flags);

        Assert.Equal(flags, info.Value);
        Assert.Contains("FLG_HEAP_ENABLE_TAIL_CHECK", info.Flags);
        Assert.Contains("FLG_APPLICATION_VERIFIER", info.Flags);
    }
}
