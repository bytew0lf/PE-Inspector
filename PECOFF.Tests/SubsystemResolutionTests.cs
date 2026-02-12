using PECoff;
using Xunit;

public class SubsystemResolutionTests
{
    [Fact]
    public void Subsystem_BootApplication_Is_Mapped()
    {
        SubsystemInfo info = PECOFF.BuildSubsystemInfoForTest(16);
        Assert.Equal((ushort)16, info.Value);
        Assert.Equal("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", info.Name);
        Assert.False(info.IsGui);
        Assert.False(info.IsConsole);
    }

    [Fact]
    public void Subsystem_Unknown_Value_Is_Reported_As_Unknown()
    {
        SubsystemInfo info = PECOFF.BuildSubsystemInfoForTest(0xFFFF);
        Assert.Equal("Unknown", info.Name);
    }
}
