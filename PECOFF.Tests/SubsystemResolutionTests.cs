using PECoff;
using Xunit;

public class SubsystemResolutionTests
{
    [Theory]
    [InlineData((ushort)0, "IMAGE_SUBSYSTEM_UNKNOWN", false, false)]
    [InlineData((ushort)1, "IMAGE_SUBSYSTEM_NATIVE", false, false)]
    [InlineData((ushort)2, "IMAGE_SUBSYSTEM_WINDOWS_GUI", true, false)]
    [InlineData((ushort)3, "IMAGE_SUBSYSTEM_WINDOWS_CUI", false, true)]
    [InlineData((ushort)5, "IMAGE_SUBSYSTEM_OS2_CUI", false, true)]
    [InlineData((ushort)7, "IMAGE_SUBSYSTEM_POSIX_CUI", false, true)]
    [InlineData((ushort)8, "IMAGE_SUBSYSTEM_NATIVE_WINDOWS", false, false)]
    [InlineData((ushort)9, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", true, false)]
    [InlineData((ushort)10, "IMAGE_SUBSYSTEM_EFI_APPLICATION", false, false)]
    [InlineData((ushort)11, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", false, false)]
    [InlineData((ushort)12, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", false, false)]
    [InlineData((ushort)13, "IMAGE_SUBSYSTEM_EFI_ROM", false, false)]
    [InlineData((ushort)14, "IMAGE_SUBSYSTEM_XBOX", false, false)]
    [InlineData((ushort)16, "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", false, false)]
    public void Subsystem_Documented_Values_Are_Mapped_With_Expected_Classification(
        ushort subsystem,
        string expectedName,
        bool expectedGui,
        bool expectedConsole)
    {
        SubsystemInfo info = PECOFF.BuildSubsystemInfoForTest(subsystem);
        Assert.Equal(subsystem, info.Value);
        Assert.Equal(expectedName, info.Name);
        Assert.Equal(expectedGui, info.IsGui);
        Assert.Equal(expectedConsole, info.IsConsole);
    }

    [Fact]
    public void Subsystem_Unknown_Value_Is_Reported_As_Unknown()
    {
        SubsystemInfo info = PECOFF.BuildSubsystemInfoForTest(0xFFFF);
        Assert.Equal("Unknown", info.Name);
    }
}
