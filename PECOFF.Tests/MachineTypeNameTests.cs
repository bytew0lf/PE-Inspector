using PECoff;
using Xunit;

public class MachineTypeNameTests
{
    [Theory]
    [InlineData((ushort)0x0000, "IMAGE_FILE_MACHINE_UNKNOWN")]
    [InlineData((ushort)0x0001, "TARGET_HOST")]
    [InlineData((ushort)0x014C, "x86")]
    [InlineData((ushort)0x0160, "R3000BE")]
    [InlineData((ushort)0x0162, "R3000")]
    [InlineData((ushort)0x0166, "R4000")]
    [InlineData((ushort)0x0168, "R10000")]
    [InlineData((ushort)0x0169, "IMAGE_FILE_MACHINE_WCEMIPSV2")]
    [InlineData((ushort)0x0184, "ALPHA")]
    [InlineData((ushort)0x01A2, "IMAGE_FILE_MACHINE_SH3")]
    [InlineData((ushort)0x01A3, "IMAGE_FILE_MACHINE_SH3DSP")]
    [InlineData((ushort)0x01A4, "SH3E")]
    [InlineData((ushort)0x01A6, "IMAGE_FILE_MACHINE_SH4")]
    [InlineData((ushort)0x01A8, "IMAGE_FILE_MACHINE_SH5")]
    [InlineData((ushort)0x01C0, "ARM")]
    [InlineData((ushort)0x01C2, "Thumb")]
    [InlineData((ushort)0x01C4, "ARMNT")]
    [InlineData((ushort)0x01D3, "IMAGE_FILE_MACHINE_AM33")]
    [InlineData((ushort)0x01F0, "PowerPC")]
    [InlineData((ushort)0x01F1, "PowerPCFP")]
    [InlineData((ushort)0x0200, "IA64")]
    [InlineData((ushort)0x0266, "MIPS16")]
    [InlineData((ushort)0x0284, "ALPHA64 (AXP64)")]
    [InlineData((ushort)0x0366, "MIPSFPU")]
    [InlineData((ushort)0x0466, "MIPSFPU16")]
    [InlineData((ushort)0x0520, "TRICORE")]
    [InlineData((ushort)0x0CEF, "CEF")]
    [InlineData((ushort)0x0EBC, "EBC")]
    [InlineData((ushort)0x3A64, "CHPE_X86")]
    [InlineData((ushort)0x5032, "RISC-V32")]
    [InlineData((ushort)0x5064, "RISC-V64")]
    [InlineData((ushort)0x5128, "RISC-V128")]
    [InlineData((ushort)0x6232, "LoongArch32")]
    [InlineData((ushort)0x6264, "LoongArch64")]
    [InlineData((ushort)0x8664, "x64")]
    [InlineData((ushort)0x9041, "IMAGE_FILE_MACHINE_M32R")]
    [InlineData((ushort)0xA641, "ARM64EC")]
    [InlineData((ushort)0xA64E, "ARM64X")]
    [InlineData((ushort)0xAA64, "ARM64")]
    [InlineData((ushort)0xC0EE, "CEE")]
    public void MachineName_Resolves_Documented_Constants(ushort machine, string expected)
    {
        string name = PECOFF.GetMachineNameForTest(machine);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x0184, "ALPHA")]
    [InlineData((ushort)0x0284, "ALPHA64 (AXP64)")]
    [InlineData((ushort)0xC0EE, "CEE")]
    public void MachineName_Resolves_Canonical_Alias_Targets(ushort machine, string expected)
    {
        string name = PECOFF.GetMachineNameForTest(machine);
        Assert.Equal(expected, name);
    }

    [Fact]
    public void MachineName_Unknown_FallsBack_ToHex()
    {
        string name = PECOFF.GetMachineNameForTest(0xDEAD);
        Assert.Equal("0xDEAD", name);
    }

    [Theory]
    [InlineData((ushort)0x0160, (ushort)0x000A, "SECTION")]
    [InlineData((ushort)0x0160, (ushort)0x0010, "JMPADDR16")]
    public void R3000BE_Uses_MipsRelocationMapping(ushort machine, ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest(machine, type);
        Assert.Equal(expected, name);
    }
}
