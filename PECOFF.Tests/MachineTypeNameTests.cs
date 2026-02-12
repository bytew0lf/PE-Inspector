using PECoff;
using Xunit;

public class MachineTypeNameTests
{
    [Theory]
    [InlineData((ushort)0x0001, "TARGET_HOST")]
    [InlineData((ushort)0x0160, "R3000BE")]
    [InlineData((ushort)0x0520, "TRICORE")]
    [InlineData((ushort)0x0CEF, "CEF")]
    [InlineData((ushort)0x3A64, "CHPE_X86")]
    public void MachineName_Resolves_Documented_Constants(ushort machine, string expected)
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
