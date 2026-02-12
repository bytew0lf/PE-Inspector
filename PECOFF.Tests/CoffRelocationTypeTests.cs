using PECoff;
using Xunit;

public class CoffRelocationTypeTests
{
    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "ADDR32")]
    [InlineData((ushort)0x0002, "ADDR32NB")]
    [InlineData((ushort)0x0003, "BRANCH24")]
    [InlineData((ushort)0x0004, "BRANCH11")]
    [InlineData((ushort)0x0005, "TOKEN")]
    [InlineData((ushort)0x0006, "BLX24")]
    [InlineData((ushort)0x0007, "BLX11")]
    [InlineData((ushort)0x0008, "SECTION")]
    [InlineData((ushort)0x0009, "SECREL")]
    [InlineData((ushort)0x000A, "MOV32A")]
    [InlineData((ushort)0x000B, "MOV32T")]
    [InlineData((ushort)0x000C, "BRANCH20T")]
    [InlineData((ushort)0x000D, "BRANCH24T")]
    [InlineData((ushort)0x000E, "BLX23T")]
    public void CoffRelocationTypeName_ArmTable_Matches_Spec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x01C2, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x01C2, (ushort)0x000A, "MOV32A")] // THUMB
    [InlineData((ushort)0x01C2, (ushort)0x000B, "MOV32T")] // THUMB
    [InlineData((ushort)0x01C2, (ushort)0x000C, "BRANCH20T")] // THUMB
    [InlineData((ushort)0x01C2, (ushort)0x000D, "BRANCH24T")] // THUMB
    [InlineData((ushort)0x01C2, (ushort)0x000E, "BLX23T")] // THUMB
    [InlineData((ushort)0xA641, (ushort)0x000E, "ADDR64")] // ARM64EC
    public void CoffRelocationTypeName_Maps_Additional_Machines(ushort machine, ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest(machine, type);
        Assert.Equal(expected, name);
    }

    [Fact]
    public void CoffRelocationTypeName_Uses_Unknown_Fallback_For_Undefined_Arm_Values()
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x01C2, (ushort)0x0010);
        Assert.Equal("TYPE_0x0010", name);
    }
}
