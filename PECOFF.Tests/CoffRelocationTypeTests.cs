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
    [InlineData((ushort)0x000A, "REL32")]
    [InlineData((ushort)0x000B, "BLX24")]
    [InlineData((ushort)0x000C, "BLX11")]
    [InlineData((ushort)0x000D, "TOKEN")]
    [InlineData((ushort)0x000E, "SECTION")]
    [InlineData((ushort)0x000F, "SECREL")]
    [InlineData((ushort)0x0010, "ARM_MOV32")]
    [InlineData((ushort)0x0011, "THUMB_MOV32")]
    [InlineData((ushort)0x0012, "THUMB_BRANCH20")]
    [InlineData((ushort)0x0013, "UNUSED")]
    [InlineData((ushort)0x0014, "THUMB_BRANCH24")]
    [InlineData((ushort)0x0015, "THUMB_BLX23")]
    [InlineData((ushort)0x0016, "PAIR")]
    public void CoffRelocationTypeName_ArmTable_Matches_Spec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x01C2, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x01C2, (ushort)0x0010, "ARM_MOV32")] // THUMB
    [InlineData((ushort)0x01C2, (ushort)0x0011, "THUMB_MOV32")] // THUMB
    [InlineData((ushort)0x01C2, (ushort)0x0012, "THUMB_BRANCH20")] // THUMB
    [InlineData((ushort)0x01C2, (ushort)0x0014, "THUMB_BRANCH24")] // THUMB
    [InlineData((ushort)0x01C2, (ushort)0x0015, "THUMB_BLX23")] // THUMB
    [InlineData((ushort)0xA641, (ushort)0x000E, "ADDR64")] // ARM64EC
    public void CoffRelocationTypeName_Maps_Additional_Machines(ushort machine, ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest(machine, type);
        Assert.Equal(expected, name);
    }

    [Fact]
    public void CoffRelocationTypeName_Uses_Unknown_Fallback_For_Undefined_Arm_Values()
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x01C2, (ushort)0x0008);
        Assert.Equal("TYPE_0x0008", name);
    }
}
