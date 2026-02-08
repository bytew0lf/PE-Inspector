using PECoff;
using Xunit;

public class CoffRelocationTypeTests
{
    [Theory]
    [InlineData((ushort)0x01C2, (ushort)0x000C, "THUMB_BRANCH20")] // THUMB
    [InlineData((ushort)0xA641, (ushort)0x000E, "ADDR64")] // ARM64EC
    public void CoffRelocationTypeName_Maps_Additional_Machines(ushort machine, ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest(machine, type);
        Assert.Equal(expected, name);
    }
}
