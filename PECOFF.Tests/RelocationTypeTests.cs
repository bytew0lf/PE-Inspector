using PECoff;
using Xunit;

public class RelocationTypeTests
{
    [Theory]
    [InlineData(11, "HIGH3ADJ")]
    [InlineData(12, "ARM_MOV32")]
    [InlineData(13, "RISCV_HIGH20")]
    [InlineData(14, "RISCV_LOW12I")]
    [InlineData(15, "RISCV_LOW12S")]
    public void BaseRelocation_Type_Names_Extended(int type, string expected)
    {
        string name = PECOFF.GetRelocationTypeNameForTest(type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData(8, true)]
    [InlineData(12, false)]
    [InlineData(10, false)]
    [InlineData(31, true)]
    public void BaseRelocation_Reserved_Detection(int type, bool expected)
    {
        bool reserved = PECOFF.IsRelocationTypeReservedForTest(type);
        Assert.Equal(expected, reserved);
    }
}
