using PECoff;
using Xunit;

public class RelocationTypeTests
{
    [Theory]
    [InlineData((ushort)0x01C0, 5, "ARM_MOV32")] // ARM
    [InlineData((ushort)0x01C4, 7, "THUMB_MOV32")] // ARMNT
    [InlineData((ushort)0x01C2, 7, "THUMB_MOV32")] // THUMB
    [InlineData((ushort)0x5032, 5, "RISCV_HIGH20")] // RISCV32
    [InlineData((ushort)0x5064, 7, "RISCV_LOW12I")] // RISCV64
    [InlineData((ushort)0x5064, 8, "RISCV_LOW12S")] // RISCV64
    [InlineData((ushort)0x6264, 8, "LOONGARCH64_MARK_LA")] // LOONGARCH64
    public void BaseRelocation_Type_Names_Extended(ushort machine, int type, string expected)
    {
        string name = PECOFF.GetRelocationTypeNameForTest(machine, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x8664, 5, true)] // AMD64 + ARM/RISCV relocation
    [InlineData((ushort)0x5032, 5, false)] // RISCV32
    [InlineData((ushort)0x5064, 8, false)] // RISCV64
    [InlineData((ushort)0x6264, 8, false)] // LOONGARCH64
    [InlineData((ushort)0x014c, 8, true)] // x86 + reserved
    [InlineData((ushort)0x014c, 10, false)] // DIR64 known even if unusual
    public void BaseRelocation_Reserved_Detection(ushort machine, int type, bool expected)
    {
        bool reserved = PECOFF.IsRelocationTypeReservedForTest(machine, type);
        Assert.Equal(expected, reserved);
    }
}
