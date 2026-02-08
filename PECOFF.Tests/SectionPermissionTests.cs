using System;
using PECoff;
using Xunit;

public class SectionPermissionTests
{
    [Fact]
    public void SectionPermission_Decode_Flags_Sets_RWXSuspicious()
    {
        const uint MemExecute = 0x20000000;
        const uint MemRead = 0x40000000;
        const uint MemWrite = 0x80000000;
        const uint CntCode = 0x00000020;

        uint flags = MemExecute | MemRead | MemWrite | CntCode;
        SectionPermissionInfo info = PECOFF.DecodeSectionPermissionsForTest(flags);

        Assert.True(info.IsReadable);
        Assert.True(info.IsWritable);
        Assert.True(info.IsExecutable);
        Assert.True(info.IsCode);
        Assert.True(info.HasSuspiciousPermissions);
        Assert.False(info.HasMismatch);
        Assert.Contains(info.Flags, name => string.Equals(name, "MEM_EXECUTE", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SectionPermission_Decode_Flags_Includes_Alignment_And_Comdat()
    {
        const uint Align16 = 0x00500000;
        const uint LnkComdat = 0x00001000;
        const uint MemRead = 0x40000000;

        uint flags = Align16 | LnkComdat | MemRead;
        SectionPermissionInfo info = PECOFF.DecodeSectionPermissionsForTest(flags);

        Assert.Contains(info.Flags, name => string.Equals(name, "ALIGN_16", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(info.Flags, name => string.Equals(name, "LNK_COMDAT", StringComparison.OrdinalIgnoreCase));
        Assert.True(info.IsReadable);
    }
}
