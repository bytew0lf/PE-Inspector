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
}
