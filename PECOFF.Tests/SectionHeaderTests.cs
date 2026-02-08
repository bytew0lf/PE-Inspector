using System;
using PECoff;
using Xunit;

public class SectionHeaderTests
{
    [Fact]
    public void SectionHeader_Computes_Padding_And_Alignment()
    {
        const uint MemRead = 0x40000000;
        const uint MemWrite = 0x80000000;
        const uint MemExecute = 0x20000000;
        const uint CntCode = 0x00000020;

        SectionHeaderInfo info = PECOFF.BuildSectionHeaderInfoForTest(
            name: ".text",
            index: 0,
            virtualAddress: 0x1000,
            virtualSize: 0x1000,
            rawPointer: 0x400,
            rawSize: 0x600,
            characteristics: MemRead | MemWrite | MemExecute | CntCode,
            fileAlignment: 0x200,
            sectionAlignment: 0x1000,
            fileLength: 0x3000);

        Assert.True(info.RawPointerAligned);
        Assert.True(info.RawSizeAligned);
        Assert.True(info.VirtualAddressAligned);
        Assert.Equal((uint)0xA00, info.VirtualPadding);
        Assert.Equal(0u, info.RawPadding);
        Assert.True(info.HasSizeMismatch);
        Assert.True(info.HasSuspiciousPermissions);
        Assert.True(info.RawDataInFileBounds);
    }

    [Fact]
    public void SectionHeader_Detects_OutOfBounds_RawData()
    {
        SectionHeaderInfo info = PECOFF.BuildSectionHeaderInfoForTest(
            name: ".rdata",
            index: 1,
            virtualAddress: 0x2000,
            virtualSize: 0x200,
            rawPointer: 0x2800,
            rawSize: 0x400,
            characteristics: 0,
            fileAlignment: 0x200,
            sectionAlignment: 0x1000,
            fileLength: 0x2A00);

        Assert.False(info.RawDataInFileBounds);
    }
}
