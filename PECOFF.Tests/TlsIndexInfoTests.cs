using System;
using PECoff;
using Xunit;

public class TlsIndexInfoTests
{
    [Fact]
    public void TlsIndexInfo_Maps_And_Reads_Value()
    {
        TlsIndexInfo info = PECOFF.BuildTlsIndexInfoForTest(
            address: 0x1000,
            rva: 0x200,
            hasRva: true,
            isMapped: true,
            sectionName: ".tls",
            sectionRva: 0x200,
            sectionOffset: 0x10,
            hasValue: true,
            value: 7);

        Assert.True(info.HasRva);
        Assert.True(info.IsMapped);
        Assert.True(info.HasValue);
        Assert.Equal((uint)7, info.Value);
        Assert.True(string.IsNullOrWhiteSpace(info.Notes));
    }

    [Fact]
    public void TlsIndexInfo_Notes_Unmapped_And_Unreadable()
    {
        TlsIndexInfo info = PECOFF.BuildTlsIndexInfoForTest(
            address: 0x1000,
            rva: 0x200,
            hasRva: true,
            isMapped: false,
            sectionName: string.Empty,
            sectionRva: 0,
            sectionOffset: 0,
            hasValue: false,
            value: 0);

        Assert.Contains("index RVA not mapped", info.Notes, StringComparison.Ordinal);
        Assert.Contains("index value not readable", info.Notes, StringComparison.Ordinal);
    }
}
