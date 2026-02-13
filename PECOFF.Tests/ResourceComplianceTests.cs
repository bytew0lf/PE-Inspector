using System;
using PECoff;
using Xunit;

public class ResourceComplianceTests
{
    [Fact]
    public void ResourceDirectory_Detects_OutOfOrder_NamedEntries()
    {
        byte[] data = new byte[0x90];

        WriteDirectoryHeader(data, 0x00, namedEntries: 2, idEntries: 0);
        WriteDirectoryEntry(data, 0x10, 0x80000040u, 0x00000060u); // "B"
        WriteDirectoryEntry(data, 0x18, 0x80000050u, 0x00000070u); // "A"
        WriteResourceName(data, 0x40, "B");
        WriteResourceName(data, 0x50, "A");
        WriteDataEntry(data, 0x60);
        WriteDataEntry(data, 0x70);

        string[] issues = PECOFF.ValidateResourceDirectoryForTest(data, allowDeepTree: false);

        Assert.Contains(issues, issue => issue.Contains("named entries are out of order", StringComparison.Ordinal));
    }

    [Fact]
    public void ResourceDirectory_Detects_OutOfOrder_IdEntries()
    {
        byte[] data = new byte[0x80];

        WriteDirectoryHeader(data, 0x00, namedEntries: 0, idEntries: 2);
        WriteDirectoryEntry(data, 0x10, 2u, 0x00000040u);
        WriteDirectoryEntry(data, 0x18, 1u, 0x00000050u);
        WriteDataEntry(data, 0x40);
        WriteDataEntry(data, 0x50);

        string[] issues = PECOFF.ValidateResourceDirectoryForTest(data, allowDeepTree: false);

        Assert.Contains(issues, issue => issue.Contains("ID entries are out of order", StringComparison.Ordinal));
    }

    [Fact]
    public void ResourceDirectory_DeepTree_Validation_Is_Optional()
    {
        byte[] data = BuildDeepResourceTree();

        string[] strictDepthIssues = PECOFF.ValidateResourceDirectoryForTest(data, allowDeepTree: false);
        Assert.Contains(strictDepthIssues, issue => issue.Contains("depth exceeded", StringComparison.Ordinal));

        string[] deepTreeIssues = PECOFF.ValidateResourceDirectoryForTest(data, allowDeepTree: true);
        Assert.DoesNotContain(deepTreeIssues, issue => issue.Contains("depth exceeded", StringComparison.Ordinal));
    }

    [Fact]
    public void ResourceDirectory_Detects_Circular_References()
    {
        byte[] data = new byte[0x40];
        WriteDirectoryHeader(data, 0x00, namedEntries: 0, idEntries: 1);
        WriteDirectoryEntry(data, 0x10, 1u, 0x80000000u); // points to root

        string[] issues = PECOFF.ValidateResourceDirectoryForTest(data, allowDeepTree: true);

        Assert.Contains(issues, issue => issue.Contains("circular reference", StringComparison.Ordinal));
    }

    [Fact]
    public void ResourceDirectory_Detects_Malformed_EntryCount()
    {
        byte[] data = new byte[0x20];
        WriteDirectoryHeader(data, 0x00, namedEntries: 0, idEntries: 4); // too many for buffer
        WriteDirectoryEntry(data, 0x10, 1u, 0x00000018u);

        string[] issues = PECOFF.ValidateResourceDirectoryForTest(data, allowDeepTree: false);

        Assert.Contains(issues, issue => issue.Contains("entry count exceeds available data", StringComparison.Ordinal));
    }

    [Fact]
    public void ResourceDirectory_Detects_NonZero_DirectoryCharacteristics()
    {
        byte[] data = new byte[0x40];
        WriteUInt32(data, 0x00, 1u); // Characteristics must be 0
        WriteDirectoryHeader(data, 0x00, namedEntries: 0, idEntries: 1);
        WriteDirectoryEntry(data, 0x10, 1u, 0x00000020u);
        WriteDataEntry(data, 0x20);

        string[] issues = PECOFF.ValidateResourceDirectoryForTest(data, allowDeepTree: false);

        Assert.Contains(
            issues,
            issue => issue.Contains("IMAGE_RESOURCE_DIRECTORY.Characteristics is reserved and must be 0", StringComparison.Ordinal));
    }

    [Fact]
    public void ResourceDirectory_Detects_NonZero_IdEntryReservedHighBits()
    {
        byte[] data = new byte[0x40];
        WriteDirectoryHeader(data, 0x00, namedEntries: 0, idEntries: 1);
        WriteDirectoryEntry(data, 0x10, 0x00010001u, 0x00000020u); // high bits must be 0 for ID entries
        WriteDataEntry(data, 0x20);

        string[] issues = PECOFF.ValidateResourceDirectoryForTest(data, allowDeepTree: false);

        Assert.Contains(
            issues,
            issue => issue.Contains("Resource directory ID entry uses non-zero reserved high bits", StringComparison.Ordinal));
    }

    [Fact]
    public void ResourceDirectory_Detects_NonZero_DataEntryReserved()
    {
        byte[] data = new byte[0x40];
        WriteDirectoryHeader(data, 0x00, namedEntries: 0, idEntries: 1);
        WriteDirectoryEntry(data, 0x10, 1u, 0x00000020u);
        WriteDataEntry(data, 0x20);
        WriteUInt32(data, 0x20 + 12, 1u); // Reserved must be 0

        string[] issues = PECOFF.ValidateResourceDirectoryForTest(data, allowDeepTree: false);

        Assert.Contains(
            issues,
            issue => issue.Contains("IMAGE_RESOURCE_DATA_ENTRY.Reserved must be 0", StringComparison.Ordinal));
    }

    private static byte[] BuildDeepResourceTree()
    {
        byte[] data = new byte[0x140];

        // level 0 -> 1
        WriteDirectoryHeader(data, 0x00, namedEntries: 0, idEntries: 1);
        WriteDirectoryEntry(data, 0x10, 1u, 0x80000040u);

        // level 1 -> 2
        WriteDirectoryHeader(data, 0x40, namedEntries: 0, idEntries: 1);
        WriteDirectoryEntry(data, 0x50, 2u, 0x80000080u);

        // level 2 -> 3
        WriteDirectoryHeader(data, 0x80, namedEntries: 0, idEntries: 1);
        WriteDirectoryEntry(data, 0x90, 0x0409u, 0x800000C0u);

        // level 3 -> data
        WriteDirectoryHeader(data, 0xC0, namedEntries: 0, idEntries: 1);
        WriteDirectoryEntry(data, 0xD0, 0x0411u, 0x00000100u);
        WriteDataEntry(data, 0x100);

        return data;
    }

    private static void WriteDirectoryHeader(byte[] data, int offset, ushort namedEntries, ushort idEntries)
    {
        // IMAGE_RESOURCE_DIRECTORY: skip first 12 bytes, then counts
        WriteUInt16(data, offset + 12, namedEntries);
        WriteUInt16(data, offset + 14, idEntries);
    }

    private static void WriteDirectoryEntry(byte[] data, int offset, uint nameOrId, uint dataOrSubdir)
    {
        WriteUInt32(data, offset, nameOrId);
        WriteUInt32(data, offset + 4, dataOrSubdir);
    }

    private static void WriteResourceName(byte[] data, int offset, string value)
    {
        value ??= string.Empty;
        WriteUInt16(data, offset, (ushort)value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            WriteUInt16(data, offset + 2 + (i * 2), value[i]);
        }
    }

    private static void WriteDataEntry(byte[] data, int offset)
    {
        // IMAGE_RESOURCE_DATA_ENTRY
        WriteUInt32(data, offset, 0x2000u); // DataRva
        WriteUInt32(data, offset + 4, 0x10u); // Size
        WriteUInt32(data, offset + 8, 0u); // CodePage
        WriteUInt32(data, offset + 12, 0u); // Reserved
    }

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)((value >> 16) & 0xFF);
        data[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
