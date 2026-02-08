using PECoff;
using Xunit;

public class DataDirectoryValidationTests
{
    [Fact]
    public void Validation_Flags_SizeAlignment()
    {
        DataDirectoryValidationInfo validation = PECOFF.BuildDataDirectoryValidationForTest(
            index: 1,
            virtualAddress: 0x1100,
            size: 0x30,
            isPe32Plus: false,
            startMapped: true,
            sectionRva: 0x1000,
            sectionSize: 0x200,
            sectionName: ".text");

        Assert.True(validation.IsMapped);
        Assert.True(validation.IsFullyMapped);
        Assert.False(validation.SizeAligned);
        Assert.True(validation.SizePlausible);
        Assert.Contains("size not aligned", validation.Notes);
    }

    [Fact]
    public void Validation_Flags_Security_UsesFileOffset()
    {
        DataDirectoryValidationInfo validation = PECOFF.BuildDataDirectoryValidationForTest(
            index: 4,
            virtualAddress: 0x2000,
            size: 0x200,
            isPe32Plus: false,
            startMapped: false,
            sectionRva: 0,
            sectionSize: 0,
            sectionName: string.Empty);

        Assert.True(validation.UsesFileOffset);
        Assert.False(validation.IsMapped);
        Assert.Contains("uses file offset", validation.Notes);
    }

    [Fact]
    public void Validation_Flags_SizeBelowMinimum()
    {
        DataDirectoryValidationInfo validation = PECOFF.BuildDataDirectoryValidationForTest(
            index: 6,
            virtualAddress: 0x3000,
            size: 8,
            isPe32Plus: false,
            startMapped: true,
            sectionRva: 0x3000,
            sectionSize: 0x80,
            sectionName: ".rdata");

        Assert.False(validation.SizePlausible);
        Assert.Equal((uint)28, validation.MinimumSize);
        Assert.Contains("size below minimum", validation.Notes);
    }
}
