using PECoff;
using Xunit;

public class SectionDirectoryCoverageTests
{
    [Fact]
    public void SectionDirectory_Coverage_Builds_Map_And_Unmapped()
    {
        DataDirectoryInfo[] directories = new[]
        {
            new DataDirectoryInfo(0, "Export", 0x1000, 0x200, true, ".text", 0x1000, 0x600),
            new DataDirectoryInfo(1, "Import", 0x2000, 0x100, false, string.Empty, 0, 0)
        };

        string[] sections = { ".text", ".rdata" };
        SectionDirectoryInfo[] coverage = PECOFF.BuildSectionDirectoryCoverageForTest(directories, sections, out string[] unmapped);

        Assert.Equal(2, coverage.Length);
        Assert.Equal(".text", coverage[0].SectionName);
        Assert.Contains("Export", coverage[0].Directories);
        Assert.Equal(".rdata", coverage[1].SectionName);
        Assert.Empty(coverage[1].Directories);
        Assert.Single(unmapped);
        Assert.Equal("Import", unmapped[0]);
    }
}
