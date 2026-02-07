using System.Linq;
using PECoff;
using Xunit;

public class ResourceStringCoverageTests
{
    [Fact]
    public void StringCoverage_Computes_Missing_Blocks_And_BestMatch()
    {
        ResourceStringTableInfo[] tables =
        {
            new ResourceStringTableInfo(1, 0x0409, new[] { "Hello", "" }),
            new ResourceStringTableInfo(3, 0x0409, new[] { "World" }),
            new ResourceStringTableInfo(1, 0x0411, new[] { "Test" })
        };

        ResourceStringCoverageInfo[] coverage = PECOFF.BuildResourceStringCoverageForTest(tables);

        Assert.Equal(2, coverage.Length);

        ResourceStringCoverageInfo en = coverage.Single(c => c.LanguageId == 0x0409);
        Assert.Equal(2, en.BlockCount);
        Assert.Equal(2, en.StringCount);
        Assert.Equal(1, en.MissingBlockCount);
        Assert.Contains((uint)2, en.MissingBlocks);
        Assert.True(en.IsBestMatch);

        ResourceStringCoverageInfo ja = coverage.Single(c => c.LanguageId == 0x0411);
        Assert.False(ja.IsBestMatch);
    }
}
