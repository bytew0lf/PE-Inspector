using PECoff;
using Xunit;

public class ResourceLocaleCoverageTests
{
    [Fact]
    public void LocaleCoverage_Reports_MissingNeutralFallback()
    {
        ResourceLocaleCoverageInfo coverage = PECOFF.BuildResourceLocaleCoverageForTest("StringTable", 0x0409, 0x0411);
        Assert.True(coverage.HasLocalizedLanguage);
        Assert.False(coverage.HasNeutralLanguage);
        Assert.True(coverage.MissingNeutralFallback);
    }

    [Fact]
    public void LocaleCoverage_WithNeutral_Is_Not_Missing()
    {
        ResourceLocaleCoverageInfo coverage = PECOFF.BuildResourceLocaleCoverageForTest("Manifest", 0x0000, 0x0409);
        Assert.True(coverage.HasLocalizedLanguage);
        Assert.True(coverage.HasNeutralLanguage);
        Assert.False(coverage.MissingNeutralFallback);
    }
}
