using PECoff;
using Xunit;

public class SectionPaddingTests
{
    [Fact]
    public void AnalyzeSectionPadding_Detects_NonZero_Gaps_And_Slack()
    {
        byte[] data = new byte[100];
        for (int i = 20; i < 30; i++)
        {
            data[i] = 0xAA;
        }
        for (int i = 30; i < 50; i++)
        {
            data[i] = 0xBB;
        }

        SectionRange[] sections =
        {
            new SectionRange("A", 0x1000, 10, 10, 20),
            new SectionRange("B", 0x2000, 10, 50, 10)
        };

        PECOFF.AnalyzeSectionPaddingForTest(data, sections, 10, out SectionGapInfo[] gaps, out SectionSlackInfo[] slacks);

        Assert.Single(slacks);
        Assert.Equal("A", slacks[0].SectionName);
        Assert.True(slacks[0].NonZeroCount > 0);

        Assert.Single(gaps);
        Assert.Equal("A", gaps[0].PreviousSection);
        Assert.Equal("B", gaps[0].NextSection);
        Assert.True(gaps[0].NonZeroCount > 0);
    }
}
