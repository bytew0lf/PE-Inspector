using System.Collections.Generic;
using PECoff;
using Xunit;

public class ExceptionDirectorySummaryTests
{
    [Fact]
    public void BuildExceptionDirectorySummary_Tracks_Ranges_And_Unwind()
    {
        ExceptionFunctionInfo[] functions =
        {
            new ExceptionFunctionInfo(0x100, 0x200, 0x300),
            new ExceptionFunctionInfo(0x500, 0x400, 0x600),
            new ExceptionFunctionInfo(0x1800, 0x2800, 0x700)
        };

        Dictionary<uint, byte[]> unwindInfo = new Dictionary<uint, byte[]>
        {
            [0x300] = new byte[] { 0x01 }
        };

        ExceptionDirectorySummary summary = PECOFF.BuildExceptionDirectorySummaryForTest(
            functions,
            0x2000,
            true,
            unwindInfo);

        Assert.Equal(3, summary.FunctionCount);
        Assert.Equal(1, summary.InvalidRangeCount);
        Assert.Equal(1, summary.OutOfRangeCount);
        Assert.Equal(1, summary.UnwindInfoCount);
        Assert.Single(summary.UnwindInfoVersions);
        Assert.Equal(1, summary.UnwindInfoVersions[0].Version);
        Assert.Equal(1, summary.UnwindInfoVersions[0].Count);
    }
}
