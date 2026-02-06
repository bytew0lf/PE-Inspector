using PECoff;
using Xunit;

public class ExportAnomalyTests
{
    [Fact]
    public void ExportAnomalies_Report_Duplicates_And_OutOfRange()
    {
        ExportEntry[] entries = new[]
        {
            new ExportEntry("Foo", 1, 0, false, string.Empty),
            new ExportEntry("Foo", 2, 0, false, string.Empty),
            new ExportEntry("Bar", 1, 0, false, string.Empty)
        };

        ExportAnomalySummary summary = PECOFF.ComputeExportAnomaliesForTest(entries, 2);

        Assert.Equal(1, summary.DuplicateNameCount);
        Assert.Equal(1, summary.DuplicateOrdinalCount);
        Assert.Equal(2, summary.OrdinalOutOfRangeCount);
    }
}
