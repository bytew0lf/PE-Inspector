using System.Linq;
using PECoff;
using Xunit;

public class ExportForwarderTests
{
    [Fact]
    public void ResolveExportForwarders_Builds_Chain()
    {
        ExportEntry[] entries =
        {
            new ExportEntry("A", 1, 0, true, "testdll.B"),
            new ExportEntry("B", 2, 0, true, "testdll.C"),
            new ExportEntry("C", 3, 0, false, string.Empty)
        };

        ExportEntry[] resolved = PECOFF.ResolveExportForwarderChainsForTest(entries, "testdll.dll", "testdll.dll");
        ExportEntry a = resolved.Single(e => e.Name == "A");
        ExportEntry b = resolved.Single(e => e.Name == "B");

        Assert.Equal(new[] { "testdll!B", "testdll!C" }, a.ForwarderChain);
        Assert.False(a.ForwarderHasCycle);
        Assert.Equal("testdll!C", a.ForwarderTarget);
        Assert.Equal(new[] { "testdll!C" }, b.ForwarderChain);
    }

    [Fact]
    public void ResolveExportForwarders_Detects_Cycle()
    {
        ExportEntry[] entries =
        {
            new ExportEntry("A", 1, 0, true, "testdll.B"),
            new ExportEntry("B", 2, 0, true, "testdll.A")
        };

        ExportEntry[] resolved = PECOFF.ResolveExportForwarderChainsForTest(entries, "testdll", "testdll.dll");
        ExportEntry a = resolved.Single(e => e.Name == "A");

        Assert.True(a.ForwarderHasCycle);
        Assert.Contains("testdll!A", a.ForwarderChain);
        Assert.Contains("testdll!B", a.ForwarderChain);
    }
}
