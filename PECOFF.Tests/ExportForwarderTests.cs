using PECoff;
using Xunit;

public class ExportForwarderTests
{
    [Fact]
    public void ExportForwarder_Resolves_Chain_Within_Module()
    {
        ExportEntry[] entries = new[]
        {
            new ExportEntry("A", 1, 0, true, "foo.B"),
            new ExportEntry("B", 2, 0, true, "foo.C"),
            new ExportEntry("C", 3, 0x1234, false, string.Empty)
        };

        ExportEntry[] resolved = PECOFF.ResolveExportForwarderChainsForTest(entries, "foo", "foo.dll");
        ExportEntry forwarder = Assert.Single(resolved, entry => entry.Name == "A");

        Assert.True(forwarder.ForwarderResolved);
        Assert.False(forwarder.ForwarderHasCycle);
        Assert.Equal("foo!C", forwarder.ForwarderTarget);
        Assert.Equal(2, forwarder.ForwarderChain.Count);
    }

    [Fact]
    public void ExportForwarder_Resolves_External_Target()
    {
        ExportEntry[] entries = new[]
        {
            new ExportEntry("A", 1, 0, true, "kernel32.Sleep")
        };

        ExportEntry[] resolved = PECOFF.ResolveExportForwarderChainsForTest(entries, "foo", "foo.dll");
        ExportEntry forwarder = resolved[0];

        Assert.True(forwarder.ForwarderResolved);
        Assert.Equal("kernel32!Sleep", forwarder.ForwarderTarget);
        Assert.Single(forwarder.ForwarderChain);
    }

    [Fact]
    public void ExportForwarder_Detects_Cycles()
    {
        ExportEntry[] entries = new[]
        {
            new ExportEntry("A", 1, 0, true, "foo.B"),
            new ExportEntry("B", 2, 0, true, "foo.A")
        };

        ExportEntry[] resolved = PECOFF.ResolveExportForwarderChainsForTest(entries, "foo", "foo.dll");
        ExportEntry forwarder = Assert.Single(resolved, entry => entry.Name == "A");

        Assert.True(forwarder.ForwarderHasCycle);
        Assert.False(forwarder.ForwarderResolved);
    }
}
