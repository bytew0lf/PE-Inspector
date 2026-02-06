using System;
using System.IO;
using PECoff;
using Xunit;

public class CorruptFixtureTests
{
    [Fact]
    public void BadRva_Fixture_Emits_Import_Warning()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "corrupt", "bad-rva.exe");
        PECOFF pe = new PECOFF(path);

        Assert.True(pe.ParseResult.IsSuccess);
        Assert.Contains(pe.ParseResult.Warnings, w => w.Contains("Import table RVA", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Overlap_Fixture_Emits_Section_Overlap_Warning()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "corrupt", "overlap.exe");
        PECOFF pe = new PECOFF(path);

        Assert.True(pe.ParseResult.IsSuccess);
        Assert.Contains(pe.ParseResult.Warnings, w => w.Contains("overlaps", StringComparison.OrdinalIgnoreCase));
    }

    private static string? FindFixturesDirectory()
    {
        string? dir = AppContext.BaseDirectory;
        for (int i = 0; i < 6 && dir != null; i++)
        {
            string candidate = Path.Combine(dir, "PECOFF.Tests", "Fixtures");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
            dir = Directory.GetParent(dir)?.FullName;
        }

        return null;
    }
}
