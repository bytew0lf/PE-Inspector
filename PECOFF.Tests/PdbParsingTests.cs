using System;
using System.IO;
using PECoff;
using Xunit;

public class PdbParsingTests
{
    [Fact]
    public void Pdb_Msf_Parses_Header_And_Publics()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string pdbPath = Path.Combine(fixturesDir!, "pdb", "minimal.pdb");
        Assert.True(File.Exists(pdbPath), $"Fixture not found: {pdbPath}");

        bool parsed = PECOFF.TryParsePdbInfoForTest(pdbPath, out PdbInfo info);

        Assert.True(parsed);
        Assert.Equal("MSF 7.00", info.Format);
        Assert.Equal((uint)0x12345678, info.PdbSignature);
        Assert.Equal((uint)3, info.Age);
        Assert.Equal(new Guid("00112233-4455-6677-8899-AABBCCDDEEFF"), info.Guid);
        Assert.Equal(2, info.PublicSymbolCount);
        Assert.Null(info.Dbi);
        Assert.Null(info.Tpi);
        Assert.Null(info.Ipi);
        Assert.NotNull(info.Publics);
        Assert.Equal(2, info.Publics.NameCount);
        Assert.Null(info.Globals);
        Assert.Contains("foo", info.PublicSymbols, StringComparer.Ordinal);
        Assert.Contains("bar", info.PublicSymbols, StringComparer.Ordinal);
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
