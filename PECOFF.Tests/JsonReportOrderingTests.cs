using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using PECoff;
using Xunit;

public class JsonReportOrderingTests
{
    [Fact]
    public void Json_Report_Uses_Stable_Ordering_For_Imports()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", "PE-Inspector.dll");
        Assert.True(File.Exists(path));

        PECOFF pe = new PECOFF(path);
        string json = pe.Result.ToJsonReport();

        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement importsElement = doc.RootElement.GetProperty("Imports");
        string[] imports = importsElement.EnumerateArray()
            .Select(item => item.GetString() ?? string.Empty)
            .ToArray();

        if (imports.Length <= 1)
        {
            return;
        }

        string[] sorted = imports.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray();
        Assert.Equal(sorted, imports);
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
