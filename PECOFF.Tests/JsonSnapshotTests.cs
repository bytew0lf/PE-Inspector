using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using PECoff;
using Xunit;

public class JsonSnapshotTests
{
    private static readonly string[] SnapshotFiles = new[]
    {
        "minimal-x86.exe",
        "minimal-x64.exe"
    };

    [Fact]
    public void Minimal_Fixtures_Json_Snapshots_Match()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string snapshotDir = Path.Combine(fixturesDir!, "json");
        Directory.CreateDirectory(snapshotDir);

        bool update = string.Equals(Environment.GetEnvironmentVariable("PECOFF_UPDATE_JSON_SNAPSHOTS"), "1", StringComparison.Ordinal);
        foreach (string fileName in SnapshotFiles)
        {
            string fixturePath = Path.Combine(fixturesDir!, "minimal", fileName);
            Assert.True(File.Exists(fixturePath), $"Fixture not found: {fixturePath}");

            PECOFF parser = new PECOFF(fixturePath);
            string actual = NormalizeJson(parser.Result.ToJsonReport(indented: true), fileName);

            string snapshotPath = Path.Combine(snapshotDir, fileName + ".json");
            if (update)
            {
                File.WriteAllText(snapshotPath, actual);
                continue;
            }

            Assert.True(File.Exists(snapshotPath), $"Snapshot missing: {snapshotPath}. Set PECOFF_UPDATE_JSON_SNAPSHOTS=1 to generate.");
            string expected = File.ReadAllText(snapshotPath);
            Assert.Equal(expected, actual);
        }
    }

    private static string NormalizeJson(string json, string fileName)
    {
        JsonNode? node = JsonNode.Parse(json);
        if (node is JsonObject obj)
        {
            obj["FilePath"] = fileName;
        }

        return node?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) ?? string.Empty;
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
