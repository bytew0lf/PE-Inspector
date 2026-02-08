using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using PECoff;

string[] snapshotFiles =
{
    "minimal-x86.exe",
    "minimal-x64.exe"
};

string? fixturesDir = null;
string? outputDir = null;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--fixtures":
        case "--input":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine("Missing value for --fixtures.");
                return 1;
            }
            fixturesDir = args[++i];
            break;
        case "--output":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine("Missing value for --output.");
                return 1;
            }
            outputDir = args[++i];
            break;
        case "--help":
        case "-h":
            PrintHelp();
            return 0;
        default:
            Console.Error.WriteLine($"Unknown argument: {args[i]}");
            PrintHelp();
            return 1;
    }
}

fixturesDir = ResolveFixturesDirectory(fixturesDir);
if (string.IsNullOrWhiteSpace(fixturesDir) || !Directory.Exists(fixturesDir))
{
    Console.Error.WriteLine("Could not locate PECOFF.Tests/Fixtures. Use --fixtures to specify the path.");
    return 1;
}

outputDir ??= Path.Combine(fixturesDir, "json");
Directory.CreateDirectory(outputDir);

string minimalDir = Path.Combine(fixturesDir, "minimal");
if (!Directory.Exists(minimalDir))
{
    Console.Error.WriteLine($"Minimal fixtures directory not found: {minimalDir}");
    return 1;
}

List<string> written = new List<string>();
foreach (string fileName in snapshotFiles)
{
    string fixturePath = Path.Combine(minimalDir, fileName);
    if (!File.Exists(fixturePath))
    {
        Console.Error.WriteLine($"Fixture not found: {fixturePath}");
        return 1;
    }

    PECOFF parser = new PECOFF(fixturePath);
    string json = NormalizeJson(parser.Result.ToJsonReport(indented: true), fileName);
    string snapshotPath = Path.Combine(outputDir, fileName + ".json");
    File.WriteAllText(snapshotPath, json);
    written.Add(snapshotPath);
}

Console.WriteLine("JSON snapshots written:");
foreach (string path in written)
{
    Console.WriteLine("  " + path);
}

return 0;

static string NormalizeJson(string json, string fileName)
{
    JsonNode? node = JsonNode.Parse(json);
    if (node is JsonObject obj)
    {
        obj["FilePath"] = fileName;
    }

    return node?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) ?? string.Empty;
}

static string? ResolveFixturesDirectory(string? supplied)
{
    if (!string.IsNullOrWhiteSpace(supplied))
    {
        return supplied;
    }

    string? dir = Directory.GetCurrentDirectory();
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

static void PrintHelp()
{
    Console.WriteLine("JsonSnapshotGenerator");
    Console.WriteLine("  --fixtures <path>   Path to PECOFF.Tests/Fixtures (optional).");
    Console.WriteLine("  --output <path>     Output directory for JSON snapshots (optional).");
}
