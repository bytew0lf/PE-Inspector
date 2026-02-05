using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Xunit;
using PECoff;

public class SnapshotTests
{
    private const string SnapshotFileName = "testfiles.snap";

    [Fact]
    public void Testfiles_Snapshots_Match()
    {
        if (string.Equals(Environment.GetEnvironmentVariable("PECOFF_UPDATE_GOLDENS"), "1", StringComparison.Ordinal))
        {
            return;
        }

        string? testFilesDir = FindTestFilesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(testFilesDir));

        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string snapshotPath = Path.Combine(fixturesDir!, SnapshotFileName);
        Assert.True(File.Exists(snapshotPath), $"Snapshot file missing: {snapshotPath}. Run with PECOFF_UPDATE_GOLDENS=1 to generate.");

        Dictionary<string, SnapshotEntry> expected = LoadSnapshots(snapshotPath);
        Dictionary<string, SnapshotEntry> actual = BuildSnapshots(testFilesDir!);

        Assert.Equal(expected.Count, actual.Count);
        foreach (KeyValuePair<string, SnapshotEntry> pair in actual)
        {
            Assert.True(expected.TryGetValue(pair.Key, out SnapshotEntry? expectedEntry), $"Missing snapshot for {pair.Key}");
            SnapshotEntry actualEntry = pair.Value;
            Assert.Equal(expectedEntry.Hash, actualEntry.Hash);
            Assert.Equal(expectedEntry.IsDotNet, actualEntry.IsDotNet);
            Assert.Equal(expectedEntry.ImportCount, actualEntry.ImportCount);
            Assert.Equal(expectedEntry.ExportCount, actualEntry.ExportCount);
            Assert.Equal(expectedEntry.DelayImportCount, actualEntry.DelayImportCount);
            Assert.Equal(expectedEntry.DelayImportDescriptorCount, actualEntry.DelayImportDescriptorCount);
            Assert.Equal(expectedEntry.BoundImportCount, actualEntry.BoundImportCount);
            Assert.Equal(expectedEntry.CertificateCount, actualEntry.CertificateCount);
            Assert.Equal(expectedEntry.ResourceCount, actualEntry.ResourceCount);
        }
    }

    [Fact]
    public void Update_Testfiles_Snapshots()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("PECOFF_UPDATE_GOLDENS"), "1", StringComparison.Ordinal))
        {
            return;
        }

        string? testFilesDir = FindTestFilesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(testFilesDir));

        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string snapshotPath = Path.Combine(fixturesDir!, SnapshotFileName);
        Dictionary<string, SnapshotEntry> snapshots = BuildSnapshots(testFilesDir!);
        WriteSnapshots(snapshotPath, snapshots);
    }

    private static Dictionary<string, SnapshotEntry> BuildSnapshots(string testFilesDir)
    {
        Dictionary<string, SnapshotEntry> snapshots = new Dictionary<string, SnapshotEntry>(StringComparer.OrdinalIgnoreCase);
        string[] files = Directory.GetFiles(testFilesDir, "*.*", SearchOption.TopDirectoryOnly)
            .OrderBy(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (string file in files)
        {
            if (!HasMzHeader(file))
            {
                continue;
            }

            PECOFF parser = new PECOFF(file);
            SnapshotEntry entry = new SnapshotEntry(
                Path.GetFileName(file) ?? file,
                parser.Hash ?? string.Empty,
                parser.IsDotNetFile,
                parser.ImportEntries.Length,
                parser.ExportEntries.Length,
                parser.DelayImportEntries.Length,
                parser.DelayImportDescriptors.Length,
                parser.BoundImports.Length,
                parser.CertificateEntries.Length,
                parser.Resources.Length);

            snapshots[entry.Name] = entry;
        }

        return snapshots;
    }

    private static bool HasMzHeader(string path)
    {
        try
        {
            using FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length < 2)
            {
                return false;
            }

            int b0 = fs.ReadByte();
            int b1 = fs.ReadByte();
            return b0 == 0x4D && b1 == 0x5A;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static Dictionary<string, SnapshotEntry> LoadSnapshots(string path)
    {
        Dictionary<string, SnapshotEntry> snapshots = new Dictionary<string, SnapshotEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            string[] parts = line.Split('|');
            if (parts.Length != 10)
            {
                continue;
            }

            SnapshotEntry entry = new SnapshotEntry(
                parts[0],
                parts[1],
                bool.Parse(parts[2]),
                int.Parse(parts[3], CultureInfo.InvariantCulture),
                int.Parse(parts[4], CultureInfo.InvariantCulture),
                int.Parse(parts[5], CultureInfo.InvariantCulture),
                int.Parse(parts[6], CultureInfo.InvariantCulture),
                int.Parse(parts[7], CultureInfo.InvariantCulture),
                int.Parse(parts[8], CultureInfo.InvariantCulture),
                int.Parse(parts[9], CultureInfo.InvariantCulture));

            snapshots[entry.Name] = entry;
        }

        return snapshots;
    }

    private static void WriteSnapshots(string path, Dictionary<string, SnapshotEntry> snapshots)
    {
        List<string> lines = new List<string>();
        foreach (SnapshotEntry entry in snapshots.Values.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            lines.Add(string.Join("|",
                entry.Name,
                entry.Hash,
                entry.IsDotNet.ToString(),
                entry.ImportCount.ToString(CultureInfo.InvariantCulture),
                entry.ExportCount.ToString(CultureInfo.InvariantCulture),
                entry.DelayImportCount.ToString(CultureInfo.InvariantCulture),
                entry.DelayImportDescriptorCount.ToString(CultureInfo.InvariantCulture),
                entry.BoundImportCount.ToString(CultureInfo.InvariantCulture),
                entry.CertificateCount.ToString(CultureInfo.InvariantCulture),
                entry.ResourceCount.ToString(CultureInfo.InvariantCulture)));
        }

        File.WriteAllLines(path, lines);
    }

    private static string? FindTestFilesDirectory()
    {
        string baseDir = AppContext.BaseDirectory;
        DirectoryInfo? dir = new DirectoryInfo(baseDir);
        for (int i = 0; i < 6 && dir != null; i++)
        {
            string candidate = Path.Combine(dir.FullName, "testfiles");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        return null;
    }

    private static string? FindFixturesDirectory()
    {
        string baseDir = AppContext.BaseDirectory;
        DirectoryInfo? dir = new DirectoryInfo(baseDir);
        for (int i = 0; i < 6 && dir != null; i++)
        {
            string candidate = Path.Combine(dir.FullName, "PECOFF.Tests", "Fixtures");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            candidate = Path.Combine(dir.FullName, "Fixtures");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        return null;
    }

    private sealed class SnapshotEntry
    {
        public string Name { get; }
        public string Hash { get; }
        public bool IsDotNet { get; }
        public int ImportCount { get; }
        public int ExportCount { get; }
        public int DelayImportCount { get; }
        public int DelayImportDescriptorCount { get; }
        public int BoundImportCount { get; }
        public int CertificateCount { get; }
        public int ResourceCount { get; }

        public SnapshotEntry(
            string name,
            string hash,
            bool isDotNet,
            int importCount,
            int exportCount,
            int delayImportCount,
            int delayImportDescriptorCount,
            int boundImportCount,
            int certificateCount,
            int resourceCount)
        {
            Name = name ?? string.Empty;
            Hash = hash ?? string.Empty;
            IsDotNet = isDotNet;
            ImportCount = importCount;
            ExportCount = exportCount;
            DelayImportCount = delayImportCount;
            DelayImportDescriptorCount = delayImportDescriptorCount;
            BoundImportCount = boundImportCount;
            CertificateCount = certificateCount;
            ResourceCount = resourceCount;
        }
    }
}
