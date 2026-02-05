using System.Globalization;
using PECoff;

string repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
string testFilesDir = Path.Combine(repoRoot, "testfiles");
string fixturesDir = Path.Combine(repoRoot, "PECOFF.Tests", "Fixtures");
string snapshotPath = Path.Combine(fixturesDir, "testfiles.snap");

for (int i = 0; i < args.Length; i++)
{
    string arg = args[i];
    if (string.Equals(arg, "--input", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        testFilesDir = args[++i];
    }
    else if (string.Equals(arg, "--output", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
    {
        snapshotPath = args[++i];
    }
}

if (!Directory.Exists(testFilesDir))
{
    Console.Error.WriteLine("Input directory not found: {0}", testFilesDir);
    return 1;
}

Directory.CreateDirectory(Path.GetDirectoryName(snapshotPath) ?? fixturesDir);

Dictionary<string, SnapshotEntry> snapshots = new Dictionary<string, SnapshotEntry>(StringComparer.OrdinalIgnoreCase);
foreach (string file in Directory.GetFiles(testFilesDir, "*.*", SearchOption.TopDirectoryOnly)
    .OrderBy(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase))
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
        parser.Resources.Length,
        parser.DebugDirectories.Length,
        parser.BaseRelocations.Length,
        parser.IconGroups.Length,
        parser.TlsInfo != null,
        parser.LoadConfig != null,
        parser.CertificateEntries.Sum(e => e.AuthenticodeResults?.Length ?? 0));

    snapshots[entry.Name] = entry;
}

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
        entry.ResourceCount.ToString(CultureInfo.InvariantCulture),
        entry.DebugCount.ToString(CultureInfo.InvariantCulture),
        entry.RelocationBlockCount.ToString(CultureInfo.InvariantCulture),
        entry.IconGroupCount.ToString(CultureInfo.InvariantCulture),
        entry.HasTls.ToString(),
        entry.HasLoadConfig.ToString(),
        entry.AuthenticodeResultCount.ToString(CultureInfo.InvariantCulture)));
}

File.WriteAllLines(snapshotPath, lines);
Console.WriteLine("Snapshot written to: {0}", snapshotPath);
return 0;

static bool HasMzHeader(string path)
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

sealed class SnapshotEntry
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
    public int DebugCount { get; }
    public int RelocationBlockCount { get; }
    public int IconGroupCount { get; }
    public bool HasTls { get; }
    public bool HasLoadConfig { get; }
    public int AuthenticodeResultCount { get; }

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
        int resourceCount,
        int debugCount,
        int relocationBlockCount,
        int iconGroupCount,
        bool hasTls,
        bool hasLoadConfig,
        int authenticodeResultCount)
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
        DebugCount = debugCount;
        RelocationBlockCount = relocationBlockCount;
        IconGroupCount = iconGroupCount;
        HasTls = hasTls;
        HasLoadConfig = hasLoadConfig;
        AuthenticodeResultCount = authenticodeResultCount;
    }
}
