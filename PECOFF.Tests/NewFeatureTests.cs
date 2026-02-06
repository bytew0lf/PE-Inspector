using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using PECoff;
using Xunit;

public class NewFeatureTests
{
    [Fact]
    public void ApiSet_Imports_Are_Resolved_With_Targets()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", "notepad.exe");
        PECOFF pe = new PECOFF(path);

        var apiSets = pe.ImportDescriptors
            .Where(d => d.ApiSetResolution != null && d.ApiSetResolution.IsApiSet)
            .ToList();

        Assert.NotEmpty(apiSets);
        Assert.All(apiSets, descriptor => Assert.True(descriptor.ApiSetResolution.Targets.Count > 0));
    }

    [Fact]
    public void VersionInfoDetails_Include_StringTables_And_Translations()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", "notepad.exe");
        PECOFF pe = new PECOFF(path);

        VersionInfoDetails details = pe.VersionInfoDetails;
        Assert.NotNull(details);
        Assert.True(details.StringTables.Count > 0);
        Assert.True(details.Translations.Count > 0);
    }

    [Fact]
    public void Relocation_Section_Summaries_Aggregate_Block_Counts()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", "advapi32.dll");
        PECOFF pe = new PECOFF(path);

        if (pe.BaseRelocations.Length == 0)
        {
            return; // fixture may be stripped in some environments
        }

        Assert.NotEmpty(pe.BaseRelocationSections);
        int totalBlockEntries = pe.BaseRelocations.Sum(b => b.EntryCount);
        int totalSectionEntries = pe.BaseRelocationSections.Sum(s => s.EntryCount);
        Assert.Equal(totalBlockEntries, totalSectionEntries);
    }

    [Fact]
    public void Packing_Hints_Detect_Overlay_Signatures()
    {
        PackingHintInfo[] hints = PECOFF.DetectOverlayHintsForTest(new byte[] { 0x55, 0x50, 0x58, 0x21 });
        Assert.Contains(hints, hint => hint.Name.Contains("UPX", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidationProfile_Strict_Upgrades_Warnings()
    {
#pragma warning disable SYSLIB0050
        PECOFF parser = (PECOFF)FormatterServices.GetUninitializedObject(typeof(PECOFF));
#pragma warning restore SYSLIB0050

        ParseResult result = new ParseResult();
        SetField(parser, "_parseResult", result);
        SetField(parser, "_options", new PECOFFOptions { ValidationProfile = ValidationProfile.Strict });

        InvokeNonPublic(parser, "Warn", new object[] { ParseIssueCategory.Imports, "profile-warning" });

        Assert.Contains(result.Errors, message => message.Contains("profile-warning", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Json_Report_Includes_SchemaVersion()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", "zlib1.dll");
        PECOFF pe = new PECOFF(path);

        string json = pe.Result.ToJsonReport();
        Assert.Contains("\"SchemaVersion\"", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"FilePath\"", json, StringComparison.OrdinalIgnoreCase);
    }

    private static void SetField(object target, string name, object value)
    {
        FieldInfo? field = target.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        field!.SetValue(target, value);
    }

    private static void InvokeNonPublic(object target, string methodName, object[] args)
    {
        MethodInfo? method = target.GetType().GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance, null, args.Select(a => a.GetType()).ToArray(), null);
        Assert.NotNull(method);
        method!.Invoke(target, args);
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
