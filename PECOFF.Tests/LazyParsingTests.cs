using System;
using System.IO;
using System.Reflection;
using PECoff;
using Xunit;

public class LazyParsingTests
{
    [Fact]
    public void Lazy_Parse_Defers_Data_Directories_Until_Access()
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", "notepad.exe");
        Assert.True(File.Exists(path));

        PECOFFOptions options = new PECOFFOptions { LazyParseDataDirectories = true };
        PECOFF parser = new PECOFF(path, options);

        Assert.False(GetBoolField(parser, "_resourcesParsed"));
        Assert.False(GetBoolField(parser, "_debugParsed"));
        Assert.False(GetBoolField(parser, "_relocationsParsed"));

        _ = parser.ResourceStringTables;
        Assert.True(GetBoolField(parser, "_resourcesParsed"));

        _ = parser.DebugDirectories;
        Assert.True(GetBoolField(parser, "_debugParsed"));

        _ = parser.BaseRelocations;
        Assert.True(GetBoolField(parser, "_relocationsParsed"));
    }

    private static bool GetBoolField(object target, string name)
    {
        FieldInfo? field = target.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        return (bool)field!.GetValue(target)!;
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
