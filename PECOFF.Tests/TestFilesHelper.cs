using System;
using System.IO;

internal static class TestFilesHelper
{
    private const int MaxDepth = 6;

    public static string? TryGetTestFilesDirectory()
    {
        string? explicitDir = Environment.GetEnvironmentVariable("PECOFF_TESTFILES_DIR");
        if (!string.IsNullOrWhiteSpace(explicitDir))
        {
            return Directory.Exists(explicitDir) ? explicitDir : null;
        }

        string? dir = AppContext.BaseDirectory;
        for (int i = 0; i < MaxDepth && dir != null; i++)
        {
            string candidate = Path.Combine(dir, "testfiles");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
            dir = Directory.GetParent(dir)?.FullName;
        }

        return null;
    }
}
