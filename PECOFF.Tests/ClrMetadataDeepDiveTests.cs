using System;
using System.IO;
using PECoff;
using Xunit;

public class ClrMetadataDeepDiveTests
{
    [Fact]
    public void Clr_Metadata_DeepDive_Populates_TokenRefs_And_MethodBodies()
    {
        string? testFilesDir = FindTestFilesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(testFilesDir));

        string path = Path.Combine(testFilesDir!, "PE-Inspector.dll");
        Assert.True(File.Exists(path), $"Test file not found: {path}");

        PECOFF parser = new PECOFF(path);
        Assert.NotNull(parser.ClrMetadata);
        Assert.NotNull(parser.ClrMetadata.MethodBodySummary);
        Assert.True(parser.ClrMetadata.MethodBodySummary.MethodBodyCount > 0);
        Assert.NotEmpty(parser.ClrMetadata.TokenReferences);
        Assert.NotNull(parser.ClrMetadata.SignatureSummary);
        Assert.True(parser.ClrMetadata.SignatureSummary.MethodSignatureCount > 0);
        Assert.True(parser.ClrMetadata.SignatureSummary.Samples.Count > 0);
    }

    private static string? FindTestFilesDirectory()
    {
        string? dir = AppContext.BaseDirectory;
        for (int i = 0; i < 6 && dir != null; i++)
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
