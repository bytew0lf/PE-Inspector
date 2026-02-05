using System;
using System.IO;
using Xunit;
using PECoff;

public class PECOFFTests
{
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

    [Fact]
    public void Parses_Current_Assembly_Successfully()
    {
        string assemblyPath = typeof(PECOFF).Assembly.Location;
        Assert.False(string.IsNullOrWhiteSpace(assemblyPath));
        Assert.True(File.Exists(assemblyPath));

        PECOFF parser = new PECOFF(assemblyPath);

        Assert.True(parser.ParseResult.IsSuccess);
        Assert.NotNull(parser.Hash);
        Assert.NotEmpty(parser.Hash);
        Assert.NotNull(parser.Imports);
        Assert.NotNull(parser.Exports);
    }

    [Fact]
    public void Parses_TestFiles_Without_Fatal_Errors()
    {
        string? testFilesDir = FindTestFilesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(testFilesDir));

        string[] files = Directory.GetFiles(testFilesDir!, "*.*", SearchOption.TopDirectoryOnly);
        Assert.NotEmpty(files);

        foreach (string file in files)
        {
            bool hasMzHeader = false;
            using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                if (fs.Length >= 2)
                {
                    int b0 = fs.ReadByte();
                    int b1 = fs.ReadByte();
                    hasMzHeader = (b0 == 0x4D && b1 == 0x5A);
                }
            }

            PECOFF parser = new PECOFF(file);
            if (hasMzHeader)
            {
                Assert.True(parser.ParseResult.IsSuccess, $"Parse failed for {Path.GetFileName(file)}: {string.Join(" | ", parser.ParseResult.Errors)}");
                Assert.False(string.IsNullOrWhiteSpace(parser.Hash));
            }
            else
            {
                Assert.False(parser.ParseResult.IsSuccess);
                Assert.NotEmpty(parser.ParseResult.Errors);
            }
        }
    }

    [Fact]
    public void Invalid_File_Reports_Error()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, new byte[] { 0x00, 0x01, 0x02, 0x03 });

            PECOFF parser = new PECOFF(tempFile);

            Assert.False(parser.ParseResult.IsSuccess);
            Assert.NotEmpty(parser.ParseResult.Errors);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }
}
