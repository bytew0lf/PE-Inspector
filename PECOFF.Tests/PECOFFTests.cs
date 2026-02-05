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

    private static bool IsUpperHex(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
            {
                return false;
            }
        }

        return true;
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
        Assert.Equal(64, parser.Hash.Length);
        Assert.True(IsUpperHex(parser.Hash));
        Assert.NotNull(parser.Imports);
        Assert.NotNull(parser.Exports);
        Assert.NotNull(parser.ClrMetadata);
        Assert.False(string.IsNullOrWhiteSpace(parser.ClrMetadata.AssemblyName));
        Assert.False(string.IsNullOrWhiteSpace(parser.ClrMetadata.Mvid));
    }

    [Fact]
    public void Parses_Fixture_Valid_Pe()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "valid-pe.dll");
        Assert.True(File.Exists(validPath));

        PECOFF parser = new PECOFF(validPath);
        Assert.True(parser.ParseResult.IsSuccess);
        Assert.NotNull(parser.ClrMetadata);
    }

    [Fact]
    public void Corrupt_Fixture_Reports_Errors()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string corruptPath = Path.Combine(fixtures!, "corrupt.bin");
        Assert.True(File.Exists(corruptPath));

        PECOFF parser = new PECOFF(corruptPath);
        Assert.False(parser.ParseResult.IsSuccess);
        Assert.NotEmpty(parser.ParseResult.Errors);
    }

    [Fact]
    public void IssuePolicy_Allows_OptionalHeader_Warnings_In_StrictMode()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "valid-pe.dll");
        Assert.True(File.Exists(validPath));

        byte[] data = File.ReadAllBytes(validPath);
        int fileAlignmentOffset = FindFileAlignmentOffset(data);
        Assert.True(fileAlignmentOffset >= 0);

        byte[] mutated = (byte[])data.Clone();
        WriteUInt32(mutated, fileAlignmentOffset, 0);

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));

            PECOFFOptions options = new PECOFFOptions
            {
                StrictMode = true,
                IssuePolicy = new System.Collections.Generic.Dictionary<ParseIssueCategory, ParseIssueSeverity>
                {
                    [ParseIssueCategory.OptionalHeader] = ParseIssueSeverity.Warning
                }
            };
            PECOFF parser = new PECOFF(tempFile, options);
            Assert.True(parser.ParseResult.IsSuccess);
            Assert.NotEmpty(parser.ParseResult.Warnings);
        }
        finally
        {
            File.Delete(tempFile);
        }
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
                Assert.Equal(64, parser.Hash.Length);
                Assert.True(IsUpperHex(parser.Hash));
                if (parser.HasCertificate)
                {
                    Assert.NotNull(parser.Certificate);
                    Assert.NotEmpty(parser.Certificate);
                    foreach (CertificateEntry entry in parser.CertificateEntries)
                    {
                        Assert.NotNull(entry.Pkcs7SignerInfos);
                        Assert.NotNull(entry.Pkcs7Error);
                    }
                }
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

    private static int FindFileAlignmentOffset(byte[] data)
    {
        if (data == null || data.Length < 0x40)
        {
            return -1;
        }

        int peOffset = BitConverter.ToInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 4 + 20 + 2 > data.Length)
        {
            return -1;
        }

        int optionalHeaderStart = peOffset + 4 + 20;
        ushort magic = BitConverter.ToUInt16(data, optionalHeaderStart);
        if (magic != 0x10B && magic != 0x20B)
        {
            return -1;
        }

        int fileAlignmentOffset = optionalHeaderStart + 0x24;
        if (fileAlignmentOffset + 4 > data.Length)
        {
            return -1;
        }

        return fileAlignmentOffset;
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)((value >> 16) & 0xFF);
        data[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
