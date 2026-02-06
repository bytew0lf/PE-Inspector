using System;
using System.Collections.Generic;
using System.IO;
using Xunit;
using PECoff;

public class OptionsAndCallbackTests
{
    [Fact]
    public void Result_Has_SchemaVersion()
    {
        string assemblyPath = typeof(PECOFF).Assembly.Location;
        PECOFF parser = new PECOFF(assemblyPath);
        PECOFFResult result = parser.ToResult();

        Assert.Equal(PECOFFResult.CurrentSchemaVersion, result.SchemaVersion);
    }

    [Fact]
    public void Presets_Configure_Expected_Flags()
    {
        PECOFFOptions fast = PECOFFOptions.PresetFast();
        Assert.False(fast.ComputeHash);
        Assert.False(fast.ComputeImportHash);
        Assert.False(fast.ComputeChecksum);
        Assert.False(fast.ParseCertificateSigners);

        PECOFFOptions strict = PECOFFOptions.PresetStrictSecurity();
        Assert.True(strict.StrictMode);
        Assert.True(strict.AuthenticodePolicy.RequireSignature);
        Assert.True(strict.AuthenticodePolicy.RequireSignatureValid);
        Assert.True(strict.AuthenticodePolicy.RequireChainValid);
        Assert.True(strict.AuthenticodePolicy.RequireTimestampValid);
    }

    [Fact]
    public void IssueCallback_Receives_Warnings()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string path = Path.Combine(fixtures!, "minimal", "zlib1.dll");
        byte[] data = File.ReadAllBytes(path);
        int fileAlignmentOffset = FindFileAlignmentOffset(data);
        Assert.True(fileAlignmentOffset >= 0);

        byte[] mutated = (byte[])data.Clone();
        WriteUInt32(mutated, fileAlignmentOffset, 0);

        string tempFile = Path.GetTempFileName();
        List<ParseIssue> issues = new List<ParseIssue>();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFFOptions options = new PECOFFOptions
            {
                IssueCallback = issues.Add
            };

            PECOFF parser = new PECOFF(tempFile, options);
            Assert.True(issues.Count > 0);
            Assert.Contains(issues, issue => issue.Severity == ParseIssueSeverity.Warning);
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
