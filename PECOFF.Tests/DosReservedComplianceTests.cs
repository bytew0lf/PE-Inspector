using System;
using System.IO;
using PECoff;
using Xunit;

public class DosReservedComplianceTests
{
    [Fact]
    public void PeImage_DosReservedWordsNonZero_EmitSpecViolation_AndStrictModeFails()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] mutated = File.ReadAllBytes(validPath);
        Assert.True(TryMutateDosReservedWords(mutated));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DOS_HEADER.e_res contains non-zero reserved words.", StringComparison.Ordinal));
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DOS_HEADER.e_res2 contains non-zero reserved words.", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    private static bool TryMutateDosReservedWords(byte[] data)
    {
        if (data == null || data.Length < 0x40)
        {
            return false;
        }

        if (BitConverter.ToUInt16(data, 0) != 0x5A4D)
        {
            return false;
        }

        WriteUInt16(data, 0x1C, 0x1122); // e_res[0]
        WriteUInt16(data, 0x28, 0x3344); // e_res2[0]
        return true;
    }

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
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
