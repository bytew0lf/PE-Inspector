using System;
using System.IO;
using PECoff;
using Xunit;

public class ReservedFieldComplianceTests
{
    [Fact]
    public void ReservedFields_ReportSpecViolations_And_StrictModeFails()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] original = File.ReadAllBytes(validPath);
        byte[] mutated = (byte[])original.Clone();
        Assert.True(TryMutateReservedFields(mutated));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(parser.ParseResult.Warnings, warning => warning.Contains("SPEC violation: OptionalHeader.Win32VersionValue", StringComparison.Ordinal));
            Assert.Contains(parser.ParseResult.Warnings, warning => warning.Contains("SPEC violation: OptionalHeader.LoaderFlags", StringComparison.Ordinal));
            Assert.Contains(parser.ParseResult.Warnings, warning => warning.Contains("SPEC violation: OptionalHeader.DllCharacteristics contains reserved bits", StringComparison.Ordinal));
            Assert.Contains(parser.ParseResult.Warnings, warning => warning.Contains("SPEC violation: DataDirectory[7]", StringComparison.Ordinal));
            Assert.Contains(parser.ParseResult.Warnings, warning => warning.Contains("SPEC violation: DataDirectory[8]", StringComparison.Ordinal));
            Assert.Contains(parser.ParseResult.Warnings, warning => warning.Contains("SPEC violation: DataDirectory[15]", StringComparison.Ordinal));

            DataDirectoryValidationInfo architecture = Assert.Single(parser.DataDirectoryValidations, v => v.Index == 7);
            DataDirectoryValidationInfo globalPtr = Assert.Single(parser.DataDirectoryValidations, v => v.Index == 8);
            DataDirectoryValidationInfo reserved = Assert.Single(parser.DataDirectoryValidations, v => v.Index == 15);
            Assert.Contains("SPEC violation", architecture.Notes, StringComparison.Ordinal);
            Assert.Contains("SPEC violation", globalPtr.Notes, StringComparison.Ordinal);
            Assert.Contains("SPEC violation", reserved.Notes, StringComparison.Ordinal);

            string json = parser.Result.ToJsonReport(includeBinary: false, indented: false);
            Assert.Contains("SPEC violation", json, StringComparison.Ordinal);

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    private static bool TryMutateReservedFields(byte[] data)
    {
        if (!TryGetPeLayout(data, out int optionalHeaderStart, out bool isPe32Plus, out int dataDirectoryStart))
        {
            return false;
        }

        int win32VersionOffset = optionalHeaderStart + 0x34;
        int dllCharacteristicsOffset = optionalHeaderStart + 0x46;
        int loaderFlagsOffset = optionalHeaderStart + (isPe32Plus ? 0x68 : 0x58);
        if (win32VersionOffset + 4 > data.Length ||
            dllCharacteristicsOffset + 2 > data.Length ||
            loaderFlagsOffset + 4 > data.Length)
        {
            return false;
        }

        WriteUInt32(data, win32VersionOffset, 0x11223344);
        WriteUInt16(data, dllCharacteristicsOffset, 0x0001);
        WriteUInt32(data, loaderFlagsOffset, 0xAABBCCDD);

        if (!TryWriteDirectory(data, dataDirectoryStart, 7, 0x00001234, 0x00000020))
        {
            return false;
        }

        if (!TryWriteDirectory(data, dataDirectoryStart, 8, 0x00002000, 0x00000004))
        {
            return false;
        }

        if (!TryWriteDirectory(data, dataDirectoryStart, 15, 0x00004321, 0x00000010))
        {
            return false;
        }

        return true;
    }

    private static bool TryWriteDirectory(byte[] data, int dataDirectoryStart, int index, uint virtualAddress, uint size)
    {
        int offset = dataDirectoryStart + (index * 8);
        if (offset < 0 || offset + 8 > data.Length)
        {
            return false;
        }

        WriteUInt32(data, offset, virtualAddress);
        WriteUInt32(data, offset + 4, size);
        return true;
    }

    private static bool TryGetPeLayout(byte[] data, out int optionalHeaderStart, out bool isPe32Plus, out int dataDirectoryStart)
    {
        optionalHeaderStart = 0;
        isPe32Plus = false;
        dataDirectoryStart = 0;

        if (data == null || data.Length < 0x40)
        {
            return false;
        }

        int peOffset = BitConverter.ToInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 4 + 20 + 2 > data.Length)
        {
            return false;
        }

        optionalHeaderStart = peOffset + 4 + 20;
        ushort magic = BitConverter.ToUInt16(data, optionalHeaderStart);
        if (magic == 0x10B)
        {
            isPe32Plus = false;
            dataDirectoryStart = optionalHeaderStart + 0x60;
        }
        else if (magic == 0x20B)
        {
            isPe32Plus = true;
            dataDirectoryStart = optionalHeaderStart + 0x70;
        }
        else
        {
            return false;
        }

        return dataDirectoryStart + (16 * 8) <= data.Length;
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)((value >> 16) & 0xFF);
        data[offset + 3] = (byte)((value >> 24) & 0xFF);
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
