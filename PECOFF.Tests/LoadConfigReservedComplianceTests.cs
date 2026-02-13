using System;
using System.IO;
using PECoff;
using Xunit;

public class LoadConfigReservedComplianceTests
{
    [Fact]
    public void PeImage_LoadConfigReservedFieldsNonZero_EmitSpecViolation_AndStrictModeFails()
    {
        byte[] mutated = File.ReadAllBytes(GetMinimalFixturePath());
        Assert.True(TryInjectLoadConfigReservedFields(mutated));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("IMAGE_LOAD_CONFIG_CODE_INTEGRITY.Reserved must be 0", StringComparison.Ordinal));
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("IMAGE_LOAD_CONFIG_DIRECTORY.Reserved2 must be 0", StringComparison.Ordinal));
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("IMAGE_LOAD_CONFIG_DIRECTORY.Reserved3 must be 0", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    private static string GetMinimalFixturePath()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));
        return validPath;
    }

    private static bool TryInjectLoadConfigReservedFields(byte[] data)
    {
        if (!TryGetPeLayout(data, out int dataDirectoryOffset, out int sectionTableOffset, out bool isPe32Plus) || isPe32Plus)
        {
            return false;
        }

        int firstSectionOffset = sectionTableOffset;
        uint sectionVirtualAddress = BitConverter.ToUInt32(data, firstSectionOffset + 12);
        uint sectionRawSize = BitConverter.ToUInt32(data, firstSectionOffset + 16);
        uint sectionRawPointer = BitConverter.ToUInt32(data, firstSectionOffset + 20);
        if (sectionRawPointer > int.MaxValue)
        {
            return false;
        }

        const int loadConfigSize = 0xA0;
        const uint loadConfigOffsetInSection = 0x100;
        ulong sectionEnd = (ulong)loadConfigOffsetInSection + (ulong)loadConfigSize;
        if (sectionEnd > sectionRawSize)
        {
            return false;
        }

        int loadConfigRaw = checked((int)sectionRawPointer + (int)loadConfigOffsetInSection);
        if (loadConfigRaw < 0 || loadConfigRaw + loadConfigSize > data.Length)
        {
            return false;
        }

        uint loadConfigRva = sectionVirtualAddress + loadConfigOffsetInSection;
        int directoryOffset = dataDirectoryOffset + (10 * 8);
        WriteUInt32(data, directoryOffset, loadConfigRva);
        WriteUInt32(data, directoryOffset + 4, loadConfigSize);

        for (int i = 0; i < loadConfigSize; i++)
        {
            data[loadConfigRaw + i] = 0;
        }

        WriteUInt32(data, loadConfigRaw + 0, loadConfigSize); // Size

        // Offsets for PE32 in this parser's layout walk.
        WriteUInt32(data, loadConfigRaw + 0x64, 0x11223344u); // CodeIntegrity.Reserved
        WriteUInt16(data, loadConfigRaw + 0x8E, 0x00A5);      // Reserved2
        WriteUInt32(data, loadConfigRaw + 0x98, 0x55667788u); // Reserved3

        return true;
    }

    private static bool TryGetPeLayout(byte[] data, out int dataDirectoryOffset, out int sectionTableOffset, out bool isPe32Plus)
    {
        dataDirectoryOffset = 0;
        sectionTableOffset = 0;
        isPe32Plus = false;

        if (data == null || data.Length < 0x100)
        {
            return false;
        }

        int peOffset = BitConverter.ToInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 4 + 20 > data.Length)
        {
            return false;
        }

        int fileHeaderOffset = peOffset + 4;
        ushort numberOfSections = BitConverter.ToUInt16(data, fileHeaderOffset + 2);
        ushort sizeOfOptionalHeader = BitConverter.ToUInt16(data, fileHeaderOffset + 16);
        int optionalHeaderOffset = fileHeaderOffset + 20;
        sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
        if (numberOfSections == 0 || sectionTableOffset + 40 > data.Length || optionalHeaderOffset + 2 > data.Length)
        {
            return false;
        }

        ushort magic = BitConverter.ToUInt16(data, optionalHeaderOffset);
        isPe32Plus = magic == 0x20B;
        dataDirectoryOffset = optionalHeaderOffset + (isPe32Plus ? 0x70 : 0x60);
        return dataDirectoryOffset + (16 * 8) <= data.Length;
    }

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
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
