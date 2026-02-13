using System;
using System.IO;
using PECoff;
using Xunit;

public class DelayImportReservedComplianceTests
{
    [Fact]
    public void PeImage_DelayImportAttributesNonZero_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] mutated = File.ReadAllBytes(GetMinimalFixturePath());
        Assert.True(TrySetDelayImportDescriptorAttributesNonZero(mutated, 1u));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("IMAGE_DELAY_IMPORT_DESCRIPTOR.Attributes is reserved and must be 0", StringComparison.Ordinal));

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

    private static bool TrySetDelayImportDescriptorAttributesNonZero(byte[] data, uint attributes)
    {
        if (!TryGetPeLayout(data, out int dataDirectoryOffset, out int sectionTableOffset))
        {
            return false;
        }

        int firstSectionOffset = sectionTableOffset;
        uint sectionVirtualAddress = BitConverter.ToUInt32(data, firstSectionOffset + 12);
        uint sectionRawSize = BitConverter.ToUInt32(data, firstSectionOffset + 16);
        uint sectionRawPointer = BitConverter.ToUInt32(data, firstSectionOffset + 20);
        if (sectionRawSize < 0x80 || sectionRawPointer > int.MaxValue)
        {
            return false;
        }

        const int delayImportDescriptorSize = 32;
        const uint delayImportOffsetInSection = 0x60;
        long delayImportRawOffset = sectionRawPointer + delayImportOffsetInSection;
        if (delayImportRawOffset < 0 ||
            delayImportRawOffset + delayImportDescriptorSize > data.Length ||
            delayImportOffsetInSection + delayImportDescriptorSize > sectionRawSize)
        {
            return false;
        }

        int directoryOffset = dataDirectoryOffset + (13 * 8);
        uint delayImportRva = sectionVirtualAddress + delayImportOffsetInSection;
        WriteUInt32(data, directoryOffset, delayImportRva);
        WriteUInt32(data, directoryOffset + 4, delayImportDescriptorSize);

        int rawOffset = (int)delayImportRawOffset;
        for (int i = 0; i < delayImportDescriptorSize; i++)
        {
            data[rawOffset + i] = 0;
        }

        WriteUInt32(data, rawOffset, attributes);
        return true;
    }

    private static bool TryGetPeLayout(byte[] data, out int dataDirectoryOffset, out int sectionTableOffset)
    {
        dataDirectoryOffset = 0;
        sectionTableOffset = 0;

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
        bool isPe32Plus = magic == 0x20B;
        dataDirectoryOffset = optionalHeaderOffset + (isPe32Plus ? 0x70 : 0x60);
        if (dataDirectoryOffset + (16 * 8) > data.Length)
        {
            return false;
        }

        return true;
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
