using System;
using System.IO;
using PECoff;
using Xunit;

public class TlsReservedComplianceTests
{
    [Fact]
    public void PeImage_TlsCharacteristicsReservedBits_EmitSpecViolation_AndStrictModeFails()
    {
        byte[] mutated = File.ReadAllBytes(GetMinimalFixturePath());
        Assert.True(TrySetTlsCharacteristics(mutated, 0x00000001u));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("IMAGE_TLS_DIRECTORY.Characteristics has reserved bits set", StringComparison.Ordinal));

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

    private static bool TrySetTlsCharacteristics(byte[] data, uint characteristics)
    {
        if (!TryGetPeLayout(data, out int dataDirectoryOffset, out int sectionTableOffset, out bool isPe32Plus))
        {
            return false;
        }

        int firstSectionOffset = sectionTableOffset;
        uint sectionVirtualAddress = BitConverter.ToUInt32(data, firstSectionOffset + 12);
        uint sectionRawSize = BitConverter.ToUInt32(data, firstSectionOffset + 16);
        uint sectionRawPointer = BitConverter.ToUInt32(data, firstSectionOffset + 20);
        if (sectionRawSize < 0xC0 || sectionRawPointer > int.MaxValue)
        {
            return false;
        }

        int tlsDirectorySize = isPe32Plus ? 40 : 24;
        uint tlsOffsetInSection = 0x80;
        long tlsRawOffset = sectionRawPointer + tlsOffsetInSection;
        if (tlsRawOffset < 0 ||
            tlsRawOffset + tlsDirectorySize > data.Length ||
            tlsOffsetInSection + tlsDirectorySize > sectionRawSize)
        {
            return false;
        }

        int tlsDirectoryOffset = dataDirectoryOffset + (9 * 8);
        uint tlsRva = sectionVirtualAddress + tlsOffsetInSection;
        WriteUInt32(data, tlsDirectoryOffset, tlsRva);
        WriteUInt32(data, tlsDirectoryOffset + 4, (uint)tlsDirectorySize);

        int rawOffset = (int)tlsRawOffset;
        for (int i = 0; i < tlsDirectorySize; i++)
        {
            data[rawOffset + i] = 0;
        }

        int characteristicsOffset = rawOffset + (isPe32Plus ? 36 : 20);
        WriteUInt32(data, characteristicsOffset, characteristics);
        return true;
    }

    private static bool TryGetPeLayout(
        byte[] data,
        out int dataDirectoryOffset,
        out int sectionTableOffset,
        out bool isPe32Plus)
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
