using System;
using System.IO;
using PECoff;
using Xunit;

public class ImportThunkReservedBitsComplianceTests
{
    [Fact]
    public void PeImage_ImportThunkOrdinalReservedBits_EmitSpecViolation_AndStrictModeFails()
    {
        byte[] mutated = File.ReadAllBytes(GetFixturePath("minimal-x86.exe"));
        Assert.True(TryInjectImportTableWithOrdinalReservedBits(mutated));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("imports by ordinal but has reserved bits set", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void PeImage_ImportThunkNameReservedHighBitsPe32Plus_EmitSpecViolation_AndStrictModeFails()
    {
        byte[] mutated = File.ReadAllBytes(GetFixturePath("minimal-x64.exe"));
        Assert.True(TryInjectImportTableWithNameReservedHighBits(mutated));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("imports by name but has reserved high bits set", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    private static bool TryInjectImportTableWithOrdinalReservedBits(byte[] data)
    {
        if (!TryGetPeLayout(data, out int dataDirectoryOffset, out int sectionTableOffset, out bool isPe32Plus) || isPe32Plus)
        {
            return false;
        }

        if (!TryGetFirstSectionLayout(data, sectionTableOffset, out uint sectionRva, out uint sectionRawSize, out uint sectionRawPointer))
        {
            return false;
        }

        const int importDescriptorSize = 20;
        const uint descriptorOffsetInSection = 0x40;
        const uint intOffsetInSection = 0x80;
        const uint iatOffsetInSection = 0xA0;
        const uint dllNameOffsetInSection = 0xD0;

        if (!ValidateSectionPlacement(sectionRawSize, descriptorOffsetInSection, importDescriptorSize * 2) ||
            !ValidateSectionPlacement(sectionRawSize, intOffsetInSection, 8) ||
            !ValidateSectionPlacement(sectionRawSize, iatOffsetInSection, 8) ||
            !ValidateSectionPlacement(sectionRawSize, dllNameOffsetInSection, 16))
        {
            return false;
        }

        int descriptorRaw = checked((int)sectionRawPointer + (int)descriptorOffsetInSection);
        int intRaw = checked((int)sectionRawPointer + (int)intOffsetInSection);
        int iatRaw = checked((int)sectionRawPointer + (int)iatOffsetInSection);
        int dllRaw = checked((int)sectionRawPointer + (int)dllNameOffsetInSection);
        if (!ValidateFilePlacement(data, descriptorRaw, importDescriptorSize * 2) ||
            !ValidateFilePlacement(data, intRaw, 8) ||
            !ValidateFilePlacement(data, iatRaw, 8) ||
            !ValidateFilePlacement(data, dllRaw, 16))
        {
            return false;
        }

        uint descriptorRva = sectionRva + descriptorOffsetInSection;
        uint intRva = sectionRva + intOffsetInSection;
        uint iatRva = sectionRva + iatOffsetInSection;
        uint dllRva = sectionRva + dllNameOffsetInSection;

        int importDirectoryOffset = dataDirectoryOffset + (1 * 8);
        WriteUInt32(data, importDirectoryOffset, descriptorRva);
        WriteUInt32(data, importDirectoryOffset + 4, (uint)(importDescriptorSize * 2));

        ZeroRange(data, descriptorRaw, importDescriptorSize * 2);
        WriteUInt32(data, descriptorRaw + 0, intRva);
        WriteUInt32(data, descriptorRaw + 12, dllRva);
        WriteUInt32(data, descriptorRaw + 16, iatRva);

        uint thunkWithReservedOrdinalBits = 0x81230001u;
        WriteUInt32(data, intRaw + 0, thunkWithReservedOrdinalBits);
        WriteUInt32(data, intRaw + 4, 0u);
        WriteUInt32(data, iatRaw + 0, thunkWithReservedOrdinalBits);
        WriteUInt32(data, iatRaw + 4, 0u);

        WriteAsciiZ(data, dllRaw, "test.dll");
        return true;
    }

    private static bool TryInjectImportTableWithNameReservedHighBits(byte[] data)
    {
        if (!TryGetPeLayout(data, out int dataDirectoryOffset, out int sectionTableOffset, out bool isPe32Plus) || !isPe32Plus)
        {
            return false;
        }

        if (!TryGetFirstSectionLayout(data, sectionTableOffset, out uint sectionRva, out uint sectionRawSize, out uint sectionRawPointer))
        {
            return false;
        }

        const int importDescriptorSize = 20;
        const uint descriptorOffsetInSection = 0x40;
        const uint intOffsetInSection = 0x80;
        const uint iatOffsetInSection = 0xA0;
        const uint nameOffsetInSection = 0xC0;
        const uint dllNameOffsetInSection = 0xD8;

        if (!ValidateSectionPlacement(sectionRawSize, descriptorOffsetInSection, importDescriptorSize * 2) ||
            !ValidateSectionPlacement(sectionRawSize, intOffsetInSection, 16) ||
            !ValidateSectionPlacement(sectionRawSize, iatOffsetInSection, 16) ||
            !ValidateSectionPlacement(sectionRawSize, nameOffsetInSection, 24) ||
            !ValidateSectionPlacement(sectionRawSize, dllNameOffsetInSection, 16))
        {
            return false;
        }

        int descriptorRaw = checked((int)sectionRawPointer + (int)descriptorOffsetInSection);
        int intRaw = checked((int)sectionRawPointer + (int)intOffsetInSection);
        int iatRaw = checked((int)sectionRawPointer + (int)iatOffsetInSection);
        int nameRaw = checked((int)sectionRawPointer + (int)nameOffsetInSection);
        int dllRaw = checked((int)sectionRawPointer + (int)dllNameOffsetInSection);
        if (!ValidateFilePlacement(data, descriptorRaw, importDescriptorSize * 2) ||
            !ValidateFilePlacement(data, intRaw, 16) ||
            !ValidateFilePlacement(data, iatRaw, 16) ||
            !ValidateFilePlacement(data, nameRaw, 24) ||
            !ValidateFilePlacement(data, dllRaw, 16))
        {
            return false;
        }

        uint descriptorRva = sectionRva + descriptorOffsetInSection;
        uint intRva = sectionRva + intOffsetInSection;
        uint iatRva = sectionRva + iatOffsetInSection;
        uint nameRva = sectionRva + nameOffsetInSection;
        uint dllRva = sectionRva + dllNameOffsetInSection;

        int importDirectoryOffset = dataDirectoryOffset + (1 * 8);
        WriteUInt32(data, importDirectoryOffset, descriptorRva);
        WriteUInt32(data, importDirectoryOffset + 4, (uint)(importDescriptorSize * 2));

        ZeroRange(data, descriptorRaw, importDescriptorSize * 2);
        WriteUInt32(data, descriptorRaw + 0, intRva);
        WriteUInt32(data, descriptorRaw + 12, dllRva);
        WriteUInt32(data, descriptorRaw + 16, iatRva);

        ulong thunkWithReservedNameBits = (1UL << 40) | nameRva;
        WriteUInt64(data, intRaw + 0, thunkWithReservedNameBits);
        WriteUInt64(data, intRaw + 8, 0UL);
        WriteUInt64(data, iatRaw + 0, thunkWithReservedNameBits);
        WriteUInt64(data, iatRaw + 8, 0UL);

        WriteUInt16(data, nameRaw + 0, 0);
        WriteAsciiZ(data, nameRaw + 2, "FuncA");
        WriteAsciiZ(data, dllRaw, "test64.dll");
        return true;
    }

    private static bool TryGetFirstSectionLayout(byte[] data, int sectionTableOffset, out uint sectionRva, out uint sectionRawSize, out uint sectionRawPointer)
    {
        sectionRva = 0;
        sectionRawSize = 0;
        sectionRawPointer = 0;

        if (sectionTableOffset < 0 || sectionTableOffset + 40 > data.Length)
        {
            return false;
        }

        sectionRva = BitConverter.ToUInt32(data, sectionTableOffset + 12);
        sectionRawSize = BitConverter.ToUInt32(data, sectionTableOffset + 16);
        sectionRawPointer = BitConverter.ToUInt32(data, sectionTableOffset + 20);
        return sectionRawPointer <= int.MaxValue;
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

    private static string GetFixturePath(string fileName)
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", fileName);
        Assert.True(File.Exists(validPath));
        return validPath;
    }

    private static bool ValidateSectionPlacement(uint sectionRawSize, uint offsetInSection, int length)
    {
        if (length <= 0)
        {
            return false;
        }

        ulong end = (ulong)offsetInSection + (ulong)length;
        return end <= sectionRawSize;
    }

    private static bool ValidateFilePlacement(byte[] data, int offset, int length)
    {
        return offset >= 0 && length > 0 && offset + length <= data.Length;
    }

    private static void ZeroRange(byte[] data, int offset, int length)
    {
        for (int i = 0; i < length; i++)
        {
            data[offset + i] = 0;
        }
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

    private static void WriteUInt64(byte[] data, int offset, ulong value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)((value >> 16) & 0xFF);
        data[offset + 3] = (byte)((value >> 24) & 0xFF);
        data[offset + 4] = (byte)((value >> 32) & 0xFF);
        data[offset + 5] = (byte)((value >> 40) & 0xFF);
        data[offset + 6] = (byte)((value >> 48) & 0xFF);
        data[offset + 7] = (byte)((value >> 56) & 0xFF);
    }

    private static void WriteAsciiZ(byte[] data, int offset, string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            data[offset + i] = (byte)value[i];
        }

        data[offset + value.Length] = 0;
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
