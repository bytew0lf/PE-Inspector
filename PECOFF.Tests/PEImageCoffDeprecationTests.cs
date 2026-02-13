using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class PEImageCoffDeprecationTests
{
    private const ushort IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
    private const ushort IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004;
    private const ushort IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008;
    private const ushort IMAGE_FILE_DEBUG_STRIPPED = 0x0200;
    private const ushort IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040;

    [Fact]
    public void PeImage_With_CoffPointers_Emits_Deprecation_Warnings()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));
        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] mutated = File.ReadAllBytes(validPath);
        Assert.True(TryMutateDeprecatedCoffFields(mutated));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: PE images should have COFF symbol table pointers cleared", StringComparison.Ordinal));
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: PE image section", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void CoffObject_Does_Not_Emit_Image_Deprecation_Warnings()
    {
        byte[] data = BuildCoffObjectWithLinePointers();
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);

            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: PE images should have COFF symbol table pointers cleared", StringComparison.Ordinal));
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: PE image section", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PeImage_With_SectionRelocationPointers_Emits_Deprecation_Warning_AndStrictModeFails()
    {
        byte[] mutated = File.ReadAllBytes(GetMinimalFixturePath());
        Assert.True(TryMutateImageSectionRelocationFields(mutated, pointerToRelocations: 0x00000300u, numberOfRelocations: 2));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: PE image section", StringComparison.Ordinal) &&
                           warning.Contains("should not use COFF relocations", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void PeImage_RelocsStripped_Set_WithRelocationDirectory_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] mutated = File.ReadAllBytes(GetMinimalFixturePath());
        Assert.True(TryMutateRelocsStrippedSemantics(
            mutated,
            setRelocsStripped: true,
            ensureDynamicBase: false,
            clearRelocationDirectory: false));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_FILE_RELOCS_STRIPPED is set but relocation information is still present", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void PeImage_RelocsStripped_Clear_DynamicBaseWithoutRelocs_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] mutated = File.ReadAllBytes(GetMinimalFixturePath());
        Assert.True(TryMutateRelocsStrippedSemantics(
            mutated,
            setRelocsStripped: false,
            ensureDynamicBase: true,
            clearRelocationDirectory: true));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_FILE_RELOCS_STRIPPED is clear while no relocation information is present and DYNAMIC_BASE is enabled", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Theory]
    [InlineData(true, true, true)]   // stripped + no reloc dir + no DYNAMIC_BASE
    [InlineData(false, false, true)] // not stripped + reloc dir present + DYNAMIC_BASE
    public void PeImage_RelocsStripped_ValidCases_DoNotEmitRelocsStrippedSpecViolation(
        bool setRelocsStripped,
        bool clearRelocationDirectory,
        bool ensureDynamicBase)
    {
        byte[] mutated = File.ReadAllBytes(GetMinimalFixturePath());
        Assert.True(TryMutateRelocsStrippedSemantics(
            mutated,
            setRelocsStripped,
            ensureDynamicBase,
            clearRelocationDirectory));

        if (setRelocsStripped && clearRelocationDirectory)
        {
            Assert.True(TryMutateDllDynamicBase(mutated, enabled: false));
        }

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_FILE_RELOCS_STRIPPED is ", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void PeImage_StrippedCharacteristics_WithContradictoryData_EmitWarnings_AndStrictModeFails()
    {
        byte[] mutated = File.ReadAllBytes(GetMinimalFixturePath());
        Assert.True(TryMutateImageStrippedCharacteristicContradictions(mutated));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_FILE_LINE_NUMS_STRIPPED is set but COFF line-number data is still present", StringComparison.Ordinal));
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_FILE_LOCAL_SYMS_STRIPPED is set but COFF symbol table data is present", StringComparison.Ordinal));
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_FILE_DEBUG_STRIPPED is set but a debug directory is still present", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void PeImage_StrippedCharacteristics_WithoutContradictoryData_DoNotWarn()
    {
        byte[] mutated = File.ReadAllBytes(GetMinimalFixturePath());
        Assert.True(TryMutateImageStrippedCharacteristicConsistentState(mutated));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("IMAGE_FILE_LINE_NUMS_STRIPPED is set", StringComparison.Ordinal));
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("IMAGE_FILE_LOCAL_SYMS_STRIPPED is set", StringComparison.Ordinal));
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("IMAGE_FILE_DEBUG_STRIPPED is set", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    private static bool TryMutateDeprecatedCoffFields(byte[] data)
    {
        if (!TryGetPeLayout(
                data,
                out int fileHeaderOffset,
                out _,
                out _,
                out int sectionTableOffset,
                out ushort numberOfSections,
                out _))
        {
            return false;
        }

        WriteUInt32(data, fileHeaderOffset + 8, 0x00000200); // PointerToSymbolTable
        WriteUInt32(data, fileHeaderOffset + 12, 1); // NumberOfSymbols

        int firstSectionOffset = sectionTableOffset;
        WriteUInt32(data, firstSectionOffset + 20, 0x00000340); // PointerToRelocations
        WriteUInt16(data, firstSectionOffset + 32, 1); // NumberOfRelocations
        WriteUInt32(data, firstSectionOffset + 24, 0x00000300); // PointerToLinenumbers
        WriteUInt16(data, firstSectionOffset + 34, 2); // NumberOfLinenumbers
        return true;
    }

    private static byte[] BuildCoffObjectWithLinePointers()
    {
        const int coffHeaderSize = 20;
        const int sectionHeaderSize = 40;
        const int lineNumberSize = 6;
        const int symbolSize = 18;
        int lineOffset = coffHeaderSize + sectionHeaderSize;
        int symbolOffset = lineOffset + lineNumberSize;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write((ushort)0x014c); // machine
        writer.Write((ushort)1); // sections
        writer.Write(0u); // timestamp
        writer.Write(symbolOffset); // ptr symbol table
        writer.Write(1u); // symbol count
        writer.Write((ushort)0); // optional size
        writer.Write((ushort)0); // characteristics

        byte[] name = new byte[8];
        Encoding.ASCII.GetBytes(".text").CopyTo(name, 0);
        writer.Write(name);
        writer.Write(0u); // vsize
        writer.Write(0u); // vaddr
        writer.Write(0u); // raw size
        writer.Write(0u); // raw ptr
        writer.Write(0u); // reloc ptr
        writer.Write(lineOffset); // line ptr
        writer.Write((ushort)0); // reloc count
        writer.Write((ushort)1); // line count
        writer.Write(0x60000020u);

        writer.Write(0u); // line virtual address
        writer.Write((ushort)1); // line number

        byte[] symbol = new byte[symbolSize];
        Encoding.ASCII.GetBytes("sym").CopyTo(symbol, 0);
        BitConverter.GetBytes(0u).CopyTo(symbol, 8);
        BitConverter.GetBytes((short)1).CopyTo(symbol, 12);
        BitConverter.GetBytes((ushort)0).CopyTo(symbol, 14);
        symbol[16] = 2;
        symbol[17] = 0;
        writer.Write(symbol);
        writer.Write(4u); // empty string table

        writer.Flush();
        return ms.ToArray();
    }

    private static string GetMinimalFixturePath()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));
        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));
        return validPath;
    }

    private static bool TryMutateImageSectionRelocationFields(byte[] data, uint pointerToRelocations, ushort numberOfRelocations)
    {
        if (!TryGetPeLayout(
                data,
                out _,
                out _,
                out _,
                out int sectionTableOffset,
                out _,
                out _))
        {
            return false;
        }

        int firstSectionOffset = sectionTableOffset;
        WriteUInt32(data, firstSectionOffset + 20, pointerToRelocations);
        WriteUInt16(data, firstSectionOffset + 32, numberOfRelocations);
        return true;
    }

    private static bool TryMutateRelocsStrippedSemantics(
        byte[] data,
        bool setRelocsStripped,
        bool ensureDynamicBase,
        bool clearRelocationDirectory)
    {
        if (!TryGetPeLayout(
                data,
                out int fileHeaderOffset,
                out _,
                out int dataDirectoryOffset,
                out int sectionTableOffset,
                out _,
                out _))
        {
            return false;
        }

        ushort characteristics = BitConverter.ToUInt16(data, fileHeaderOffset + 18);
        if (setRelocsStripped)
        {
            characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        }
        else
        {
            characteristics = (ushort)(characteristics & ~IMAGE_FILE_RELOCS_STRIPPED);
        }

        WriteUInt16(data, fileHeaderOffset + 18, characteristics);

        if (!TryMutateDllDynamicBase(data, ensureDynamicBase))
        {
            return false;
        }

        int baseRelocDirectoryOffset = dataDirectoryOffset + (5 * 8);
        if (clearRelocationDirectory)
        {
            WriteUInt32(data, baseRelocDirectoryOffset, 0);
            WriteUInt32(data, baseRelocDirectoryOffset + 4, 0);
            WriteUInt32(data, sectionTableOffset + 20, 0); // PointerToRelocations
            WriteUInt16(data, sectionTableOffset + 32, 0); // NumberOfRelocations
        }
        else
        {
            uint currentRva = BitConverter.ToUInt32(data, baseRelocDirectoryOffset);
            uint currentSize = BitConverter.ToUInt32(data, baseRelocDirectoryOffset + 4);
            if (currentRva == 0 || currentSize == 0)
            {
                WriteUInt32(data, baseRelocDirectoryOffset, 0x2000);
                WriteUInt32(data, baseRelocDirectoryOffset + 4, 0x10);
            }
        }

        return true;
    }

    private static bool TryMutateDllDynamicBase(byte[] data, bool enabled)
    {
        if (!TryGetPeLayout(
                data,
                out _,
                out int optionalHeaderOffset,
                out _,
                out _,
                out _,
                out bool isPe32Plus))
        {
            return false;
        }

        int dllCharacteristicsOffset = optionalHeaderOffset + (isPe32Plus ? 0x5E : 0x46);
        ushort dllCharacteristics = BitConverter.ToUInt16(data, dllCharacteristicsOffset);
        if (enabled)
        {
            dllCharacteristics |= IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE;
        }
        else
        {
            dllCharacteristics = (ushort)(dllCharacteristics & ~IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
        }

        WriteUInt16(data, dllCharacteristicsOffset, dllCharacteristics);
        return true;
    }

    private static bool TryMutateImageStrippedCharacteristicContradictions(byte[] data)
    {
        if (!TryGetPeLayout(
                data,
                out int fileHeaderOffset,
                out _,
                out int dataDirectoryOffset,
                out int sectionTableOffset,
                out _,
                out _))
        {
            return false;
        }

        ushort characteristics = BitConverter.ToUInt16(data, fileHeaderOffset + 18);
        characteristics |= IMAGE_FILE_LINE_NUMS_STRIPPED;
        characteristics |= IMAGE_FILE_LOCAL_SYMS_STRIPPED;
        characteristics |= IMAGE_FILE_DEBUG_STRIPPED;
        WriteUInt16(data, fileHeaderOffset + 18, characteristics);

        WriteUInt32(data, fileHeaderOffset + 8, 0x00000200); // PointerToSymbolTable
        WriteUInt32(data, fileHeaderOffset + 12, 1); // NumberOfSymbols

        WriteUInt32(data, sectionTableOffset + 24, 0x00000300); // PointerToLinenumbers
        WriteUInt16(data, sectionTableOffset + 34, 2); // NumberOfLinenumbers

        int debugDirectoryOffset = dataDirectoryOffset + (6 * 8);
        uint debugRva = BitConverter.ToUInt32(data, debugDirectoryOffset);
        uint debugSize = BitConverter.ToUInt32(data, debugDirectoryOffset + 4);
        if (debugRva == 0 || debugSize == 0)
        {
            WriteUInt32(data, debugDirectoryOffset, 0x3000);
            WriteUInt32(data, debugDirectoryOffset + 4, 0x1C);
        }

        return true;
    }

    private static bool TryMutateImageStrippedCharacteristicConsistentState(byte[] data)
    {
        if (!TryGetPeLayout(
                data,
                out int fileHeaderOffset,
                out _,
                out int dataDirectoryOffset,
                out int sectionTableOffset,
                out _,
                out _))
        {
            return false;
        }

        ushort characteristics = BitConverter.ToUInt16(data, fileHeaderOffset + 18);
        characteristics |= IMAGE_FILE_LINE_NUMS_STRIPPED;
        characteristics |= IMAGE_FILE_LOCAL_SYMS_STRIPPED;
        characteristics |= IMAGE_FILE_DEBUG_STRIPPED;
        WriteUInt16(data, fileHeaderOffset + 18, characteristics);

        WriteUInt32(data, fileHeaderOffset + 8, 0); // PointerToSymbolTable
        WriteUInt32(data, fileHeaderOffset + 12, 0); // NumberOfSymbols
        WriteUInt32(data, sectionTableOffset + 24, 0); // PointerToLinenumbers
        WriteUInt16(data, sectionTableOffset + 34, 0); // NumberOfLinenumbers

        int debugDirectoryOffset = dataDirectoryOffset + (6 * 8);
        WriteUInt32(data, debugDirectoryOffset, 0);
        WriteUInt32(data, debugDirectoryOffset + 4, 0);
        return true;
    }

    private static bool TryGetPeLayout(
        byte[] data,
        out int fileHeaderOffset,
        out int optionalHeaderOffset,
        out int dataDirectoryOffset,
        out int sectionTableOffset,
        out ushort numberOfSections,
        out bool isPe32Plus)
    {
        fileHeaderOffset = 0;
        optionalHeaderOffset = 0;
        dataDirectoryOffset = 0;
        sectionTableOffset = 0;
        numberOfSections = 0;
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

        fileHeaderOffset = peOffset + 4;
        numberOfSections = BitConverter.ToUInt16(data, fileHeaderOffset + 2);
        ushort sizeOfOptionalHeader = BitConverter.ToUInt16(data, fileHeaderOffset + 16);
        optionalHeaderOffset = fileHeaderOffset + 20;
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
