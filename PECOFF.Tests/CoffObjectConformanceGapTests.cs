using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffObjectConformanceGapTests
{
    [Fact]
    public void CoffRelocation_NonPair_ResolvesByFullSymbolTableIndex_WithAuxEntries()
    {
        byte[] fileSymbol = CreateShortNameSymbol(".file", sectionNumber: 0, storageClass: 0x67, auxCount: 1);
        byte[] fileAux = new byte[18];
        Encoding.ASCII.GetBytes("unit.c").CopyTo(fileAux, 0);
        byte[] targetSymbol = CreateShortNameSymbol("target", sectionNumber: 1, storageClass: 0x02, auxCount: 0);

        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sectionName: CreateSectionName(".text"),
            relocations: new[] { (0x10u, 2u, (ushort)0x0006) },
            symbols: new[] { fileSymbol, fileAux, targetSymbol },
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            CoffRelocationInfo relocation = Assert.Single(parser.CoffRelocations);
            Assert.Equal((uint)2, relocation.SymbolIndex);
            Assert.Equal("target", relocation.SymbolName);
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("invalid SymbolTableIndex", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData((ushort)0x01C2, (ushort)0x0016)] // ARM_PAIR
    [InlineData((ushort)0x01F0, (ushort)0x0012)] // PPC_PAIR
    [InlineData((ushort)0x0166, (ushort)0x0025)] // MIPS_PAIR
    [InlineData((ushort)0x9041, (ushort)0x000B)] // M32R_PAIR
    [InlineData((ushort)0x01A6, (ushort)0x0018)] // SHM_PAIR
    public void CoffRelocation_PairTypes_TreatSymbolTableIndexAsDisplacement(ushort machine, ushort relocationType)
    {
        const uint displacement = 0x01020304u;
        byte[] symbol = CreateShortNameSymbol("sym", sectionNumber: 1, storageClass: 0x02, auxCount: 0);
        byte[] data = BuildCoffObject(
            machine,
            CreateSectionName(".text"),
            new[] { (0x20u, displacement, relocationType) },
            new[] { symbol },
            Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            CoffRelocationInfo relocation = Assert.Single(parser.CoffRelocations);
            Assert.Equal(displacement, relocation.SymbolIndex);
            Assert.Equal(string.Empty, relocation.SymbolName);
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("invalid SymbolTableIndex", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData((ushort)0x01C2, (ushort)0x0010, (ushort)0x0016)] // ARM_MOV32 -> ARM_PAIR
    [InlineData((ushort)0x01F0, (ushort)0x0010, (ushort)0x0012)] // PPC REFHI -> PAIR
    [InlineData((ushort)0x0166, (ushort)0x0004, (ushort)0x0025)] // MIPS REFHI -> PAIR
    [InlineData((ushort)0x9041, (ushort)0x0009, (ushort)0x000B)] // M32R REFHI -> PAIR
    [InlineData((ushort)0x01A6, (ushort)0x0016, (ushort)0x0018)] // SHM_RELLO -> SHM_PAIR
    public void CoffRelocation_PairTypes_ValidOrdering_DoesNotWarn(ushort machine, ushort leadingType, ushort pairType)
    {
        const uint displacement = 0x0BADF00Du;
        byte[] symbol = CreateShortNameSymbol("sym", sectionNumber: 1, storageClass: 0x02, auxCount: 0);
        byte[] data = BuildCoffObject(
            machine,
            CreateSectionName(".text"),
            new[]
            {
                (0x20u, 0u, leadingType),
                (0x24u, displacement, pairType)
            },
            new[] { symbol },
            Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Equal(2, parser.CoffRelocations.Length);
            Assert.Equal(string.Empty, parser.CoffRelocations[1].SymbolName);
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("must immediately follow", StringComparison.Ordinal));
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("invalid SymbolTableIndex", StringComparison.Ordinal));

            PECOFF strict = new PECOFF(path, new PECOFFOptions { StrictMode = true });
            Assert.Equal(2, strict.CoffRelocations.Length);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData((ushort)0x01C2, (ushort)0x000A, (ushort)0x0016)] // ARM REL32 -> ARM_PAIR (invalid)
    [InlineData((ushort)0x01F0, (ushort)0x0002, (ushort)0x0012)] // PPC ADDR32 -> PAIR (invalid)
    [InlineData((ushort)0x0166, (ushort)0x0002, (ushort)0x0025)] // MIPS REFWORD -> PAIR (invalid)
    [InlineData((ushort)0x9041, (ushort)0x0008, (ushort)0x000B)] // M32R REFHALF -> PAIR (invalid)
    [InlineData((ushort)0x01A6, (ushort)0x0002, (ushort)0x0018)] // SH DIRECT32 -> SHM_PAIR (invalid)
    public void CoffRelocation_PairTypes_InvalidOrdering_EmitsSpecWarning_AndStrictModeFails(ushort machine, ushort leadingType, ushort pairType)
    {
        const uint displacement = 0x01020304u;
        byte[] symbol = CreateShortNameSymbol("sym", sectionNumber: 1, storageClass: 0x02, auxCount: 0);
        byte[] data = BuildCoffObject(
            machine,
            CreateSectionName(".text"),
            new[]
            {
                (0x20u, 0u, leadingType),
                (0x24u, displacement, pairType)
            },
            new[] { symbol },
            Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF", StringComparison.Ordinal) &&
                           warning.Contains("must immediately follow", StringComparison.Ordinal));
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("invalid SymbolTableIndex", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffRelocation_InvalidSymbolTableIndex_EmitsSpecWarning_AndStrictModeFails()
    {
        byte[] symbol = CreateShortNameSymbol("sym", sectionNumber: 1, storageClass: 0x02, auxCount: 0);
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sectionName: CreateSectionName(".text"),
            relocations: new[] { (0x10u, 99u, (ushort)0x0006) },
            symbols: new[] { symbol },
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF relocation entry", StringComparison.Ordinal) &&
                           warning.Contains("invalid SymbolTableIndex 99", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffSectionLongName_SlashOffset_ResolvesAcrossSectionViews()
    {
        const string longSectionName = ".really_long_section_name";
        byte[] symbol = CreateShortNameSymbol("sym", sectionNumber: 1, storageClass: 0x02, auxCount: 0);
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sectionName: CreateSectionName("/4"),
            relocations: new[] { (0x10u, 0u, (ushort)0x0006) },
            symbols: new[] { symbol },
            stringTablePayload: Encoding.UTF8.GetBytes(longSectionName + "\0"));

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Single(parser.SectionHeaders);
            Assert.Equal(longSectionName, parser.SectionHeaders[0].Name);
            Assert.Single(parser.SectionPermissions);
            Assert.Equal(longSectionName, parser.SectionPermissions[0].Name);
            Assert.Single(parser.CoffSymbols);
            Assert.Equal(longSectionName, parser.CoffSymbols[0].SectionName);
            Assert.Single(parser.CoffRelocations);
            Assert.Equal(longSectionName, parser.CoffRelocations[0].SectionName);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffSectionLongName_NonNumericOffset_EmitsSpecWarning_AndStrictModeFails()
    {
        byte[] symbol = CreateShortNameSymbol("sym", sectionNumber: 1, storageClass: 0x02, auxCount: 0);
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sectionName: CreateSectionName("/abc"),
            relocations: Array.Empty<(uint VirtualAddress, uint SymbolIndex, ushort Type)>(),
            symbols: new[] { symbol },
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF section header name", StringComparison.Ordinal) &&
                           warning.Contains("non-numeric long-name offset", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffSectionLongName_MissingStringTableOffset_EmitsSpecWarning_AndStrictModeFails()
    {
        byte[] symbol = CreateShortNameSymbol("sym", sectionNumber: 1, storageClass: 0x02, auxCount: 0);
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sectionName: CreateSectionName("/99"),
            relocations: Array.Empty<(uint VirtualAddress, uint SymbolIndex, ushort Type)>(),
            symbols: new[] { symbol },
            stringTablePayload: Encoding.UTF8.GetBytes("name\0"));

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF section header long-name offset /99", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffStringTable_InvalidUtf8_EmitsSpecWarning_AndStrictModeFails()
    {
        byte[] symbol = CreateLongNameSymbol(stringTableOffset: 4, sectionNumber: 1, storageClass: 0x02);
        byte[] invalidUtf8 = new byte[] { 0xC3, 0x28, 0x00 };
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sectionName: CreateSectionName(".text"),
            relocations: Array.Empty<(uint VirtualAddress, uint SymbolIndex, ushort Type)>(),
            symbols: new[] { symbol },
            stringTablePayload: invalidUtf8);

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Single(parser.CoffSymbols);
            Assert.Equal("Ã(", parser.CoffSymbols[0].Name);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF string-table entry at offset 4", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string WriteTemp(byte[] data)
    {
        string path = Path.GetTempFileName();
        File.WriteAllBytes(path, data);
        return path;
    }

    private static byte[] BuildCoffObject(
        ushort machine,
        byte[] sectionName,
        (uint VirtualAddress, uint SymbolIndex, ushort Type)[] relocations,
        byte[][] symbols,
        byte[] stringTablePayload)
    {
        const int coffHeaderSize = 20;
        const int sectionHeaderSize = 40;
        const int relocationSize = 10;
        relocations ??= Array.Empty<(uint VirtualAddress, uint SymbolIndex, ushort Type)>();
        symbols ??= Array.Empty<byte[]>();
        int relocationCount = relocations.Length;
        int relocationOffset = coffHeaderSize + sectionHeaderSize;
        int symbolTableOffset = relocationOffset + (relocationCount * relocationSize);
        int symbolCount = symbols.Length;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write(machine);
        writer.Write((ushort)1); // NumberOfSections
        writer.Write(0x5E2B1234u);
        writer.Write(symbolCount == 0 ? 0u : (uint)symbolTableOffset);
        writer.Write((uint)symbolCount);
        writer.Write((ushort)0); // SizeOfOptionalHeader
        writer.Write((ushort)0); // Characteristics

        writer.Write(sectionName);
        writer.Write(0u); // VirtualSize
        writer.Write(0u); // VirtualAddress
        writer.Write(0u); // SizeOfRawData
        writer.Write(0u); // PointerToRawData
        writer.Write(relocationCount == 0 ? 0u : (uint)relocationOffset);
        writer.Write(0u); // PointerToLinenumbers
        writer.Write((ushort)relocationCount);
        writer.Write((ushort)0); // NumberOfLinenumbers
        writer.Write(0x60000020u); // Characteristics

        for (int i = 0; i < relocationCount; i++)
        {
            writer.Write(relocations[i].VirtualAddress);
            writer.Write(relocations[i].SymbolIndex);
            writer.Write(relocations[i].Type);
        }

        for (int i = 0; i < symbolCount; i++)
        {
            writer.Write(symbols[i] ?? Array.Empty<byte>());
        }

        if (symbolCount > 0)
        {
            byte[] payload = stringTablePayload ?? Array.Empty<byte>();
            writer.Write((uint)(4 + payload.Length));
            writer.Write(payload);
        }

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] CreateSectionName(string name)
    {
        byte[] result = new byte[8];
        Encoding.ASCII.GetBytes(name ?? string.Empty).CopyTo(result, 0);
        return result;
    }

    private static byte[] CreateShortNameSymbol(string name, short sectionNumber, byte storageClass, byte auxCount, ushort type = 0, uint value = 0)
    {
        byte[] symbol = new byte[18];
        Encoding.ASCII.GetBytes(name ?? string.Empty).CopyTo(symbol, 0);
        WriteUInt32(symbol, 8, value);
        WriteInt16(symbol, 12, sectionNumber);
        WriteUInt16(symbol, 14, type);
        symbol[16] = storageClass;
        symbol[17] = auxCount;
        return symbol;
    }

    private static byte[] CreateLongNameSymbol(uint stringTableOffset, short sectionNumber, byte storageClass, byte auxCount = 0, ushort type = 0, uint value = 0)
    {
        byte[] symbol = new byte[18];
        WriteUInt32(symbol, 0, 0);
        WriteUInt32(symbol, 4, stringTableOffset);
        WriteUInt32(symbol, 8, value);
        WriteInt16(symbol, 12, sectionNumber);
        WriteUInt16(symbol, 14, type);
        symbol[16] = storageClass;
        symbol[17] = auxCount;
        return symbol;
    }

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
    }

    private static void WriteInt16(byte[] data, int offset, short value)
    {
        WriteUInt16(data, offset, unchecked((ushort)value));
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)((value >> 16) & 0xFF);
        data[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
