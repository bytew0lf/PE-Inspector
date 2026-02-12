using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffRelocationOverflowTests
{
    [Fact]
    public void CoffRelocationOverflow_UsesMarkerCount_AndSkipsMarkerEntry()
    {
        const int markerCount = 65535;
        (uint VirtualAddress, uint SymbolIndex, ushort Type)[] entries = new (uint, uint, ushort)[markerCount];
        entries[0] = ((uint)markerCount, 0u, (ushort)0x0000); // overflow marker
        for (int i = 1; i < markerCount; i++)
        {
            entries[i] = ((uint)(0x20 + (i & 0x0FFF)), 0u, 0x0006); // DIR32
        }

        byte[] data = BuildCoffObject(
            numberOfRelocationsField: ushort.MaxValue,
            setOverflowFlag: true,
            relocationEntries: entries,
            includeSymbol: true);
        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Equal(markerCount - 1, parser.CoffRelocations.Length);
            Assert.Equal((ushort)0x0006, parser.CoffRelocations[0].Type);
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("Overflow COFF relocation marker", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffRelocationOverflow_FlagMismatch_EmitsSpecWarnings_AndStrictModeFails()
    {
        byte[] data = BuildCoffObject(
            numberOfRelocationsField: 2,
            setOverflowFlag: true,
            relocationEntries: new[]
            {
                (0x10u, 0u, (ushort)0x0006),
                (0x20u, 0u, (ushort)0x0006)
            },
            includeSymbol: true);
        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("sets IMAGE_SCN_LNK_NRELOC_OVFL", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffRelocationOverflow_NumberFFFFWithoutFlag_EmitsSpecWarning_AndStrictModeFails()
    {
        byte[] data = BuildCoffObject(
            numberOfRelocationsField: ushort.MaxValue,
            setOverflowFlag: false,
            relocationEntries: new[]
            {
                (0x10u, 0u, (ushort)0x0006)
            },
            includeSymbol: true);
        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("NumberOfRelocations=0xFFFF without IMAGE_SCN_LNK_NRELOC_OVFL", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffRelocationOverflow_MarkerMissingOrTruncated_EmitsSpecWarnings_AndStrictModeFails()
    {
        byte[] data = BuildCoffObject(
            numberOfRelocationsField: ushort.MaxValue,
            setOverflowFlag: true,
            relocationEntries: Array.Empty<(uint VirtualAddress, uint SymbolIndex, ushort Type)>(),
            includeSymbol: false,
            relocationPointerOverride: 0x4000u);
        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("Overflow COFF relocation marker", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffRelocationOverflow_TruncatedTable_EmitsWarning_AndStrictModeFails()
    {
        byte[] data = BuildCoffObject(
            numberOfRelocationsField: ushort.MaxValue,
            setOverflowFlag: true,
            relocationEntries: new[]
            {
                (70000u, 0u, (ushort)0x0000), // overflow marker count
                (0x10u, 0u, (ushort)0x0006),
                (0x20u, 0u, (ushort)0x0006)
            },
            includeSymbol: true);
        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("Relocation table for section .text exceeds file size", StringComparison.Ordinal));

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
        ushort numberOfRelocationsField,
        bool setOverflowFlag,
        (uint VirtualAddress, uint SymbolIndex, ushort Type)[] relocationEntries,
        bool includeSymbol,
        uint? relocationPointerOverride = null)
    {
        const int coffHeaderSize = 20;
        const int sectionHeaderSize = 40;
        const int relocationSize = 10;
        relocationEntries ??= Array.Empty<(uint VirtualAddress, uint SymbolIndex, ushort Type)>();

        int relocationDataSize = relocationEntries.Length * relocationSize;
        int relocationOffset = coffHeaderSize + sectionHeaderSize;
        int symbolTableOffset = relocationOffset + relocationDataSize;
        uint pointerToSymbolTable = includeSymbol ? (uint)symbolTableOffset : 0u;
        uint numberOfSymbols = includeSymbol ? 1u : 0u;
        uint pointerToRelocations = relocationPointerOverride ?? (uint)relocationOffset;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write((ushort)0x014C); // x86
        writer.Write((ushort)1); // NumberOfSections
        writer.Write(0x5E2B1234u);
        writer.Write(pointerToSymbolTable);
        writer.Write(numberOfSymbols);
        writer.Write((ushort)0);
        writer.Write((ushort)0);

        byte[] name = new byte[8];
        Encoding.ASCII.GetBytes(".text").CopyTo(name, 0);
        writer.Write(name);
        writer.Write(0u); // VirtualSize
        writer.Write(0u); // VirtualAddress
        writer.Write(0u); // SizeOfRawData
        writer.Write(0u); // PointerToRawData
        writer.Write(pointerToRelocations);
        writer.Write(0u); // PointerToLinenumbers
        writer.Write(numberOfRelocationsField);
        writer.Write((ushort)0);
        uint characteristics = 0x60000020u;
        if (setOverflowFlag)
        {
            characteristics |= 0x01000000u; // IMAGE_SCN_LNK_NRELOC_OVFL
        }
        writer.Write(characteristics);

        for (int i = 0; i < relocationEntries.Length; i++)
        {
            writer.Write(relocationEntries[i].VirtualAddress);
            writer.Write(relocationEntries[i].SymbolIndex);
            writer.Write(relocationEntries[i].Type);
        }

        if (includeSymbol)
        {
            byte[] symbol = new byte[18];
            Encoding.ASCII.GetBytes("sym").CopyTo(symbol, 0);
            WriteUInt32(symbol, 8, 0u);
            WriteInt16(symbol, 12, 1);
            WriteUInt16(symbol, 14, 0);
            symbol[16] = 0x02;
            symbol[17] = 0;
            writer.Write(symbol);
            writer.Write(4u); // string table size
        }

        writer.Flush();
        return ms.ToArray();
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
