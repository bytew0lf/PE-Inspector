using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffSpecialSectionComplianceTests
{
    [Fact]
    public void CoffObject_Drectve_Parses_Directives_And_Enforces_NoRelocsOrLines()
    {
        byte[] drectveData = Encoding.ASCII.GetBytes("/DEFAULTLIB:\"msvcrt.lib\" /FAILIFMISMATCH:\"_MSC_VER=1930\"\0");
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sections: new[]
            {
                new SectionSpec(
                    ".drectve",
                    drectveData,
                    characteristics: 0x00100A00u,
                    numberOfRelocations: 1,
                    numberOfLinenumbers: 1)
            },
            symbols: Array.Empty<byte[]>(),
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.NotNull(parser.CoffObject);
            Assert.NotEmpty(parser.CoffObject.Directives);
            CoffObjectInfo.CoffDirectiveInfo directive = parser.CoffObject.Directives[0];
            Assert.Contains("/DEFAULTLIB:\"msvcrt.lib\"", directive.Directives);
            Assert.Contains("/FAILIFMISMATCH:\"_MSC_VER=1930\"", directive.Directives);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains(".drectve section must not contain COFF relocations", StringComparison.Ordinal));
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains(".drectve section must not contain COFF line numbers", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_Drectve_WithoutBom_Uses_AnsiStyle_Decode()
    {
        byte[] drectveData =
        {
            (byte)'/', (byte)'D', (byte)'E', (byte)'F', (byte)'A', (byte)'U', (byte)'L', (byte)'T',
            (byte)'L', (byte)'I', (byte)'B', (byte)':', (byte)'"', 0xFC, (byte)'.', (byte)'l',
            (byte)'i', (byte)'b', (byte)'"', 0
        };

        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sections: new[]
            {
                new SectionSpec(".drectve", drectveData, characteristics: 0x00100A00u)
            },
            symbols: Array.Empty<byte[]>(),
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            CoffObjectInfo.CoffDirectiveInfo directive = Assert.Single(parser.CoffObject.Directives);
            Assert.Contains("ü.lib", directive.RawText, StringComparison.Ordinal);
            Assert.Contains("/DEFAULTLIB:\"ü.lib\"", directive.Directives);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_SxData_Parses_Handlers_And_Validates_FeatSymbol()
    {
        byte[] handler = CreateShortNameSymbol("__seh", sectionNumber: 1, storageClass: 0x02, auxCount: 0);
        byte[] feat = CreateShortNameSymbol("@feat.00", sectionNumber: 0, storageClass: 0x03, auxCount: 0, value: 0x00000001u);

        byte[] sxdata = new byte[8];
        WriteUInt32(sxdata, 0, 0u);
        WriteUInt32(sxdata, 4, 9u);

        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sections: new[]
            {
                new SectionSpec(".text", Array.Empty<byte>(), 0x60000020u),
                new SectionSpec(".sxdata", sxdata, 0x40000040u)
            },
            symbols: new[] { handler, feat },
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.NotNull(parser.CoffObject);
            Assert.NotNull(parser.CoffObject.SafeSeh);
            Assert.True(parser.CoffObject.SafeSeh.HasSxDataSection);
            Assert.True(parser.CoffObject.SafeSeh.HasFeatureSymbol);
            Assert.True(parser.CoffObject.SafeSeh.SafeSehEnabled);
            Assert.Equal(2, parser.CoffObject.SafeSeh.Handlers.Count);
            Assert.True(parser.CoffObject.SafeSeh.Handlers[0].IsResolved);
            Assert.Equal("__seh", parser.CoffObject.SafeSeh.Handlers[0].SymbolName);
            Assert.False(parser.CoffObject.SafeSeh.Handlers[1].IsResolved);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains(".sxdata entry #1 references unresolved symbol index 9", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_SafeSehFeatSymbol_WithoutSxData_Is_Accepted_On_X86()
    {
        byte[] feat = CreateShortNameSymbol("@feat.00", sectionNumber: 0, storageClass: 0x03, auxCount: 0, value: 0x00000001u);
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sections: new[]
            {
                new SectionSpec(".text", Array.Empty<byte>(), 0x60000020u)
            },
            symbols: new[] { feat },
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.NotNull(parser.CoffObject.SafeSeh);
            Assert.False(parser.CoffObject.SafeSeh.HasSxDataSection);
            Assert.True(parser.CoffObject.SafeSeh.SafeSehEnabled);
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("no .sxdata section was found", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_SafeSehMetadata_On_NonX86_Emits_SpecWarning()
    {
        byte[] feat = CreateShortNameSymbol("@feat.00", sectionNumber: 0, storageClass: 0x03, auxCount: 0, value: 0x00000001u);
        byte[] sxdata = new byte[4];
        WriteUInt32(sxdata, 0, 0);

        byte[] data = BuildCoffObject(
            machine: 0x8664,
            sections: new[]
            {
                new SectionSpec(".sxdata", sxdata, 0x40000240u)
            },
            symbols: new[] { feat },
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SAFESEH metadata", StringComparison.Ordinal) &&
                           warning.Contains("x86 COFF objects", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_FeatSymbol_NonAbsolute_Emits_SpecWarning()
    {
        byte[] feat = CreateShortNameSymbol("@feat.00", sectionNumber: 1, storageClass: 0x03, auxCount: 0, value: 0x00000001u);
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sections: new[]
            {
                new SectionSpec(".text", Array.Empty<byte>(), 0x60000020u)
            },
            symbols: new[] { feat },
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("@feat.00 should be an absolute symbol", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_DebugSubsections_Are_Parsed_From_DebugS()
    {
        byte[] debugSubsections = BuildDebugSubsectionStream();
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sections: new[]
            {
                new SectionSpec(".debug$S", debugSubsections, 0x42000040u)
            },
            symbols: Array.Empty<byte[]>(),
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.NotNull(parser.CoffObject);
            CoffObjectInfo.CoffDebugSectionInfo section = Assert.Single(parser.CoffObject.DebugSections);
            Assert.Equal(".debug$S", section.SectionName);
            Assert.Equal("CodeViewSubsections", section.Format);
            Assert.True(section.Parsed);
            Assert.Equal(2, section.Subsections.Count);
            Assert.Equal("SYM", section.Subsections[0].TypeName);
            Assert.Equal("STRING_TABLE", section.Subsections[1].TypeName);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_DebugF_On_NonX86_Emits_SpecWarning()
    {
        byte[] debugF = new byte[16];
        byte[] data = BuildCoffObject(
            machine: 0x8664,
            sections: new[]
            {
                new SectionSpec(".debug$F", debugF, 0x42000040u)
            },
            symbols: Array.Empty<byte[]>(),
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains(".debug$F is documented for x86 COFF objects only", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_GpRelSection_On_NonIa64_Emits_SpecWarning()
    {
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sections: new[]
            {
                new SectionSpec(".sdata", Array.Empty<byte>(), 0x40008040u)
            },
            symbols: Array.Empty<byte[]>(),
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("COFF object section .sdata sets IMAGE_SCN_GPREL, which is documented only for IA64 objects.", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_GpRelSection_On_Ia64_DoesNotEmit_Ia64OnlyWarning()
    {
        byte[] data = BuildCoffObject(
            machine: 0x0200,
            sections: new[]
            {
                new SectionSpec(".sdata", Array.Empty<byte>(), 0x40008040u)
            },
            symbols: Array.Empty<byte[]>(),
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("sets IMAGE_SCN_GPREL, which is documented only for IA64 objects.", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_CorMeta_Parses_Metadata_Root()
    {
        byte[] cormeta = BuildMinimalCorMetadata();
        byte[] data = BuildCoffObject(
            machine: 0x014C,
            sections: new[]
            {
                new SectionSpec(".cormeta", cormeta, 0x40000040u)
            },
            symbols: Array.Empty<byte[]>(),
            stringTablePayload: Array.Empty<byte>());

        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.True(parser.IsDotNetFile);
            Assert.NotNull(parser.ClrMetadata);
            Assert.NotNull(parser.CoffObject);
            Assert.NotNull(parser.CoffObject.CorMetadata);
            Assert.True(parser.CoffObject.CorMetadata.Parsed);
            Assert.StartsWith("v4.0.30319", parser.CoffObject.CorMetadata.VersionString, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffBigObj_Symbol_Uses_Extended_SectionNumber()
    {
        const int bigSectionNumber = 70000;
        byte[] data = BuildBigObjWithExtendedSectionSymbol(bigSectionNumber);
        string path = WriteTemp(data);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Equal("COFF", parser.ImageKind);
            Assert.NotNull(parser.CoffObject);
            Assert.True(parser.CoffObject.IsBigObj);
            CoffSymbolInfo symbol = Assert.Single(parser.CoffSymbols);
            Assert.Equal(bigSectionNumber, symbol.SectionNumber);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private readonly struct SectionSpec
    {
        public string Name { get; }
        public byte[] Data { get; }
        public uint Characteristics { get; }
        public ushort NumberOfRelocations { get; }
        public ushort NumberOfLinenumbers { get; }

        public SectionSpec(
            string name,
            byte[] data,
            uint characteristics,
            ushort numberOfRelocations = 0,
            ushort numberOfLinenumbers = 0)
        {
            Name = name ?? string.Empty;
            Data = data ?? Array.Empty<byte>();
            Characteristics = characteristics;
            NumberOfRelocations = numberOfRelocations;
            NumberOfLinenumbers = numberOfLinenumbers;
        }
    }

    private static byte[] BuildCoffObject(
        ushort machine,
        SectionSpec[] sections,
        byte[][] symbols,
        byte[] stringTablePayload)
    {
        sections ??= Array.Empty<SectionSpec>();
        symbols ??= Array.Empty<byte[]>();

        const int coffHeaderSize = 20;
        const int sectionHeaderSize = 40;
        int sectionTableOffset = coffHeaderSize;
        int rawDataOffset = sectionTableOffset + (sections.Length * sectionHeaderSize);

        uint[] rawPointers = new uint[sections.Length];
        uint[] rawSizes = new uint[sections.Length];
        int cursor = rawDataOffset;
        for (int i = 0; i < sections.Length; i++)
        {
            byte[] data = sections[i].Data ?? Array.Empty<byte>();
            if (data.Length > 0)
            {
                rawPointers[i] = (uint)cursor;
                rawSizes[i] = (uint)data.Length;
                cursor += data.Length;
            }
        }

        int symbolTableOffset = cursor;
        int symbolCount = symbols.Length;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write(machine);
        writer.Write((ushort)sections.Length);
        writer.Write(0x5E2B1234u);
        writer.Write(symbolCount == 0 ? 0u : (uint)symbolTableOffset);
        writer.Write((uint)symbolCount);
        writer.Write((ushort)0);
        writer.Write((ushort)0);

        for (int i = 0; i < sections.Length; i++)
        {
            byte[] name = CreateSectionName(sections[i].Name);
            writer.Write(name);
            writer.Write(0u);
            writer.Write(0u);
            writer.Write(rawSizes[i]);
            writer.Write(rawPointers[i]);
            writer.Write(0u);
            writer.Write(0u);
            writer.Write(sections[i].NumberOfRelocations);
            writer.Write(sections[i].NumberOfLinenumbers);
            writer.Write(sections[i].Characteristics);
        }

        for (int i = 0; i < sections.Length; i++)
        {
            byte[] payload = sections[i].Data ?? Array.Empty<byte>();
            if (payload.Length > 0)
            {
                writer.Write(payload);
            }
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

    private static byte[] BuildBigObjWithExtendedSectionSymbol(int sectionNumber)
    {
        const int bigObjHeaderSize = 56;
        const int sectionHeaderSize = 40;
        int symbolTableOffset = bigObjHeaderSize + sectionHeaderSize;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write((ushort)0); // Sig1
        writer.Write((ushort)0xFFFF); // Sig2
        writer.Write((ushort)2); // Version
        writer.Write((ushort)0x014C); // Machine
        writer.Write(0x5E2B1234u); // TimeDateStamp
        writer.Write(new Guid("D1BAA1C7-BAEE-4BA9-A3AF-09E79D8E63DB").ToByteArray());
        writer.Write(0u); // SizeOfData
        writer.Write(0u); // Flags
        writer.Write(0u); // MetaDataSize
        writer.Write(0u); // MetaDataOffset
        writer.Write(1u); // NumberOfSections
        writer.Write((uint)symbolTableOffset); // PointerToSymbolTable
        writer.Write(1u); // NumberOfSymbols

        writer.Write(CreateSectionName(".text"));
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(0x60000020u);

        byte[] symbol = new byte[20];
        Encoding.ASCII.GetBytes("bigsym").CopyTo(symbol, 0);
        WriteUInt32(symbol, 8, 0u);
        WriteInt32(symbol, 12, sectionNumber);
        WriteUInt16(symbol, 16, (ushort)0);
        symbol[18] = 0x02;
        symbol[19] = 0;
        writer.Write(symbol);
        writer.Write(4u); // empty string table

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildDebugSubsectionStream()
    {
        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write(0xF1u); // SYM
        writer.Write(4u);
        writer.Write(0x01020304u);

        writer.Write(0xF3u); // STRING_TABLE
        writer.Write(0u);

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildMinimalCorMetadata()
    {
        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write(0x424A5342u); // BSJB
        writer.Write((ushort)1); // Major
        writer.Write((ushort)1); // Minor
        writer.Write(0u); // Reserved
        byte[] version = Encoding.ASCII.GetBytes("v4.0.30319\0");
        writer.Write((uint)version.Length);
        writer.Write(version);
        while ((ms.Length % 4) != 0)
        {
            writer.Write((byte)0);
        }

        writer.Write((ushort)0); // Flags
        writer.Write((ushort)1); // Streams

        int streamHeaderOffset = (int)ms.Length;
        writer.Write(0u); // Offset placeholder
        writer.Write(0u); // Size
        writer.Write(Encoding.ASCII.GetBytes("#~\0\0"));

        int streamDataOffset = (int)ms.Length;
        ms.Position = streamHeaderOffset;
        writer.Write((uint)streamDataOffset);
        ms.Position = ms.Length;

        writer.Flush();
        return ms.ToArray();
    }

    private static string WriteTemp(byte[] data)
    {
        string path = Path.GetTempFileName();
        File.WriteAllBytes(path, data);
        return path;
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

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
    }

    private static void WriteInt16(byte[] data, int offset, short value)
    {
        WriteUInt16(data, offset, unchecked((ushort)value));
    }

    private static void WriteInt32(byte[] data, int offset, int value)
    {
        WriteUInt32(data, offset, unchecked((uint)value));
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)((value >> 16) & 0xFF);
        data[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
