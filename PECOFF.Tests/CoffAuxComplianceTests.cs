using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffAuxComplianceTests
{
    [Fact]
    public void CoffClrTokenAux_NonZeroReservedFields_EmitSpecWarnings_AndStrictModeFails()
    {
        byte[] aux = BuildClrAuxRecord(
            auxType: CoffAuxSymbolInfo.ClrTokenAuxTypeDefinition,
            reserved: 0x01,
            symbolTableIndex: 1,
            reservedTailFill: 0xFF);
        string path = WriteTempCoffObject(aux, storageClass: 0x6B, symbolName: "tok");
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF CLR token aux record", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffClrTokenAux_InvalidAuxType_EmitsSpecWarning()
    {
        byte[] aux = BuildClrAuxRecord(
            auxType: 0x02,
            reserved: 0x00,
            symbolTableIndex: 1,
            reservedTailFill: 0x00);
        string path = WriteTempCoffObject(aux, storageClass: 0x6B, symbolName: "tok");
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("invalid AuxType", StringComparison.Ordinal));

            CoffAuxSymbolInfo clrAux = Assert.Single(Assert.Single(parser.CoffSymbols).AuxSymbols);
            Assert.Equal("ClrToken", clrAux.Kind);
            Assert.Equal((byte)0x02, clrAux.ClrAuxType);
            Assert.Equal((uint)1, clrAux.ClrSymbolTableIndex);
            Assert.True(clrAux.ClrReservedFieldsValid);

            string json = parser.Result.ToJsonReport(includeBinary: false, indented: false);
            Assert.Contains("\"ClrAuxType\":2", json, StringComparison.Ordinal);
            Assert.Contains("\"ClrSymbolTableIndex\":1", json, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffFunctionAux_MalformedLayout_EmitsSpecWarning_AndStrictModeFails()
    {
        string path = WriteTempCoffObjectWithMissingAuxRecord(storageClass: 0x65, symbolName: ".bf");
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF auxiliary records", StringComparison.Ordinal));
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF function auxiliary layout", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffFunctionAux_ReservedFields_EmitSpecWarning_AndStrictModeFails()
    {
        byte[] aux = new byte[18];
        WriteUInt16(aux, 4, 1);
        WriteUInt32(aux, 8, 0xAAAAAAAAu); // reserved bytes must be zero
        WriteUInt32(aux, 12, 0x01020304u);
        string path = WriteTempCoffObject(aux, storageClass: 0x65, symbolName: ".bf");
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF function auxiliary reserved fields are non-zero", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffFunctionDefinitionAux_ReservedTail_EmitSpecWarning_AndStrictModeFails()
    {
        byte[] aux = new byte[18];
        WriteUInt32(aux, 0, 1u);
        WriteUInt32(aux, 4, 0x20u);
        WriteUInt32(aux, 8, 0u);
        WriteUInt32(aux, 12, 0u);
        aux[16] = 0xAB; // reserved tail bytes must be zero

        string path = WriteTempCoffObject(aux, storageClass: 0x02, symbolName: "func", symbolType: 0x20);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF function auxiliary reserved fields are non-zero", StringComparison.Ordinal));

            CoffAuxSymbolInfo parsedAux = Assert.Single(Assert.Single(parser.CoffSymbols).AuxSymbols);
            Assert.Equal("FunctionDefinition", parsedAux.Kind);
            Assert.False(parsedAux.FunctionAuxReservedFieldsValid);

            string json = parser.Result.ToJsonReport(includeBinary: false, indented: false);
            Assert.Contains("\"FunctionAuxReservedFieldsValid\":false", json, StringComparison.Ordinal);

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffFunctionAux_EndRecord_WithPointer_EmitsSpecWarning()
    {
        byte[] aux = new byte[18];
        WriteUInt16(aux, 4, 2);
        WriteUInt32(aux, 12, 0x01020304u); // .ef should not use pointer to next function
        string path = WriteTempCoffObject(aux, storageClass: 0x65, symbolName: ".ef");
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF .ef auxiliary record should not define PointerToNextFunction", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffWeakExternal_ExternalUndefinedForm_ParsesAndResolvesDefaultSymbol()
    {
        string path = WriteTempWeakExternalObject(weakTagIndex: 4u, includeLeadingFileAux: true);
        try
        {
            PECOFF parser = new PECOFF(path);
            CoffSymbolInfo weakSymbol = Assert.Single(parser.CoffSymbols, s => string.Equals(s.Name, "weak", StringComparison.Ordinal));
            CoffAuxSymbolInfo aux = Assert.Single(weakSymbol.AuxSymbols);
            Assert.Equal("WeakExternal", aux.Kind);
            Assert.Equal("target", aux.WeakDefaultSymbol);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffWeakExternal_LegacyCompactIndex_FallbackStillResolves()
    {
        string path = WriteTempWeakExternalObject(weakTagIndex: 1u, includeLeadingFileAux: false);
        try
        {
            PECOFF parser = new PECOFF(path);
            CoffSymbolInfo weakSymbol = Assert.Single(parser.CoffSymbols, s => string.Equals(s.Name, "weak", StringComparison.Ordinal));
            CoffAuxSymbolInfo aux = Assert.Single(weakSymbol.AuxSymbols);
            Assert.Equal("WeakExternal", aux.Kind);
            Assert.Equal("target", aux.WeakDefaultSymbol);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffWeakExternal_UnresolvableTagIndex_EmitsSpecWarning_AndStrictModeFails()
    {
        string path = WriteTempWeakExternalObject(weakTagIndex: 99u, includeLeadingFileAux: true);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: COFF weak external aux record", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildClrAuxRecord(byte auxType, byte reserved, uint symbolTableIndex, byte reservedTailFill)
    {
        byte[] data = new byte[18];
        data[0] = auxType;
        data[1] = reserved;
        WriteUInt32(data, 2, symbolTableIndex);
        for (int i = 6; i < data.Length; i++)
        {
            data[i] = reservedTailFill;
        }
        return data;
    }

    private static string WriteTempCoffObject(byte[] auxData, byte storageClass, string symbolName, ushort symbolType = 0)
    {
        byte[] data = BuildCoffObjectWithAux(auxData, storageClass, symbolName, symbolType: symbolType);
        string path = Path.GetTempFileName();
        File.WriteAllBytes(path, data);
        return path;
    }

    private static string WriteTempCoffObjectWithMissingAuxRecord(byte storageClass, string symbolName)
    {
        byte[] data = BuildCoffObjectWithAux(auxData: Array.Empty<byte>(), storageClass, symbolName, numberOfSymbols: 1, symbolAuxCount: 1);
        string path = Path.GetTempFileName();
        File.WriteAllBytes(path, data);
        return path;
    }

    private static string WriteTempWeakExternalObject(uint weakTagIndex, bool includeLeadingFileAux)
    {
        byte[] data = BuildWeakExternalObject(weakTagIndex, includeLeadingFileAux);
        string path = Path.GetTempFileName();
        File.WriteAllBytes(path, data);
        return path;
    }

    private static byte[] BuildCoffObjectWithAux(
        byte[] auxData,
        byte storageClass,
        string symbolName,
        uint numberOfSymbols = 2,
        byte symbolAuxCount = 1,
        ushort symbolType = 0)
    {
        const int coffHeaderSize = 20;
        const int sectionHeaderSize = 40;
        int symbolTableOffset = coffHeaderSize + sectionHeaderSize;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write((ushort)0x14C); // x86
        writer.Write((ushort)1); // NumberOfSections
        writer.Write(0x5E2B1234u); // TimeDateStamp
        writer.Write(symbolTableOffset);
        writer.Write(numberOfSymbols);
        writer.Write((ushort)0); // SizeOfOptionalHeader
        writer.Write((ushort)0); // Characteristics

        byte[] sectionName = new byte[8];
        Encoding.ASCII.GetBytes(".text").CopyTo(sectionName, 0);
        writer.Write(sectionName);
        writer.Write(0u); // VirtualSize
        writer.Write(0u); // VirtualAddress
        writer.Write(0u); // SizeOfRawData
        writer.Write(0u); // PointerToRawData
        writer.Write(0u); // PointerToRelocations
        writer.Write(0u); // PointerToLinenumbers
        writer.Write((ushort)0); // NumberOfRelocations
        writer.Write((ushort)0); // NumberOfLinenumbers
        writer.Write(0u); // Characteristics

        byte[] symbol = new byte[18];
        Encoding.ASCII.GetBytes(symbolName ?? string.Empty).CopyTo(symbol, 0);
        WriteUInt32(symbol, 8, 0u); // value
        WriteInt16(symbol, 12, 1); // section number
        WriteUInt16(symbol, 14, symbolType); // type
        symbol[16] = storageClass;
        symbol[17] = symbolAuxCount;
        writer.Write(symbol);

        writer.Write(auxData ?? Array.Empty<byte>());
        writer.Write(4u); // string table length
        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildWeakExternalObject(uint weakTagIndex, bool includeLeadingFileAux)
    {
        const int coffHeaderSize = 20;
        const int sectionHeaderSize = 40;
        int symbolTableOffset = coffHeaderSize + sectionHeaderSize;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write((ushort)0x14C); // x86
        writer.Write((ushort)1); // NumberOfSections
        writer.Write(0x5E2B1234u); // TimeDateStamp
        writer.Write(symbolTableOffset);
        writer.Write(includeLeadingFileAux ? 5u : 3u); // file+aux,weak+aux,target OR weak+aux,target
        writer.Write((ushort)0); // SizeOfOptionalHeader
        writer.Write((ushort)0); // Characteristics

        byte[] sectionName = new byte[8];
        Encoding.ASCII.GetBytes(".text").CopyTo(sectionName, 0);
        writer.Write(sectionName);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(0u);

        if (includeLeadingFileAux)
        {
            byte[] fileSymbol = new byte[18];
            Encoding.ASCII.GetBytes(".file").CopyTo(fileSymbol, 0);
            WriteUInt32(fileSymbol, 8, 0u);
            WriteInt16(fileSymbol, 12, 0);
            WriteUInt16(fileSymbol, 14, 0);
            fileSymbol[16] = 0x67;
            fileSymbol[17] = 1;
            writer.Write(fileSymbol);

            byte[] fileAux = new byte[18];
            Encoding.ASCII.GetBytes("unit.c").CopyTo(fileAux, 0);
            writer.Write(fileAux);
        }

        byte[] weakSymbol = new byte[18];
        Encoding.ASCII.GetBytes("weak").CopyTo(weakSymbol, 0);
        WriteUInt32(weakSymbol, 8, 0u); // value
        WriteInt16(weakSymbol, 12, 0); // undefined section
        WriteUInt16(weakSymbol, 14, 0); // type
        weakSymbol[16] = 0x02; // EXTERNAL
        weakSymbol[17] = 1; // aux count
        writer.Write(weakSymbol);

        byte[] weakAux = new byte[18];
        WriteUInt32(weakAux, 0, weakTagIndex); // default symbol index
        WriteUInt32(weakAux, 4, 2u); // SEARCH_LIBRARY
        writer.Write(weakAux);

        byte[] targetSymbol = new byte[18];
        Encoding.ASCII.GetBytes("target").CopyTo(targetSymbol, 0);
        WriteUInt32(targetSymbol, 8, 0u);
        WriteInt16(targetSymbol, 12, 1); // section 1
        WriteUInt16(targetSymbol, 14, 0);
        targetSymbol[16] = 0x02;
        targetSymbol[17] = 0;
        writer.Write(targetSymbol);

        writer.Write(4u); // string table length
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
