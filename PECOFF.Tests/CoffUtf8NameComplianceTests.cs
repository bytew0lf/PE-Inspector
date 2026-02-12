using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffUtf8NameComplianceTests
{
    [Fact]
    public void CoffUtf8ShortNames_RoundTrip_InObjectAndJson()
    {
        byte[] sectionName = Encoding.UTF8.GetBytes("µsec");
        byte[] symbolName = Encoding.UTF8.GetBytes("äsym");
        string path = WriteTempCoffObject(sectionName, symbolName);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Single(parser.SectionHeaders);
            Assert.Equal("µsec", parser.SectionHeaders[0].Name);
            Assert.Single(parser.CoffSymbols);
            Assert.Equal("äsym", parser.CoffSymbols[0].Name);

            string json = parser.Result.ToJsonReport(includeBinary: false, indented: false);
            Assert.True(
                json.Contains("µsec", StringComparison.Ordinal) || json.Contains("\\u00B5sec", StringComparison.Ordinal),
                "Expected UTF-8 section name in JSON report.");
            Assert.True(
                json.Contains("äsym", StringComparison.Ordinal) || json.Contains("\\u00E4sym", StringComparison.Ordinal),
                "Expected UTF-8 symbol name in JSON report.");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffInvalidUtf8ShortNames_EmitWarnings_AndStrictModeFails()
    {
        byte[] sectionName = new byte[] { 0xC3, 0x28 };
        byte[] symbolName = new byte[] { 0xE2, 0x28 };
        string path = WriteTempCoffObject(sectionName, symbolName);
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("Section header short name", StringComparison.Ordinal));
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("COFF short symbol name", StringComparison.Ordinal));

            Assert.Single(parser.SectionHeaders);
            Assert.Equal("Ã(", parser.SectionHeaders[0].Name);
            Assert.Single(parser.CoffSymbols);
            Assert.Equal("â(", parser.CoffSymbols[0].Name);

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string WriteTempCoffObject(byte[] sectionNameBytes, byte[] symbolNameBytes)
    {
        byte[] data = BuildCoffObject(sectionNameBytes, symbolNameBytes);
        string path = Path.GetTempFileName();
        File.WriteAllBytes(path, data);
        return path;
    }

    private static byte[] BuildCoffObject(byte[] sectionNameBytes, byte[] symbolNameBytes)
    {
        const int coffHeaderSize = 20;
        const int sectionHeaderSize = 40;
        int symbolTableOffset = coffHeaderSize + sectionHeaderSize;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write((ushort)0x014C); // IMAGE_FILE_MACHINE_I386
        writer.Write((ushort)1); // NumberOfSections
        writer.Write(0x5E2B1234u); // TimeDateStamp
        writer.Write(symbolTableOffset);
        writer.Write(1u); // NumberOfSymbols
        writer.Write((ushort)0); // SizeOfOptionalHeader
        writer.Write((ushort)0); // Characteristics

        byte[] sectionName = new byte[8];
        Array.Copy(sectionNameBytes ?? Array.Empty<byte>(), 0, sectionName, 0, Math.Min(8, (sectionNameBytes ?? Array.Empty<byte>()).Length));
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
        Array.Copy(symbolNameBytes ?? Array.Empty<byte>(), 0, symbol, 0, Math.Min(8, (symbolNameBytes ?? Array.Empty<byte>()).Length));
        WriteUInt32(symbol, 8, 0u);
        WriteInt16(symbol, 12, 1);
        WriteUInt16(symbol, 14, 0);
        symbol[16] = 0x02; // EXTERNAL
        symbol[17] = 0;
        writer.Write(symbol);

        writer.Write(4u); // string table length
        writer.Flush();
        return ms.ToArray();
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

    private static void WriteInt16(byte[] data, int offset, short value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
    }
}
