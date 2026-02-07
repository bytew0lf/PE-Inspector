using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffObjectParsingTests
{
    [Fact]
    public void CoffObject_Parse_Basic_Header()
    {
        byte[] data = BuildMinimalCoffObject();
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF pe = new PECOFF(path);

            Assert.Equal("COFF", pe.ImageKind);
            Assert.NotNull(pe.CoffObject);
            Assert.Equal((ushort)0x014c, pe.CoffObject.Machine);
            Assert.Equal(1, pe.CoffObject.SectionCount);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffObject_Parse_Relocations()
    {
        byte[] data = BuildCoffObjectWithRelocation();
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF pe = new PECOFF(path);

            Assert.Equal("COFF", pe.ImageKind);
            Assert.Single(pe.CoffRelocations);
            CoffRelocationInfo relocation = pe.CoffRelocations[0];
            Assert.Equal(".text", relocation.SectionName);
            Assert.Equal("sym", relocation.SymbolName);
            Assert.Equal((ushort)0x0006, relocation.Type);
            Assert.Equal("DIR32", relocation.TypeName);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildMinimalCoffObject()
    {
        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write((ushort)0x014c); // IMAGE_FILE_MACHINE_I386
        writer.Write((ushort)1); // NumberOfSections
        writer.Write(0x5E2B1234u); // TimeDateStamp
        writer.Write(0u); // PointerToSymbolTable
        writer.Write(0u); // NumberOfSymbols
        writer.Write((ushort)0); // SizeOfOptionalHeader
        writer.Write((ushort)0); // Characteristics

        byte[] name = new byte[8];
        Encoding.ASCII.GetBytes(".text").CopyTo(name, 0);
        writer.Write(name);
        writer.Write(0u); // VirtualSize
        writer.Write(0u); // VirtualAddress
        writer.Write(0u); // SizeOfRawData
        writer.Write(0u); // PointerToRawData
        writer.Write(0u); // PointerToRelocations
        writer.Write(0u); // PointerToLinenumbers
        writer.Write((ushort)0); // NumberOfRelocations
        writer.Write((ushort)0); // NumberOfLinenumbers
        writer.Write(0x60000020u); // Characteristics (code + RX)

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildCoffObjectWithRelocation()
    {
        const int coffHeaderSize = 20;
        const int sectionHeaderSize = 40;
        const int relocationSize = 10;
        int relocationOffset = coffHeaderSize + sectionHeaderSize;
        int symbolTableOffset = relocationOffset + relocationSize;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write((ushort)0x014c); // IMAGE_FILE_MACHINE_I386
        writer.Write((ushort)1); // NumberOfSections
        writer.Write(0x5E2B1234u); // TimeDateStamp
        writer.Write(symbolTableOffset); // PointerToSymbolTable
        writer.Write(1u); // NumberOfSymbols
        writer.Write((ushort)0); // SizeOfOptionalHeader
        writer.Write((ushort)0); // Characteristics

        byte[] name = new byte[8];
        Encoding.ASCII.GetBytes(".text").CopyTo(name, 0);
        writer.Write(name);
        writer.Write(0u); // VirtualSize
        writer.Write(0u); // VirtualAddress
        writer.Write(0u); // SizeOfRawData
        writer.Write(0u); // PointerToRawData
        writer.Write(relocationOffset); // PointerToRelocations
        writer.Write(0u); // PointerToLinenumbers
        writer.Write((ushort)1); // NumberOfRelocations
        writer.Write((ushort)0); // NumberOfLinenumbers
        writer.Write(0x60000020u); // Characteristics

        writer.Write(0x10u); // VirtualAddress
        writer.Write(0u); // SymbolTableIndex
        writer.Write((ushort)0x0006); // DIR32

        byte[] symbol = new byte[18];
        Encoding.ASCII.GetBytes("sym").CopyTo(symbol, 0);
        BitConverter.GetBytes(0u).CopyTo(symbol, 8);
        BitConverter.GetBytes((short)1).CopyTo(symbol, 12);
        BitConverter.GetBytes((ushort)0).CopyTo(symbol, 14);
        symbol[16] = 2; // external
        symbol[17] = 0;
        writer.Write(symbol);

        writer.Write(4u); // string table length

        writer.Flush();
        return ms.ToArray();
    }
}
