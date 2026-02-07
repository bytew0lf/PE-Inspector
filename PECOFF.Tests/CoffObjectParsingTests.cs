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
}
