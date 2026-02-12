using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffRelocationMachineCoverageTests
{
    [Theory]
    [InlineData((ushort)0x014C, (ushort)0x0006, "DIR32")] // I386
    [InlineData((ushort)0x8664, (ushort)0x0004, "REL32")] // AMD64
    [InlineData((ushort)0xAA64, (ushort)0x0003, "BRANCH26")] // ARM64
    [InlineData((ushort)0x0166, (ushort)0x0025, "PAIR")] // MIPS
    [InlineData((ushort)0x01C2, (ushort)0x0015, "THUMB_BLX23")] // THUMB
    [InlineData((ushort)0x0200, (ushort)0x000A, "LTOFF22")] // IA64
    [InlineData((ushort)0x01F0, (ushort)0x0014, "SECRELHI")] // POWERPC
    [InlineData((ushort)0x0166, (ushort)0x0010, "JMPADDR16")] // R4000 (MIPS family)
    [InlineData((ushort)0x01A4, (ushort)0x0010, "DIRECT32_NB")] // SH3E
    [InlineData((ushort)0x01A6, (ushort)0x0010, "DIRECT32_NB")] // SH4
    [InlineData((ushort)0x9041, (ushort)0x000D, "SECREL")] // M32R
    public void CoffObject_RelocationTypeName_Maps_Additional_Machines(ushort machine, ushort relocationType, string expectedName)
    {
        byte[] data = BuildCoffObjectWithRelocation(machine, relocationType);
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF pe = new PECOFF(path);

            CoffRelocationInfo relocation = Assert.Single(pe.CoffRelocations);
            Assert.Equal(relocationType, relocation.Type);
            Assert.Equal(expectedName, relocation.TypeName);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildCoffObjectWithRelocation(ushort machine, ushort relocationType)
    {
        const int coffHeaderSize = 20;
        const int sectionHeaderSize = 40;
        const int relocationSize = 10;
        int relocationOffset = coffHeaderSize + sectionHeaderSize;
        int symbolTableOffset = relocationOffset + relocationSize;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write(machine);
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
        writer.Write(relocationType);

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
