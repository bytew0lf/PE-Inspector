using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class PEImageCoffDeprecationTests
{
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

    private static bool TryMutateDeprecatedCoffFields(byte[] data)
    {
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
        int sectionTableOffset = fileHeaderOffset + 20 + sizeOfOptionalHeader;
        if (numberOfSections == 0 || sectionTableOffset + 40 > data.Length)
        {
            return false;
        }

        WriteUInt32(data, fileHeaderOffset + 8, 0x00000200); // PointerToSymbolTable
        WriteUInt32(data, fileHeaderOffset + 12, 1); // NumberOfSymbols

        int firstSectionOffset = sectionTableOffset;
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
