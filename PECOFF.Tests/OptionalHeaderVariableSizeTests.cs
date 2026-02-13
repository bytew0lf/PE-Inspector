using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class OptionalHeaderVariableSizeTests
{
    [Fact]
    public void PeImage_VariableSizedOptionalHeader_ParsesMandatoryFieldsAndDirectories()
    {
        byte[] data = BuildMinimalPe32Image(optionalHeaderSize: 0x60, numberOfRvaAndSizes: 0);
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);

            Assert.Equal(0x200u, parser.FileAlignment);
            Assert.Equal(0x1000u, parser.SectionAlignment);
            Assert.Equal(0x2000u, parser.SizeOfImage);
            Assert.Equal(0x200u, parser.SizeOfHeaders);
            Assert.Equal(0u, parser.NumberOfRvaAndSizes);
            Assert.Empty(parser.DataDirectories);
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("mandatory PE32 optional-header fields", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PeImage_TruncatedOptionalHeaderMandatoryFields_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] data = BuildMinimalPe32Image(optionalHeaderSize: 0x40, numberOfRvaAndSizes: 0);
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains(
                    "SPEC violation: SizeOfOptionalHeader (0x40) is too small to contain mandatory PE32 optional-header fields",
                    StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildMinimalPe32Image(ushort optionalHeaderSize, uint numberOfRvaAndSizes)
    {
        const int peOffset = 0x80;
        const uint sectionAlignment = 0x1000;
        const uint fileAlignment = 0x200;
        const uint sizeOfImage = 0x2000;
        const uint sizeOfHeaders = 0x200;
        const uint textVirtualAddress = 0x1000;
        const uint textRawPointer = 0x200;
        const uint textRawSize = 0x200;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        byte[] dos = new byte[peOffset];
        dos[0] = (byte)'M';
        dos[1] = (byte)'Z';
        WriteUInt32(dos, 0x3C, (uint)peOffset);
        writer.Write(dos);

        writer.Write(0x00004550u); // PE\0\0
        writer.Write((ushort)0x014C); // i386
        writer.Write((ushort)1); // number of sections
        writer.Write(0u); // timestamp
        writer.Write(0u); // pointer to symbol table
        writer.Write(0u); // number of symbols
        writer.Write(optionalHeaderSize);
        writer.Write((ushort)0x0102); // EXECUTABLE_IMAGE | 32BIT_MACHINE

        byte[] optional = new byte[optionalHeaderSize];
        WriteUInt16(optional, 0x00, 0x010B); // PE32
        WriteUInt32(optional, 0x04, textRawSize); // SizeOfCode
        WriteUInt32(optional, 0x08, textRawSize); // SizeOfInitializedData
        WriteUInt32(optional, 0x10, textVirtualAddress); // AddressOfEntryPoint
        WriteUInt32(optional, 0x14, textVirtualAddress); // BaseOfCode
        WriteUInt32(optional, 0x18, textVirtualAddress); // BaseOfData
        WriteUInt32(optional, 0x1C, 0x00400000); // ImageBase
        WriteUInt32(optional, 0x20, sectionAlignment);
        WriteUInt32(optional, 0x24, fileAlignment);
        WriteUInt32(optional, 0x38, sizeOfImage);
        WriteUInt32(optional, 0x3C, sizeOfHeaders);
        WriteUInt16(optional, 0x44, 3); // IMAGE_SUBSYSTEM_WINDOWS_CUI
        WriteUInt32(optional, 0x58, 0); // LoaderFlags
        WriteUInt32(optional, 0x5C, numberOfRvaAndSizes);
        writer.Write(optional);

        byte[] section = new byte[40];
        Encoding.ASCII.GetBytes(".text").CopyTo(section, 0);
        WriteUInt32(section, 8, 0x100); // VirtualSize
        WriteUInt32(section, 12, textVirtualAddress);
        WriteUInt32(section, 16, textRawSize);
        WriteUInt32(section, 20, textRawPointer);
        WriteUInt16(section, 32, 0); // NumberOfRelocations
        WriteUInt16(section, 34, 0); // NumberOfLinenumbers
        WriteUInt32(section, 36, 0x60000020); // code | execute | read
        writer.Write(section);

        writer.Flush();
        if (ms.Length < textRawPointer)
        {
            ms.SetLength(textRawPointer);
        }

        ms.SetLength(textRawPointer + textRawSize);
        return ms.ToArray();
    }

    private static void WriteUInt16(byte[] buffer, int offset, ushort value)
    {
        if (offset < 0 || offset + sizeof(ushort) > buffer.Length)
        {
            return;
        }

        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        if (offset < 0 || offset + sizeof(uint) > buffer.Length)
        {
            return;
        }

        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
