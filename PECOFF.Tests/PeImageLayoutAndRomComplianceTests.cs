using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class PeImageLayoutAndRomComplianceTests
{
    [Fact]
    public void PeImage_RomOptionalHeader_IsSupported()
    {
        byte[] data = BuildRomImage(optionalHeaderSize: 0x38);
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);

            Assert.DoesNotContain(
                parser.ParseResult.Errors,
                error => error.Contains("Unknown PE optional header format", StringComparison.Ordinal));
            Assert.Equal(0x200u, parser.SizeOfCode);
            Assert.Equal(0u, parser.NumberOfRvaAndSizes);
            Assert.Empty(parser.DataDirectories);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PeImage_RomOptionalHeader_TruncatedMandatoryFields_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] data = BuildRomImage(optionalHeaderSize: 0x20);
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("mandatory ROM optional-header fields", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PeImage_SubPageSectionAlignment_FileAlignmentMismatch_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] data = BuildPe32Image(
            fileAlignment: 0x400,
            sectionAlignment: 0x200,
            sections: new[]
            {
                new SectionSpec(".text", 0x1000, 0x200, 0x200)
            });

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("must equal FileAlignment", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PeImage_SectionHeadersOutOfRvaOrder_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] data = BuildPe32Image(
            fileAlignment: 0x200,
            sectionAlignment: 0x1000,
            sections: new[]
            {
                new SectionSpec(".text", 0x2000, 0x200, 0x200),
                new SectionSpec(".rdata", 0x1000, 0x200, 0x200)
            });

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("not sorted by ascending VirtualAddress", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PeImage_SectionVirtualOverlap_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] data = BuildPe32Image(
            fileAlignment: 0x200,
            sectionAlignment: 0x200,
            sections: new[]
            {
                new SectionSpec(".text", 0x1000, 0x700, 0x200),
                new SectionSpec(".data", 0x1600, 0x300, 0x200)
            });

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("overlaps section", StringComparison.Ordinal) &&
                           warning.Contains("virtual address space", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PeImage_SectionRawDataOutOfRvaOrder_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] data = BuildPe32Image(
            fileAlignment: 0x200,
            sectionAlignment: 0x1000,
            sections: new[]
            {
                new SectionSpec(".text", 0x1000, 0x200, 0x200),
                new SectionSpec(".rdata", 0x2000, 0x200, 0x200)
            });

        const int peOffset = 0x80;
        const int optionalHeaderSize = 0xE0;
        const int sectionHeaderSize = 40;
        const int rawPointerOffset = 20;
        int sectionTableOffset = peOffset + 4 + 20 + optionalHeaderSize;

        WriteUInt32(data, sectionTableOffset + rawPointerOffset, 0x400); // .text points later
        WriteUInt32(data, sectionTableOffset + sectionHeaderSize + rawPointerOffset, 0x200); // .rdata points earlier

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("raw data is not laid out in ascending RVA order", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private readonly record struct SectionSpec(string Name, uint VirtualAddress, uint VirtualSize, uint RawSize);

    private static byte[] BuildPe32Image(uint fileAlignment, uint sectionAlignment, IReadOnlyList<SectionSpec> sections)
    {
        const int peOffset = 0x80;
        const ushort optionalHeaderSize = 0xE0;
        const uint imageBase = 0x00400000;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        byte[] dos = new byte[peOffset];
        dos[0] = (byte)'M';
        dos[1] = (byte)'Z';
        WriteUInt32(dos, 0x3C, (uint)peOffset);
        writer.Write(dos);

        writer.Write(0x00004550u); // PE\0\0
        writer.Write((ushort)0x014C); // x86
        writer.Write((ushort)sections.Count);
        writer.Write(0u); // timestamp
        writer.Write(0u); // pointer to symbol table
        writer.Write(0u); // number of symbols
        writer.Write(optionalHeaderSize);
        writer.Write((ushort)0x0102); // EXECUTABLE_IMAGE | 32BIT_MACHINE

        uint alignedSectionAlignment = sectionAlignment == 0 ? 1u : sectionAlignment;
        int headerSize = peOffset + 4 + 20 + optionalHeaderSize + (sections.Count * 40);
        uint sizeOfHeaders = AlignUp((uint)headerSize, fileAlignment == 0 ? 1u : fileAlignment);
        uint rawPointer = sizeOfHeaders;
        uint maxVirtualEnd = 0;
        uint sizeOfCode = 0;
        uint sizeOfInitData = 0;
        for (int i = 0; i < sections.Count; i++)
        {
            SectionSpec section = sections[i];
            uint span = Math.Max(section.VirtualSize, section.RawSize);
            uint end = section.VirtualAddress + AlignUp(span, alignedSectionAlignment);
            if (end > maxVirtualEnd)
            {
                maxVirtualEnd = end;
            }

            if (i == 0)
            {
                sizeOfCode += section.RawSize;
            }
            else
            {
                sizeOfInitData += section.RawSize;
            }
        }

        uint sizeOfImage = AlignUp(maxVirtualEnd, alignedSectionAlignment);
        byte[] optional = new byte[optionalHeaderSize];
        WriteUInt16(optional, 0x00, 0x010B); // PE32
        optional[0x02] = 14; // MajorLinkerVersion
        WriteUInt32(optional, 0x04, sizeOfCode);
        WriteUInt32(optional, 0x08, sizeOfInitData);
        WriteUInt32(optional, 0x10, sections[0].VirtualAddress); // entry point
        WriteUInt32(optional, 0x14, sections[0].VirtualAddress); // base of code
        WriteUInt32(optional, 0x18, sections.Count > 1 ? sections[1].VirtualAddress : sections[0].VirtualAddress); // base of data
        WriteUInt32(optional, 0x1C, imageBase);
        WriteUInt32(optional, 0x20, sectionAlignment);
        WriteUInt32(optional, 0x24, fileAlignment);
        WriteUInt16(optional, 0x28, 6); // OS major
        WriteUInt16(optional, 0x2A, 0); // OS minor
        WriteUInt16(optional, 0x30, 6); // subsystem major
        WriteUInt16(optional, 0x32, 0); // subsystem minor
        WriteUInt32(optional, 0x38, sizeOfImage);
        WriteUInt32(optional, 0x3C, sizeOfHeaders);
        WriteUInt16(optional, 0x44, 3); // CUI
        WriteUInt16(optional, 0x46, 0x8540); // typical DLL characteristics
        WriteUInt32(optional, 0x48, 0x00100000);
        WriteUInt32(optional, 0x4C, 0x1000);
        WriteUInt32(optional, 0x50, 0x00100000);
        WriteUInt32(optional, 0x54, 0x1000);
        WriteUInt32(optional, 0x58, 0); // loader flags
        WriteUInt32(optional, 0x5C, 0); // number of RVA and sizes
        writer.Write(optional);

        for (int i = 0; i < sections.Count; i++)
        {
            SectionSpec section = sections[i];
            byte[] header = new byte[40];
            Encoding.ASCII.GetBytes(section.Name).AsSpan(0, Math.Min(8, section.Name.Length)).CopyTo(header);
            WriteUInt32(header, 8, section.VirtualSize);
            WriteUInt32(header, 12, section.VirtualAddress);
            WriteUInt32(header, 16, section.RawSize);
            WriteUInt32(header, 20, section.RawSize == 0 ? 0 : rawPointer);
            WriteUInt32(header, 24, 0);
            WriteUInt32(header, 28, 0);
            WriteUInt16(header, 32, 0);
            WriteUInt16(header, 34, 0);
            WriteUInt32(header, 36, i == 0 ? 0x60000020u : 0x40000040u);
            writer.Write(header);

            rawPointer += AlignUp(section.RawSize, fileAlignment == 0 ? 1u : fileAlignment);
        }

        writer.Flush();
        uint fileSize = rawPointer;
        if (fileSize > ms.Length)
        {
            ms.SetLength(fileSize);
        }

        return ms.ToArray();
    }

    private static byte[] BuildRomImage(ushort optionalHeaderSize)
    {
        const int peOffset = 0x80;
        const uint rawSize = 0x200;
        const uint rawPointer = 0x200;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        byte[] dos = new byte[peOffset];
        dos[0] = (byte)'M';
        dos[1] = (byte)'Z';
        WriteUInt32(dos, 0x3C, (uint)peOffset);
        writer.Write(dos);

        writer.Write(0x00004550u); // PE\0\0
        writer.Write((ushort)0x014C); // x86
        writer.Write((ushort)1); // sections
        writer.Write(0u); // timestamp
        writer.Write(0u); // pointer to symbol table
        writer.Write(0u); // number of symbols
        writer.Write(optionalHeaderSize);
        writer.Write((ushort)0x0002); // EXECUTABLE_IMAGE

        byte[] optional = new byte[optionalHeaderSize];
        WriteUInt16(optional, 0x00, 0x0107); // ROM magic
        if (optionalHeaderSize >= 0x38)
        {
            optional[0x02] = 14; // linker major
            WriteUInt32(optional, 0x04, rawSize); // SizeOfCode
            WriteUInt32(optional, 0x08, 0); // SizeOfInitializedData
            WriteUInt32(optional, 0x0C, 0); // SizeOfUninitializedData
            WriteUInt32(optional, 0x10, 0x1000); // AddressOfEntryPoint
            WriteUInt32(optional, 0x14, 0x1000); // BaseOfCode
            WriteUInt32(optional, 0x18, 0x1000); // BaseOfData
            WriteUInt32(optional, 0x1C, 0); // BaseOfBss
            WriteUInt32(optional, 0x20, 0); // GprMask
            WriteUInt32(optional, 0x24, 0); // CprMask0
            WriteUInt32(optional, 0x28, 0); // CprMask1
            WriteUInt32(optional, 0x2C, 0); // CprMask2
            WriteUInt32(optional, 0x30, 0); // CprMask3
            WriteUInt32(optional, 0x34, 0); // GpValue
        }

        writer.Write(optional);

        byte[] section = new byte[40];
        Encoding.ASCII.GetBytes(".text").CopyTo(section, 0);
        WriteUInt32(section, 8, 0x100); // VirtualSize
        WriteUInt32(section, 12, 0x1000); // VirtualAddress
        WriteUInt32(section, 16, rawSize);
        WriteUInt32(section, 20, rawPointer);
        WriteUInt16(section, 32, 0);
        WriteUInt16(section, 34, 0);
        WriteUInt32(section, 36, 0x60000020); // code+execute+read
        writer.Write(section);

        writer.Flush();
        if (ms.Length < rawPointer + rawSize)
        {
            ms.SetLength(rawPointer + rawSize);
        }

        return ms.ToArray();
    }

    private static uint AlignUp(uint value, uint alignment)
    {
        if (alignment == 0)
        {
            return value;
        }

        uint remainder = value % alignment;
        return remainder == 0 ? value : value + (alignment - remainder);
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
