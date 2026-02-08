using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class TeImageParsingTests
{
    [Fact]
    public void TeImage_Parse_Basic_Header()
    {
        byte[] data = BuildMinimalTeImage();
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF pe = new PECOFF(path);

            Assert.Equal("TE", pe.ImageKind);
            Assert.NotNull(pe.TeImage);
            Assert.Equal((ushort)0x8664, pe.TeImage.Machine);
            Assert.Equal(1, pe.TeImage.SectionCount);
            Assert.Equal("IMAGE_SUBSYSTEM_EFI_APPLICATION", pe.TeImage.SubsystemName);
            Assert.True(pe.TeImage.EntryPointFileOffsetValid);
            Assert.True(pe.TeImage.BaseOfCodeFileOffsetValid);
            Assert.Equal(0xFE0u, pe.TeImage.EntryPointFileOffset);
            Assert.Equal(0xFE0u, pe.TeImage.BaseOfCodeFileOffset);
            Assert.True(pe.TeImage.EntryPointMapped);
            Assert.True(pe.TeImage.BaseOfCodeMapped);
            Assert.Equal(".text", pe.TeImage.EntryPointSectionName);
            Assert.Equal(".text", pe.TeImage.BaseOfCodeSectionName);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void TeImage_Parse_Relocations()
    {
        byte[] data = BuildTeImageWithRelocations();
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF pe = new PECOFF(path);

            Assert.Equal("TE", pe.ImageKind);
            Assert.NotNull(pe.TeImage);
            Assert.NotEmpty(pe.BaseRelocations);
            Assert.Single(pe.BaseRelocations);
            Assert.Equal(2, pe.BaseRelocations[0].EntryCount);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildMinimalTeImage()
    {
        const ushort teSignature = 0x5A56; // "VZ"
        const ushort machine = 0x8664; // x64
        const byte sections = 1;
        const byte subsystem = 10; // EFI application
        const ushort strippedSize = 0x20;
        const uint entryPoint = 0x1000;
        const uint baseOfCode = 0x1000;
        const ulong imageBase = 0x100000;
        const uint baseRelocRva = 0;
        const uint baseRelocSize = 0;
        const uint debugRva = 0;
        const uint debugSize = 0;
        const uint sectionRawSize = 0x200;
        const uint sectionRawPointer = 40 + 40; // TE header + section header

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write(teSignature);
        writer.Write(machine);
        writer.Write(sections);
        writer.Write(subsystem);
        writer.Write(strippedSize);
        writer.Write(entryPoint);
        writer.Write(baseOfCode);
        writer.Write(imageBase);
        writer.Write(baseRelocRva);
        writer.Write(baseRelocSize);
        writer.Write(debugRva);
        writer.Write(debugSize);

        byte[] name = new byte[8];
        Encoding.ASCII.GetBytes(".text").CopyTo(name, 0);
        writer.Write(name);
        writer.Write(sectionRawSize); // VirtualSize
        writer.Write(0x1000u); // VirtualAddress
        writer.Write(sectionRawSize); // SizeOfRawData
        writer.Write(sectionRawPointer); // PointerToRawData
        writer.Write(0u); // PointerToRelocations
        writer.Write(0u); // PointerToLinenumbers
        writer.Write((ushort)0); // NumberOfRelocations
        writer.Write((ushort)0); // NumberOfLinenumbers
        writer.Write(0x60000020u); // Characteristics

        if (ms.Length < sectionRawPointer)
        {
            writer.Write(new byte[sectionRawPointer - ms.Length]);
        }
        writer.Write(new byte[sectionRawSize]);

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildTeImageWithRelocations()
    {
        const ushort teSignature = 0x5A56; // "VZ"
        const ushort machine = 0x8664; // x64
        const byte sections = 2;
        const byte subsystem = 10; // EFI application
        const ushort strippedSize = 0x20;
        const uint entryPoint = 0x1000;
        const uint baseOfCode = 0x1000;
        const ulong imageBase = 0x100000;
        const uint baseRelocRva = 0x2000;
        const uint baseRelocSize = 12;
        const uint debugRva = 0;
        const uint debugSize = 0;
        const uint sectionRawSize = 0x200;
        const uint textRawPointer = 0x80;
        const uint relocRawPointer = 0x280;

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        writer.Write(teSignature);
        writer.Write(machine);
        writer.Write(sections);
        writer.Write(subsystem);
        writer.Write(strippedSize);
        writer.Write(entryPoint);
        writer.Write(baseOfCode);
        writer.Write(imageBase);
        writer.Write(baseRelocRva);
        writer.Write(baseRelocSize);
        writer.Write(debugRva);
        writer.Write(debugSize);

        byte[] textName = new byte[8];
        Encoding.ASCII.GetBytes(".text").CopyTo(textName, 0);
        writer.Write(textName);
        writer.Write(sectionRawSize); // VirtualSize
        writer.Write(0x1000u); // VirtualAddress
        writer.Write(sectionRawSize); // SizeOfRawData
        writer.Write(textRawPointer); // PointerToRawData
        writer.Write(0u); // PointerToRelocations
        writer.Write(0u); // PointerToLinenumbers
        writer.Write((ushort)0); // NumberOfRelocations
        writer.Write((ushort)0); // NumberOfLinenumbers
        writer.Write(0x60000020u); // Characteristics

        byte[] relocName = new byte[8];
        Encoding.ASCII.GetBytes(".reloc").CopyTo(relocName, 0);
        writer.Write(relocName);
        writer.Write(sectionRawSize); // VirtualSize
        writer.Write(baseRelocRva); // VirtualAddress
        writer.Write(sectionRawSize); // SizeOfRawData
        writer.Write(relocRawPointer); // PointerToRawData
        writer.Write(0u);
        writer.Write(0u);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(0x42000040u);

        if (ms.Length < textRawPointer)
        {
            writer.Write(new byte[textRawPointer - ms.Length]);
        }
        writer.Write(new byte[sectionRawSize]);

        if (ms.Length < relocRawPointer)
        {
            writer.Write(new byte[relocRawPointer - ms.Length]);
        }

        writer.Write(baseRelocRva); // Page RVA
        writer.Write(baseRelocSize);
        writer.Write((ushort)0xA004); // DIR64 + offset 0x004
        writer.Write((ushort)0x0000); // ABSOLUTE padding

        writer.Flush();
        return ms.ToArray();
    }
}
