using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class BaseRelocationComplianceTests
{
    [Fact]
    public void BaseRelocation_HighAdj_ConsumesAdjustmentSlot()
    {
        byte[] relocData = BuildRelocBlock(
            pageRva: 0x2000u,
            entries: new ushort[]
            {
                (ushort)((4 << 12) | 0x004), // HIGHADJ
                0x1234 // adjustment payload word
            });

        string path = WriteTemp(BuildTeImageWithRelocations(relocData));
        try
        {
            PECOFF parser = new PECOFF(path);
            BaseRelocationBlockInfo block = Assert.Single(parser.BaseRelocations);
            Assert.Equal(1, block.EntryCount);
            Assert.Equal(1, block.TypeCounts[4]);
            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("HIGHADJ entry", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void BaseRelocation_HighAdjMissingPayload_EmitsSpecWarning_AndStrictModeFails()
    {
        byte[] relocData = BuildRelocBlock(
            pageRva: 0x2000u,
            entries: new ushort[]
            {
                (ushort)((4 << 12) | 0x004) // HIGHADJ without payload
            });

        string path = WriteTemp(BuildTeImageWithRelocations(relocData));
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: Base relocation HIGHADJ entry", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void BaseRelocation_PageAlignment_Uses4KBoundary()
    {
        byte[] relocData = BuildRelocBlock(
            pageRva: 0x2101u,
            entries: new ushort[]
            {
                (ushort)((10 << 12) | 0x004) // DIR64
            });

        string path = WriteTemp(BuildTeImageWithRelocations(relocData));
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("Base relocation page RVA 0x2101 is not aligned", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void BaseRelocation_BlockStartAlignment_Requires32BitBoundary()
    {
        byte[] block1 = BuildRelocBlock(
            pageRva: 0x2000u,
            entries: new ushort[]
            {
                (ushort)((10 << 12) | 0x004) // DIR64
            });
        byte[] block2 = BuildRelocBlock(
            pageRva: 0x3000u,
            entries: new ushort[]
            {
                (ushort)((10 << 12) | 0x008) // DIR64
            });

        // block1 has size 10, so block2 starts on +10 (not 32-bit aligned).
        byte[] relocData = new byte[block1.Length + block2.Length];
        Array.Copy(block1, 0, relocData, 0, block1.Length);
        Array.Copy(block2, 0, relocData, block1.Length, block2.Length);

        string path = WriteTemp(BuildTeImageWithRelocations(relocData));
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("does not start on a 32-bit boundary", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string WriteTemp(byte[] data)
    {
        string path = Path.GetTempFileName();
        File.WriteAllBytes(path, data);
        return path;
    }

    private static byte[] BuildRelocBlock(uint pageRva, ushort[] entries)
    {
        entries ??= Array.Empty<ushort>();
        uint sizeOfBlock = (uint)(8 + (entries.Length * 2));
        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);
        writer.Write(pageRva);
        writer.Write(sizeOfBlock);
        for (int i = 0; i < entries.Length; i++)
        {
            writer.Write(entries[i]);
        }

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildTeImageWithRelocations(byte[] relocationData)
    {
        relocationData ??= Array.Empty<byte>();

        const ushort teSignature = 0x5A56; // "VZ"
        const ushort machine = 0x8664; // x64
        const byte sections = 2;
        const byte subsystem = 10; // EFI application
        const ushort strippedSize = 0x20;
        const uint entryPoint = 0x1000;
        const uint baseOfCode = 0x1000;
        const ulong imageBase = 0x100000;
        const uint baseRelocRva = 0x2000;
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
        writer.Write((uint)relocationData.Length);
        writer.Write(debugRva);
        writer.Write(debugSize);

        byte[] textName = new byte[8];
        Encoding.ASCII.GetBytes(".text").CopyTo(textName, 0);
        writer.Write(textName);
        writer.Write(sectionRawSize);
        writer.Write(0x1000u);
        writer.Write(sectionRawSize);
        writer.Write(textRawPointer);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(0x60000020u);

        byte[] relocName = new byte[8];
        Encoding.ASCII.GetBytes(".reloc").CopyTo(relocName, 0);
        writer.Write(relocName);
        writer.Write(sectionRawSize);
        writer.Write(baseRelocRva);
        writer.Write(sectionRawSize);
        writer.Write(relocRawPointer);
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
        writer.Write(relocationData);
        writer.Flush();
        return ms.ToArray();
    }
}
