using System;
using System.IO;
using PECoff;
using Xunit;

public class FpoReservedComplianceTests
{
    [Fact]
    public void DebugDirectory_FpoReservedBitSet_EmitsSpecViolation_AndStrictModeFails()
    {
        byte[] payload = BuildFpoPayload(setReservedBit: true);
        byte[] mutated = BuildDebugFixture(payload);

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, mutated);
            PECOFF parser = new PECOFF(path);

            DebugDirectoryEntry entry = Assert.Single(parser.DebugDirectories);
            Assert.Equal(DebugDirectoryType.Fpo, entry.Type);
            Assert.NotNull(entry.Fpo);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("FPO_DATA frame flags contain reserved bit 13", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DebugDirectory_FpoReservedBitClear_DoesNotEmitReservedBitSpecViolation()
    {
        byte[] payload = BuildFpoPayload(setReservedBit: false);
        byte[] mutated = BuildDebugFixture(payload);

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, mutated);
            PECOFF parser = new PECOFF(path);

            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("FPO_DATA frame flags contain reserved bit 13", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildFpoPayload(bool setReservedBit)
    {
        byte[] payload = new byte[16];
        WriteUInt32(payload, 0, 0x1000u);
        WriteUInt32(payload, 4, 0x200u);
        WriteUInt32(payload, 8, 0x20u);
        WriteUInt16(payload, 12, 0x0010);

        ushort flags = 0;
        flags |= 0x0005; // cbProlog
        flags |= 0x0300; // cbRegs
        flags |= 0x0800; // fHasSEH
        flags |= 0x8000; // cbFrame = 2
        if (setReservedBit)
        {
            flags |= 0x2000;
        }

        WriteUInt16(payload, 14, flags);
        return payload;
    }

    private static byte[] BuildDebugFixture(byte[] payload)
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] source = File.ReadAllBytes(validPath);
        Assert.True(TryGetPeLayout(source, out int dataDirectoryStart, out int sectionTableStart));

        byte[] mutated = (byte[])source.Clone();
        int firstSectionOffset = sectionTableStart;

        uint firstSectionRva = ReadUInt32(mutated, firstSectionOffset + 12);
        uint firstSectionRawSize = ReadUInt32(mutated, firstSectionOffset + 16);
        uint firstSectionRawPointer = ReadUInt32(mutated, firstSectionOffset + 20);

        int debugEntryRaw = checked((int)firstSectionRawPointer + 0x40);
        int debugDataRaw = debugEntryRaw + 0x20;
        Assert.True(firstSectionRawSize >= (uint)(0x40 + 0x20 + payload.Length));
        Assert.True(debugDataRaw + payload.Length <= mutated.Length);

        uint debugEntryRva = firstSectionRva + 0x40u;
        uint debugDataRva = debugEntryRva + 0x20u;

        int debugDirectoryOffset = dataDirectoryStart + (6 * 8);
        WriteUInt32(mutated, debugDirectoryOffset, debugEntryRva);
        WriteUInt32(mutated, debugDirectoryOffset + 4, 28u);

        WriteUInt32(mutated, debugEntryRaw + 0, 0u);
        WriteUInt32(mutated, debugEntryRaw + 4, 0u);
        WriteUInt16(mutated, debugEntryRaw + 8, 0);
        WriteUInt16(mutated, debugEntryRaw + 10, 0);
        WriteUInt32(mutated, debugEntryRaw + 12, (uint)DebugDirectoryType.Fpo);
        WriteUInt32(mutated, debugEntryRaw + 16, (uint)payload.Length);
        WriteUInt32(mutated, debugEntryRaw + 20, debugDataRva);
        WriteUInt32(mutated, debugEntryRaw + 24, (uint)debugDataRaw);

        if (payload.Length > 0)
        {
            Buffer.BlockCopy(payload, 0, mutated, debugDataRaw, payload.Length);
        }

        return mutated;
    }

    private static bool TryGetPeLayout(byte[] data, out int dataDirectoryStart, out int sectionTableStart)
    {
        dataDirectoryStart = 0;
        sectionTableStart = 0;

        if (data == null || data.Length < 0x40)
        {
            return false;
        }

        int peOffset = BitConverter.ToInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 24 > data.Length)
        {
            return false;
        }

        int fileHeaderOffset = peOffset + 4;
        ushort numberOfSections = BitConverter.ToUInt16(data, fileHeaderOffset + 2);
        ushort sizeOfOptionalHeader = BitConverter.ToUInt16(data, fileHeaderOffset + 16);
        int optionalHeaderOffset = fileHeaderOffset + 20;
        if (numberOfSections == 0)
        {
            return false;
        }

        ushort magic = BitConverter.ToUInt16(data, optionalHeaderOffset);
        bool isPe32Plus = magic == 0x20B;
        dataDirectoryStart = optionalHeaderOffset + (isPe32Plus ? 0x70 : 0x60);
        sectionTableStart = optionalHeaderOffset + sizeOfOptionalHeader;

        return dataDirectoryStart + (16 * 8) <= data.Length &&
               sectionTableStart + (numberOfSections * 40) <= data.Length;
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

    private static uint ReadUInt32(byte[] data, int offset)
    {
        return (uint)(data[offset] |
                      (data[offset + 1] << 8) |
                      (data[offset + 2] << 16) |
                      (data[offset + 3] << 24));
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
