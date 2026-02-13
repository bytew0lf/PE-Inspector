using System;
using System.IO;
using PECoff;
using Xunit;

public class DebugDirectoryReservedComplianceTests
{
    [Fact]
    public void DebugDirectory_ZeroCharacteristics_DoesNotEmitReservedFieldViolation()
    {
        byte[] mutated = BuildDebugFixture(
            debugType: (uint)DebugDirectoryType.ExDllCharacteristics,
            characteristics: 0u,
            payload: BitConverter.GetBytes(0x00000001u));

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, mutated);
            PECOFF parser = new PECOFF(path);

            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DEBUG_DIRECTORY.Characteristics", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DebugDirectory_NonZeroCharacteristics_EmitSpecViolation_AndStrictModeFails()
    {
        byte[] mutated = BuildDebugFixture(
            debugType: (uint)DebugDirectoryType.ExDllCharacteristics,
            characteristics: 0x11223344u,
            payload: BitConverter.GetBytes(0x00000001u));

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, mutated);
            PECOFF parser = new PECOFF(path);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DEBUG_DIRECTORY.Characteristics is reserved and must be 0", StringComparison.Ordinal));

            string json = parser.Result.ToJsonReport(includeBinary: false, indented: false);
            Assert.Contains("SPEC violation: IMAGE_DEBUG_DIRECTORY.Characteristics is reserved and must be 0", json, StringComparison.Ordinal);

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DebugDirectory_ReservedType10_WithPayload_EmitSpecViolation_AndKeepCompatibilityDecode()
    {
        byte[] payload = new byte[8];
        WriteUInt32(payload, 0, 1u);
        WriteUInt32(payload, 4, 2u);
        byte[] mutated = BuildDebugFixture(
            debugType: (uint)DebugDirectoryType.Reserved10,
            characteristics: 0u,
            payload: payload);

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, mutated);
            PECOFF parser = new PECOFF(path);

            DebugDirectoryEntry entry = Assert.Single(parser.DebugDirectories);
            Assert.Equal(DebugDirectoryType.Reserved10, entry.Type);
            Assert.NotNull(entry.Reserved);
            Assert.Contains("Non-standard", entry.Note, StringComparison.Ordinal);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DEBUG_TYPE_RESERVED10 is reserved and should not be used", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DebugDirectory_ReservedType10_ZeroSize_StillEmitsSpecViolation()
    {
        byte[] mutated = BuildDebugFixture(
            debugType: (uint)DebugDirectoryType.Reserved10,
            characteristics: 0u,
            payload: Array.Empty<byte>());

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, mutated);
            PECOFF parser = new PECOFF(path);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DEBUG_TYPE_RESERVED10 is reserved and should not be used", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData((uint)DebugDirectoryType.Fixup, "IMAGE_DEBUG_TYPE_FIXUP")]
    [InlineData((uint)DebugDirectoryType.Borland, "IMAGE_DEBUG_TYPE_BORLAND")]
    [InlineData((uint)DebugDirectoryType.Clsid, "IMAGE_DEBUG_TYPE_CLSID")]
    public void DebugDirectory_ReservedTypes6_9_11_WithPayload_EmitSpecViolation_AndStrictModeFails(uint debugType, string reservedTypeLabel)
    {
        byte[] payload = BuildReservedTypePayload(debugType);
        byte[] mutated = BuildDebugFixture(
            debugType: debugType,
            characteristics: 0u,
            payload: payload);

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, mutated);
            PECOFF parser = new PECOFF(path);

            DebugDirectoryEntry entry = Assert.Single(parser.DebugDirectories);
            Assert.Contains("Non-standard", entry.Note, StringComparison.Ordinal);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains($"SPEC violation: {reservedTypeLabel} is reserved and should not be used", StringComparison.Ordinal));

            if (debugType == (uint)DebugDirectoryType.Fixup)
            {
                Assert.NotNull(entry.Fixup);
            }
            else if (debugType == (uint)DebugDirectoryType.Borland)
            {
                Assert.NotNull(entry.Borland);
            }
            else if (debugType == (uint)DebugDirectoryType.Clsid)
            {
                Assert.NotNull(entry.Clsid);
            }

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData((uint)DebugDirectoryType.Fixup, "IMAGE_DEBUG_TYPE_FIXUP")]
    [InlineData((uint)DebugDirectoryType.Borland, "IMAGE_DEBUG_TYPE_BORLAND")]
    [InlineData((uint)DebugDirectoryType.Clsid, "IMAGE_DEBUG_TYPE_CLSID")]
    public void DebugDirectory_ReservedTypes6_9_11_ZeroSize_StillEmitSpecViolation(uint debugType, string reservedTypeLabel)
    {
        byte[] mutated = BuildDebugFixture(
            debugType: debugType,
            characteristics: 0u,
            payload: Array.Empty<byte>());

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, mutated);
            PECOFF parser = new PECOFF(path);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains($"SPEC violation: {reservedTypeLabel} is reserved and should not be used", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(path, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildReservedTypePayload(uint debugType)
    {
        if (debugType == (uint)DebugDirectoryType.Borland)
        {
            byte[] borland = new byte[8];
            WriteUInt32(borland, 0, 1u);
            WriteUInt32(borland, 4, 2u);
            return borland;
        }

        if (debugType == (uint)DebugDirectoryType.Clsid)
        {
            return Guid.NewGuid().ToByteArray();
        }

        return new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
    }

    private static byte[] BuildDebugFixture(uint debugType, uint characteristics, byte[] payload)
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] source = File.ReadAllBytes(validPath);
        Assert.True(TryGetPeLayout(source, out _, out int numberOfSections, out int dataDirectoryStart, out int sectionTableStart));
        Assert.True(numberOfSections > 0);

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

        WriteUInt32(mutated, debugEntryRaw + 0, characteristics);
        WriteUInt32(mutated, debugEntryRaw + 4, 0u);
        WriteUInt16(mutated, debugEntryRaw + 8, 0);
        WriteUInt16(mutated, debugEntryRaw + 10, 0);
        WriteUInt32(mutated, debugEntryRaw + 12, debugType);
        WriteUInt32(mutated, debugEntryRaw + 16, (uint)payload.Length);
        WriteUInt32(mutated, debugEntryRaw + 20, debugDataRva);
        WriteUInt32(mutated, debugEntryRaw + 24, (uint)debugDataRaw);

        if (payload.Length > 0)
        {
            Buffer.BlockCopy(payload, 0, mutated, debugDataRaw, payload.Length);
        }

        return mutated;
    }

    private static bool TryGetPeLayout(
        byte[] data,
        out int peOffset,
        out int numberOfSections,
        out int dataDirectoryStart,
        out int sectionTableStart)
    {
        peOffset = 0;
        numberOfSections = 0;
        dataDirectoryStart = 0;
        sectionTableStart = 0;

        if (data == null || data.Length < 0x40)
        {
            return false;
        }

        peOffset = BitConverter.ToInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 24 > data.Length)
        {
            return false;
        }

        numberOfSections = ReadUInt16(data, peOffset + 6);
        ushort sizeOfOptionalHeader = ReadUInt16(data, peOffset + 20);
        int optionalHeaderStart = peOffset + 24;
        if (optionalHeaderStart + sizeOfOptionalHeader > data.Length || sizeOfOptionalHeader < 0x60)
        {
            return false;
        }

        ushort magic = ReadUInt16(data, optionalHeaderStart);
        if (magic == 0x10B)
        {
            dataDirectoryStart = optionalHeaderStart + 0x60;
        }
        else if (magic == 0x20B)
        {
            dataDirectoryStart = optionalHeaderStart + 0x70;
        }
        else
        {
            return false;
        }

        sectionTableStart = optionalHeaderStart + sizeOfOptionalHeader;
        return dataDirectoryStart + (16 * 8) <= data.Length && sectionTableStart + (numberOfSections * 40) <= data.Length;
    }

    private static ushort ReadUInt16(byte[] data, int offset)
    {
        return (ushort)(data[offset] | (data[offset + 1] << 8));
    }

    private static uint ReadUInt32(byte[] data, int offset)
    {
        return (uint)(data[offset] |
                      (data[offset + 1] << 8) |
                      (data[offset + 2] << 16) |
                      (data[offset + 3] << 24));
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
