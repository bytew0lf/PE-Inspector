using System;
using System.IO;
using PECoff;
using Xunit;

public class DebugDirectoryCanonicalTypeTests
{
    [Theory]
    [InlineData(17u, "UNDEFINED_17", "EmbeddedPortablePdb")]
    [InlineData(18u, "UNKNOWN_18", "Spgo")]
    [InlineData(19u, "UNDEFINED_19", "PdbHash")]
    public void DebugDirectoryType_ExposesCanonicalAndAliasMetadata_InModelAndJson(uint debugType, string expectedCanonical, string expectedAlias)
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] source = File.ReadAllBytes(validPath);
        byte[] payload = BuildPayloadForType(debugType);
        byte[] mutated = BuildPeWithDebugDirectoryEntry(source, debugType, payload);

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            DebugDirectoryEntry entry = Assert.Single(parser.DebugDirectories);
            Assert.Equal(debugType, entry.TypeValue);
            Assert.Equal(expectedCanonical, entry.CanonicalTypeName);
            Assert.Equal(expectedAlias, entry.CompatibilityTypeAlias);

            string json = parser.Result.ToJsonReport(includeBinary: false, indented: false);
            Assert.Contains($"\"CanonicalTypeName\":\"{expectedCanonical}\"", json, StringComparison.Ordinal);
            Assert.Contains($"\"CompatibilityTypeAlias\":\"{expectedAlias}\"", json, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void DebugDirectoryType_StandardType_HasNoCompatibilityAlias()
    {
        DebugDirectoryEntry entry = new DebugDirectoryEntry(
            characteristics: 0,
            timeDateStamp: 0,
            majorVersion: 0,
            minorVersion: 0,
            type: DebugDirectoryType.CodeView,
            sizeOfData: 0,
            addressOfRawData: 0,
            pointerToRawData: 0,
            codeView: null,
            pdb: null,
            coff: null,
            pogo: null,
            vcFeature: null,
            exDllCharacteristics: null,
            fpo: null,
            borland: null,
            reserved: null,
            fixup: null,
            exception: null,
            misc: null,
            omapToSource: null,
            omapFromSource: null,
            repro: null,
            embeddedPortablePdb: null,
            spgo: null,
            pdbHash: null,
            iltcg: null,
            mpx: null,
            clsid: null,
            other: null,
            note: string.Empty);

        Assert.Equal("CodeView", entry.CanonicalTypeName);
        Assert.Equal(string.Empty, entry.CompatibilityTypeAlias);
    }

    private static byte[] BuildPayloadForType(uint debugType)
    {
        return debugType switch
        {
            17u => new byte[] { (byte)'M', (byte)'P', (byte)'D', (byte)'B', 0x10, 0x00, 0x00, 0x00 },
            18u => new byte[] { 0x01, 0x02, 0x03, 0x04 },
            19u => new byte[] { 0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB },
            _ => new byte[] { 0x00 }
        };
    }

    private static byte[] BuildPeWithDebugDirectoryEntry(byte[] source, uint debugType, byte[] payload)
    {
        Assert.NotNull(source);
        Assert.NotNull(payload);
        Assert.True(TryGetPeLayout(
            source,
            out _,
            out int numberOfSections,
            out int dataDirectoryStart,
            out int sectionTableStart));
        Assert.True(numberOfSections > 0);

        byte[] mutated = (byte[])source.Clone();
        int firstSectionOffset = sectionTableStart;
        Assert.True(firstSectionOffset + 40 <= mutated.Length);

        uint firstSectionRva = ReadUInt32(mutated, firstSectionOffset + 12);
        uint firstSectionRawSize = ReadUInt32(mutated, firstSectionOffset + 16);
        uint firstSectionRawPointer = ReadUInt32(mutated, firstSectionOffset + 20);

        int debugEntryRaw = checked((int)firstSectionRawPointer + 0x40);
        int debugDataRaw = debugEntryRaw + 0x20;
        Assert.True(debugDataRaw + payload.Length <= mutated.Length);
        Assert.True(firstSectionRawSize >= (uint)(0x40 + 0x20 + payload.Length));

        uint debugEntryRva = firstSectionRva + 0x40u;
        uint debugDataRva = debugEntryRva + 0x20u;

        int debugDirectoryOffset = dataDirectoryStart + (6 * 8);
        WriteUInt32(mutated, debugDirectoryOffset, debugEntryRva);
        WriteUInt32(mutated, debugDirectoryOffset + 4, 28u);

        WriteUInt32(mutated, debugEntryRaw + 0, 0u);
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
