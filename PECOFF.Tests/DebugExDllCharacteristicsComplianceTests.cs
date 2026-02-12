using System;
using System.IO;
using PECoff;
using Xunit;

public class DebugExDllCharacteristicsComplianceTests
{
    [Fact]
    public void ExDllCharacteristics_KnownFlags_AreNamed_WithoutSpecViolation()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] source = File.ReadAllBytes(validPath);
        byte[] mutated = BuildPeWithExDllCharacteristicsDebugEntry(source, 0x00000041u);

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            DebugDirectoryEntry debugEntry = Assert.Single(
                parser.DebugDirectories,
                entry => entry.Type == DebugDirectoryType.ExDllCharacteristics);

            Assert.NotNull(debugEntry.ExDllCharacteristics);
            Assert.Contains("EX_DLLCHARACTERISTICS_CET_COMPAT", debugEntry.ExDllCharacteristics!.FlagNames);
            Assert.Contains("EX_DLLCHARACTERISTICS_FORWARD_CFI_COMPAT", debugEntry.ExDllCharacteristics.FlagNames);

            Assert.DoesNotContain(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ExDllCharacteristics_UnknownFlags_EmitSpecViolation_AndStrictModeFails()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] source = File.ReadAllBytes(validPath);
        byte[] mutated = BuildPeWithExDllCharacteristicsDebugEntry(source, 0x80000000u);

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS contains unsupported flag bits 0x80000000", StringComparison.Ordinal));

            string json = parser.Result.ToJsonReport(includeBinary: false, indented: false);
            Assert.Contains("SPEC violation: IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS", json, StringComparison.Ordinal);

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ExDllCharacteristics_MixedKnownAndUnknownFlags_EmitSpecViolation_AndKeepNamedFlags()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] source = File.ReadAllBytes(validPath);
        byte[] mutated = BuildPeWithExDllCharacteristicsDebugEntry(source, 0x80000001u);

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            DebugDirectoryEntry debugEntry = Assert.Single(
                parser.DebugDirectories,
                entry => entry.Type == DebugDirectoryType.ExDllCharacteristics);

            Assert.NotNull(debugEntry.ExDllCharacteristics);
            Assert.Contains("EX_DLLCHARACTERISTICS_CET_COMPAT", debugEntry.ExDllCharacteristics!.FlagNames);
            Assert.Contains("0x80000000", debugEntry.ExDllCharacteristics.FlagNames);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS contains unsupported flag bits 0x80000000", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ExDllCharacteristics_NonSpecBit2_EmitSpecViolation_AndStrictModeFails()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] source = File.ReadAllBytes(validPath);
        byte[] mutated = BuildPeWithExDllCharacteristicsDebugEntry(source, 0x00000002u);

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS contains unsupported flag bits 0x00000002", StringComparison.Ordinal));

            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    private static byte[] BuildPeWithExDllCharacteristicsDebugEntry(byte[] source, uint flags)
    {
        Assert.NotNull(source);
        Assert.True(TryGetPeLayout(
            source,
            out int peOffset,
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

        Assert.True(firstSectionRawPointer < mutated.Length);
        Assert.True(firstSectionRawSize >= 0x80);

        int debugEntryRaw = checked((int)firstSectionRawPointer + 0x40);
        int debugDataRaw = debugEntryRaw + 0x20;
        Assert.True(debugDataRaw + 4 <= mutated.Length);

        uint debugEntryRva = firstSectionRva + 0x40u;
        uint debugDataRva = debugEntryRva + 0x20u;

        int debugDirectoryOffset = dataDirectoryStart + (6 * 8);
        WriteUInt32(mutated, debugDirectoryOffset, debugEntryRva);
        WriteUInt32(mutated, debugDirectoryOffset + 4, 28u);

        // IMAGE_DEBUG_DIRECTORY (size 28)
        WriteUInt32(mutated, debugEntryRaw + 0, 0u); // Characteristics
        WriteUInt32(mutated, debugEntryRaw + 4, 0u); // TimeDateStamp
        WriteUInt16(mutated, debugEntryRaw + 8, 0); // MajorVersion
        WriteUInt16(mutated, debugEntryRaw + 10, 0); // MinorVersion
        WriteUInt32(mutated, debugEntryRaw + 12, (uint)DebugDirectoryType.ExDllCharacteristics);
        WriteUInt32(mutated, debugEntryRaw + 16, 4u); // SizeOfData
        WriteUInt32(mutated, debugEntryRaw + 20, debugDataRva); // AddressOfRawData
        WriteUInt32(mutated, debugEntryRaw + 24, (uint)debugDataRaw); // PointerToRawData

        WriteUInt32(mutated, debugDataRaw, flags);
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
