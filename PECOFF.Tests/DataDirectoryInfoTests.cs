using System;
using System.Collections.Generic;
using System.IO;
using PECoff;
using Xunit;

public class DataDirectoryInfoTests
{
    [Theory]
    [MemberData(nameof(MinimalFixtureFiles))]
    public void DataDirectories_Count_Matches_Header(string fileName)
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", fileName);
        byte[] data = File.ReadAllBytes(path);

        Assert.True(TryReadHeader(data, out int optionalHeaderOffset, out bool isPe32Plus, out uint numberOfRvaAndSizes));

        PECOFF parser = new PECOFF(path);
        Assert.Equal((int)numberOfRvaAndSizes, parser.Result.DataDirectories.Count);
    }

    [Theory]
    [MemberData(nameof(MinimalFixtureFiles))]
    public void DataDirectories_SpecialEntries_Match_Header(string fileName)
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", fileName);
        byte[] data = File.ReadAllBytes(path);

        Assert.True(TryReadHeader(data, out int optionalHeaderOffset, out bool isPe32Plus, out uint numberOfRvaAndSizes));

        PECOFF parser = new PECOFF(path);

        AssertArchitectureDirectory(parser.Result.ArchitectureDirectory, data, optionalHeaderOffset, isPe32Plus, numberOfRvaAndSizes);
        AssertGlobalPtrDirectory(parser.Result.GlobalPtrDirectory, data, optionalHeaderOffset, isPe32Plus, numberOfRvaAndSizes);
        AssertIatDirectory(parser.Result.IatDirectory, data, optionalHeaderOffset, isPe32Plus, numberOfRvaAndSizes);
    }

    public static IEnumerable<object[]> MinimalFixtureFiles()
    {
        return MinimalFixtureTests.MinimalFixtureFiles();
    }

    private static void AssertArchitectureDirectory(ArchitectureDirectoryInfo? actual, byte[] data, int optionalHeaderOffset, bool isPe32Plus, uint numberOfRvaAndSizes)
    {
        const int index = 7;
        if (numberOfRvaAndSizes <= index)
        {
            Assert.Null(actual);
            return;
        }

        Assert.True(TryReadDirectoryEntry(data, optionalHeaderOffset, isPe32Plus, index, out uint rva, out uint size));
        if (rva == 0 && size == 0)
        {
            Assert.Null(actual);
            return;
        }

        Assert.NotNull(actual);
        Assert.Equal(rva, actual!.VirtualAddress);
        Assert.Equal(size, actual.Size);
    }

    private static void AssertGlobalPtrDirectory(GlobalPtrDirectoryInfo? actual, byte[] data, int optionalHeaderOffset, bool isPe32Plus, uint numberOfRvaAndSizes)
    {
        const int index = 8;
        if (numberOfRvaAndSizes <= index)
        {
            Assert.Null(actual);
            return;
        }

        Assert.True(TryReadDirectoryEntry(data, optionalHeaderOffset, isPe32Plus, index, out uint rva, out uint size));
        if (rva == 0 && size == 0)
        {
            Assert.Null(actual);
            return;
        }

        Assert.NotNull(actual);
        Assert.Equal(rva, actual!.VirtualAddress);
        Assert.Equal(size, actual.Size);
    }

    private static void AssertIatDirectory(IatDirectoryInfo? actual, byte[] data, int optionalHeaderOffset, bool isPe32Plus, uint numberOfRvaAndSizes)
    {
        const int index = 12;
        if (numberOfRvaAndSizes <= index)
        {
            Assert.Null(actual);
            return;
        }

        Assert.True(TryReadDirectoryEntry(data, optionalHeaderOffset, isPe32Plus, index, out uint rva, out uint size));
        if (rva == 0 && size == 0)
        {
            Assert.Null(actual);
            return;
        }

        Assert.NotNull(actual);
        Assert.Equal(rva, actual!.VirtualAddress);
        Assert.Equal(size, actual.Size);
        uint entrySize = isPe32Plus ? 8u : 4u;
        Assert.Equal(entrySize, actual.EntrySize);
        Assert.Equal(size / entrySize, actual.EntryCount);
        Assert.Equal(size % entrySize == 0, actual.SizeAligned);
    }

    private static bool TryReadHeader(byte[] data, out int optionalHeaderOffset, out bool isPe32Plus, out uint numberOfRvaAndSizes)
    {
        optionalHeaderOffset = 0;
        isPe32Plus = false;
        numberOfRvaAndSizes = 0;

        if (data == null || data.Length < 0x100)
        {
            return false;
        }

        int peOffset = BitConverter.ToInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 0x40 >= data.Length)
        {
            return false;
        }

        int fileHeaderOffset = peOffset + 4;
        optionalHeaderOffset = fileHeaderOffset + 20;
        if (optionalHeaderOffset + 2 > data.Length)
        {
            return false;
        }

        ushort magic = BitConverter.ToUInt16(data, optionalHeaderOffset);
        isPe32Plus = magic == 0x20B;
        int numberOffset = optionalHeaderOffset + (isPe32Plus ? 0x6C : 0x5C);
        if (numberOffset + 4 > data.Length)
        {
            return false;
        }

        numberOfRvaAndSizes = BitConverter.ToUInt32(data, numberOffset);
        return true;
    }

    private static bool TryReadDirectoryEntry(byte[] data, int optionalHeaderOffset, bool isPe32Plus, int index, out uint rva, out uint size)
    {
        rva = 0;
        size = 0;
        int dataDirectoryOffset = optionalHeaderOffset + (isPe32Plus ? 0x70 : 0x60);
        int entryOffset = dataDirectoryOffset + (index * 8);
        if (entryOffset + 8 > data.Length)
        {
            return false;
        }

        rva = BitConverter.ToUInt32(data, entryOffset);
        size = BitConverter.ToUInt32(data, entryOffset + 4);
        return true;
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
