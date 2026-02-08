using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

public class MinimalFixtureTests
{
    [Theory]
    [MemberData(nameof(MinimalFixtures))]
    public void Minimal_Fixtures_Have_Expected_Metadata(string fileName, ushort machine, bool isDll, bool isPe32Plus, bool hasCertificate)
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", fileName);
        Assert.True(File.Exists(path), $"Missing fixture: {path}");

        FixtureInfo info = ReadFixtureInfo(path);
        Assert.Equal(machine, info.Machine);
        Assert.Equal(isDll, info.IsDll);
        Assert.Equal(isPe32Plus, info.IsPe32Plus);
        Assert.Equal(hasCertificate, info.HasCertificate);
    }

    [Theory]
    [MemberData(nameof(MinimalFixtureFiles))]
    public void Minimal_Fixtures_Parse_Without_Errors(string fileName)
    {
        string? fixturesDir = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixturesDir));

        string path = Path.Combine(fixturesDir!, "minimal", fileName);
        PECoff.PECOFF parser = new PECoff.PECOFF(path);
        Assert.True(parser.ParseResult.IsSuccess, $"Parse failed for {fileName}: {string.Join(" | ", parser.ParseResult.Errors)}");
    }

    public static IEnumerable<object[]> MinimalFixtures()
    {
        const ushort I386 = 0x014c;
        const ushort AMD64 = 0x8664;

        yield return new object[] { "PE-Inspector.dll", I386, false, false, false };
        yield return new object[] { "minimal-x86.exe", I386, false, false, false };
        yield return new object[] { "minimal-x64.exe", AMD64, false, true, false };
    }

    public static IEnumerable<object[]> MinimalFixtureFiles()
    {
        yield return new object[] { "PE-Inspector.dll" };
        yield return new object[] { "minimal-x86.exe" };
        yield return new object[] { "minimal-x64.exe" };
    }

    private static FixtureInfo ReadFixtureInfo(string path)
    {
        byte[] data = File.ReadAllBytes(path);
        Assert.True(data.Length >= 0x100);
        Assert.Equal(0x4D, data[0]);
        Assert.Equal(0x5A, data[1]);

        int peOffset = BitConverter.ToInt32(data, 0x3C);
        Assert.True(peOffset > 0 && peOffset + 0x40 < data.Length);
        Assert.Equal(0x50, data[peOffset]);
        Assert.Equal(0x45, data[peOffset + 1]);

        int fileHeaderOffset = peOffset + 4;
        ushort machine = BitConverter.ToUInt16(data, fileHeaderOffset);
        ushort characteristics = BitConverter.ToUInt16(data, fileHeaderOffset + 18);
        bool isDll = (characteristics & 0x2000) != 0;

        int optionalHeaderOffset = fileHeaderOffset + 20;
        ushort magic = BitConverter.ToUInt16(data, optionalHeaderOffset);
        bool isPe32Plus = magic == 0x20B;
        int dataDirectoryOffset = optionalHeaderOffset + (isPe32Plus ? 0x70 : 0x60);
        Assert.True(dataDirectoryOffset + (8 * 5) <= data.Length);

        int certOffset = dataDirectoryOffset + (4 * 8);
        uint certSize = BitConverter.ToUInt32(data, certOffset + 4);
        bool hasCertificate = certSize > 0;

        return new FixtureInfo(machine, isDll, isPe32Plus, hasCertificate);
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

    private readonly struct FixtureInfo
    {
        public ushort Machine { get; }
        public bool IsDll { get; }
        public bool IsPe32Plus { get; }
        public bool HasCertificate { get; }

        public FixtureInfo(ushort machine, bool isDll, bool isPe32Plus, bool hasCertificate)
        {
            Machine = machine;
            IsDll = isDll;
            IsPe32Plus = isPe32Plus;
            HasCertificate = hasCertificate;
        }
    }
}
