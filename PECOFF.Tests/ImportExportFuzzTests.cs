using System;
using System.IO;
using Xunit;
using PECoff;

public class ImportExportFuzzTests
{
    [Fact]
    public void ImportExport_Directory_Fuzz_Does_Not_Throw()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));

        string basePath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        byte[] baseData = File.ReadAllBytes(basePath);
        Assert.True(TryGetDataDirectoryOffset(baseData, out int dataDirOffset));

        uint[] edges = new uint[]
        {
            0, 1, 2, 0x10, 0x100, 0x1000,
            (uint)Math.Max(0, baseData.Length - 1),
            (uint)baseData.Length,
            0x7FFFFFFF,
            0xFFFFFFFF
        };

        Random rng = new Random(2468);
        for (int i = 0; i < 60; i++)
        {
            uint exportRva = edges[rng.Next(edges.Length)];
            uint exportSize = edges[rng.Next(edges.Length)];
            uint importRva = edges[rng.Next(edges.Length)];
            uint importSize = edges[rng.Next(edges.Length)];

            byte[] mutated = (byte[])baseData.Clone();
            WriteUInt32(mutated, dataDirOffset + (0 * 8), exportRva);
            WriteUInt32(mutated, dataDirOffset + (0 * 8) + 4, exportSize);
            WriteUInt32(mutated, dataDirOffset + (1 * 8), importRva);
            WriteUInt32(mutated, dataDirOffset + (1 * 8) + 4, importSize);

            string tempFile = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(tempFile, mutated);
                Exception? ex = Record.Exception(() => new PECOFF(tempFile));
                Assert.Null(ex);
            }
            finally
            {
                File.Delete(tempFile);
            }
        }
    }

    private static bool TryGetDataDirectoryOffset(byte[] data, out int dataDirectoryOffset)
    {
        dataDirectoryOffset = 0;
        if (data == null || data.Length < 0x100)
        {
            return false;
        }

        int peOffset = BitConverter.ToInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 0x40 >= data.Length)
        {
            return false;
        }

        int optionalHeaderOffset = peOffset + 4 + 20;
        if (optionalHeaderOffset + 2 >= data.Length)
        {
            return false;
        }

        ushort magic = BitConverter.ToUInt16(data, optionalHeaderOffset);
        bool isPe32Plus = magic == 0x20B;
        dataDirectoryOffset = optionalHeaderOffset + (isPe32Plus ? 0x70 : 0x60);
        return dataDirectoryOffset + (8 * 2) <= data.Length;
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
