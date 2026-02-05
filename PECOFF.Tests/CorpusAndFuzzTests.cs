using System;
using System.IO;
using Xunit;
using PECoff;

public class CorpusAndFuzzTests
{
    [Theory]
    [MemberData(nameof(CorruptSamples))]
    public void Corrupt_Corpus_Fails(byte[] payload)
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, payload);
            Exception? ex = Record.Exception(() => new PECOFF(path));
            Assert.Null(ex);

            PECOFF parser = new PECOFF(path);
            Assert.False(parser.ParseResult.IsSuccess);
            Assert.NotEmpty(parser.ParseResult.Errors);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Fuzz_Random_Inputs_Do_Not_Throw()
    {
        Random rng = new Random(12345);
        for (int i = 0; i < 50; i++)
        {
            int size = rng.Next(0, 4096);
            byte[] data = new byte[size];
            rng.NextBytes(data);

            string path = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(path, data);
                Exception? ex = Record.Exception(() => new PECOFF(path));
                Assert.Null(ex);
            }
            finally
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void Result_Snapshot_Contains_Core_Fields()
    {
        string assemblyPath = typeof(PECOFF).Assembly.Location;
        PECOFF parser = new PECOFF(assemblyPath);
        PECOFFResult result = parser.ToResult();

        Assert.NotNull(result);
        Assert.False(string.IsNullOrWhiteSpace(result.Hash));
        Assert.Equal(parser.Imports.Length, result.Imports.Count);
        Assert.Equal(parser.Exports.Length, result.Exports.Count);
    }

    public static TheoryData<byte[]> CorruptSamples()
    {
        TheoryData<byte[]> data = new TheoryData<byte[]>();
        data.Add(Array.Empty<byte>());
        data.Add(new byte[] { 0x00 });
        data.Add(new byte[] { 0x4D, 0x5A }); // "MZ" only
        data.Add(new byte[] { 0x4D, 0x5A, 0x90, 0x00 }); // short MZ

        byte[] truncated = new byte[64];
        truncated[0] = 0x4D;
        truncated[1] = 0x5A;
        data.Add(truncated);

        byte[] invalidPeOffset = new byte[128];
        invalidPeOffset[0] = 0x4D;
        invalidPeOffset[1] = 0x5A;
        invalidPeOffset[0x3C] = 0xFF;
        invalidPeOffset[0x3D] = 0xFF;
        invalidPeOffset[0x3E] = 0xFF;
        invalidPeOffset[0x3F] = 0x7F;
        data.Add(invalidPeOffset);

        byte[] random = new byte[512];
        new Random(42).NextBytes(random);
        data.Add(random);

        return data;
    }
}
