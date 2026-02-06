using System;
using System.Collections.Generic;
using PECoff;
using Xunit;

public class RvaMappingFuzzTests
{
    [Fact]
    public void RvaMapping_Fuzz_Does_Not_Throw()
    {
        Random rng = new Random(4242);
        for (int iteration = 0; iteration < 50; iteration++)
        {
            int sectionCount = rng.Next(1, 6);
            List<SectionRange> sections = new List<SectionRange>();
            uint rawPointer = 0;
            for (int i = 0; i < sectionCount; i++)
            {
                uint rawSize = (uint)rng.Next(128, 2048);
                uint virtualSize = (uint)rng.Next(64, (int)rawSize + 256);
                uint virtualAddress = (uint)(0x1000 + (i * 0x1000));
                sections.Add(new SectionRange($"S{i}", virtualAddress, virtualSize, rawPointer, rawSize));
                rawPointer += rawSize + (uint)rng.Next(0, 128);
            }

            long fileLength = rawPointer + 1024;
            uint rva = (uint)rng.Next(0, 0x8000);

            Exception? ex = Record.Exception(() =>
            {
                bool mapped = PECOFF.TryGetFileOffsetForTest(sections, rva, fileLength, out long offset);
                if (mapped)
                {
                    Assert.InRange(offset, 0, fileLength);
                }
            });

            Assert.Null(ex);
        }
    }
}
