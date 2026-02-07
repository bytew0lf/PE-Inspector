using System;
using System.Text;
using PECoff;
using Xunit;

public class ResourceAnimatedTests
{
    [Fact]
    public void AnimatedCursor_Parses_Anih_Header()
    {
        byte[] anih = new byte[36];
        BitConverter.GetBytes(36u).CopyTo(anih, 0);
        BitConverter.GetBytes(5u).CopyTo(anih, 4);
        BitConverter.GetBytes(5u).CopyTo(anih, 8);
        BitConverter.GetBytes(32u).CopyTo(anih, 12);
        BitConverter.GetBytes(32u).CopyTo(anih, 16);
        BitConverter.GetBytes(32u).CopyTo(anih, 20);
        BitConverter.GetBytes(1u).CopyTo(anih, 24);
        BitConverter.GetBytes(10u).CopyTo(anih, 28);
        BitConverter.GetBytes(1u).CopyTo(anih, 32);

        byte[] chunkHeader = Encoding.ASCII.GetBytes("anih");
        uint chunkSize = (uint)anih.Length;

        byte[] data = new byte[12 + 8 + anih.Length];
        Encoding.ASCII.GetBytes("RIFF").CopyTo(data, 0);
        BitConverter.GetBytes((uint)(data.Length - 8)).CopyTo(data, 4);
        Encoding.ASCII.GetBytes("ACON").CopyTo(data, 8);
        chunkHeader.CopyTo(data, 12);
        BitConverter.GetBytes(chunkSize).CopyTo(data, 16);
        Array.Copy(anih, 0, data, 20, anih.Length);

        bool parsed = PECOFF.TryParseAnimatedResourceForTest(data, out ResourceAnimatedInfo info);
        Assert.True(parsed);
        Assert.Equal("RIFF/ACON", info.Format);
        Assert.Equal((uint)5, info.FrameCount);
        Assert.Equal((uint)32, info.Width);
        Assert.Contains("anih", info.ChunkTypes);
    }
}
