using System;
using System.Text;
using PECoff;
using Xunit;

public class DebugDirectoryParsingTests
{
    [Fact]
    public void PogoData_Parses_Entry()
    {
        byte[] name = Encoding.ASCII.GetBytes("foo\0");
        int size = 4 + 8 + name.Length;
        int padded = (size + 3) & ~3;
        byte[] data = new byte[padded];
        Encoding.ASCII.GetBytes("PGO ").CopyTo(data, 0);
        BitConverter.GetBytes(0x20u).CopyTo(data, 4);
        BitConverter.GetBytes(0x1000u).CopyTo(data, 8);
        name.CopyTo(data, 12);

        bool parsed = PECOFF.TryParsePogoDataForTest(data, out DebugPogoInfo info);
        Assert.True(parsed);
        Assert.Equal("PGO", info.Signature);
        Assert.Equal(1, info.TotalEntryCount);
        Assert.Single(info.Entries);
        Assert.Equal((uint)0x1000, info.Entries[0].Rva);
        Assert.Equal("foo", info.Entries[0].Name);
    }

    [Fact]
    public void VcFeatureData_Parses_Flags()
    {
        byte[] data = BitConverter.GetBytes(0x5u);
        bool parsed = PECOFF.TryParseVcFeatureDataForTest(data, out DebugVcFeatureInfo info);
        Assert.True(parsed);
        Assert.Equal(0x5u, info.Flags);
        Assert.Contains("0x00000001", info.FlagNames);
        Assert.Contains("0x00000004", info.FlagNames);
    }

    [Fact]
    public void ExDllCharacteristics_Parses_Flags()
    {
        byte[] data = BitConverter.GetBytes(0x2u);
        bool parsed = PECOFF.TryParseExDllCharacteristicsDataForTest(data, out DebugExDllCharacteristicsInfo info);
        Assert.True(parsed);
        Assert.Equal(0x2u, info.Characteristics);
        Assert.Contains("0x00000002", info.FlagNames);
    }

    [Fact]
    public void FpoData_Parses_Entry()
    {
        byte[] data = new byte[16];
        BitConverter.GetBytes(0x1000u).CopyTo(data, 0);
        BitConverter.GetBytes(0x200u).CopyTo(data, 4);
        BitConverter.GetBytes(0x10u).CopyTo(data, 8);
        BitConverter.GetBytes((ushort)0x8).CopyTo(data, 12);

        byte prolog = 5;
        byte regs = 3;
        byte frame = 2;
        ushort flags = (ushort)(prolog |
                                (regs << 8) |
                                (1 << 11) |
                                (0 << 12) |
                                (frame << 14));
        BitConverter.GetBytes(flags).CopyTo(data, 14);

        bool parsed = PECOFF.TryParseFpoDataForTest(data, out DebugFpoInfo info);
        Assert.True(parsed);
        Assert.Equal(1, info.TotalEntryCount);
        Assert.Single(info.Entries);
        Assert.Equal((uint)0x1000, info.Entries[0].StartOffset);
        Assert.True(info.Entries[0].HasSeh);
        Assert.Equal((byte)2, info.Entries[0].FrameType);
    }
}
