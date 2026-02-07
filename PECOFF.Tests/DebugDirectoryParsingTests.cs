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
    public void MiscData_Parses_Ascii()
    {
        byte[] payload = Encoding.ASCII.GetBytes("kernel32.dll\0");
        uint length = (uint)(12 + payload.Length);
        byte[] data = new byte[length];
        BitConverter.GetBytes(1u).CopyTo(data, 0);
        BitConverter.GetBytes(length).CopyTo(data, 4);
        data[8] = 0;
        payload.CopyTo(data, 12);

        bool parsed = PECOFF.TryParseDebugMiscDataForTest(data, out DebugMiscInfo info);
        Assert.True(parsed);
        Assert.Equal(1u, info.DataType);
        Assert.Equal(length, info.Length);
        Assert.False(info.IsUnicode);
        Assert.Equal("kernel32.dll", info.Data);
    }

    [Fact]
    public void OmapData_Parses_Entries()
    {
        byte[] data = new byte[16];
        BitConverter.GetBytes(0x1000u).CopyTo(data, 0);
        BitConverter.GetBytes(0x2000u).CopyTo(data, 4);
        BitConverter.GetBytes(0x1100u).CopyTo(data, 8);
        BitConverter.GetBytes(0x2100u).CopyTo(data, 12);

        bool parsed = PECOFF.TryParseOmapDataForTest(data, out DebugOmapInfo info);
        Assert.True(parsed);
        Assert.Equal(2, info.TotalEntryCount);
        Assert.Equal((uint)0x1000, info.Entries[0].From);
        Assert.Equal((uint)0x2000, info.Entries[0].To);
    }

    [Fact]
    public void ReproData_Parses_Hash()
    {
        byte[] data = { 0xDE, 0xAD, 0xBE, 0xEF };
        bool parsed = PECOFF.TryParseReproDataForTest(data, out DebugReproInfo info);
        Assert.True(parsed);
        Assert.Equal((uint)4, info.DataLength);
        Assert.Equal("DEADBEEF", info.Hash);
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
