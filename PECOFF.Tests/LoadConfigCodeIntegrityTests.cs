using System;
using PECoff;
using Xunit;

public class LoadConfigCodeIntegrityTests
{
    [Fact]
    public void CodeIntegrity_Parses_Flags()
    {
        byte[] data = new byte[12];
        BitConverter.GetBytes((ushort)0x5).CopyTo(data, 0);
        BitConverter.GetBytes((ushort)0x2).CopyTo(data, 2);
        BitConverter.GetBytes(0x1234u).CopyTo(data, 4);
        BitConverter.GetBytes(0u).CopyTo(data, 8);

        bool parsed = PECOFF.TryReadCodeIntegrityForTest(data, out LoadConfigCodeIntegrityInfo info);
        Assert.True(parsed);
        Assert.Equal((ushort)0x5, info.Flags);
        Assert.Equal((ushort)0x2, info.Catalog);
        Assert.Equal(0x1234u, info.CatalogOffset);
        Assert.Contains("0x0001", info.FlagNames);
        Assert.Contains("0x0004", info.FlagNames);
    }
}
