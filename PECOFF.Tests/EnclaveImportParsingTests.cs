using System;
using PECoff;
using Xunit;

public class EnclaveImportParsingTests
{
    [Fact]
    public void EnclaveImport_Parses_Basic_Fields()
    {
        byte[] data = new byte[80];
        BitConverter.GetBytes(3u).CopyTo(data, 0);
        BitConverter.GetBytes(7u).CopyTo(data, 4);
        for (int i = 0; i < 32; i++)
        {
            data[8 + i] = (byte)(i + 1);
        }
        for (int i = 0; i < 16; i++)
        {
            data[40 + i] = (byte)(0xA0 + i);
            data[56 + i] = (byte)(0xB0 + i);
        }

        EnclaveImportInfo info = PECOFF.ParseEnclaveImportForTest(data);
        Assert.NotNull(info);
        Assert.Equal(3u, info.MatchType);
        Assert.Equal("FamilyId", info.MatchTypeName);
        Assert.Equal(7u, info.MinimumSecurityVersion);
        Assert.False(string.IsNullOrWhiteSpace(info.UniqueOrAuthorId));
        Assert.False(string.IsNullOrWhiteSpace(info.FamilyId));
        Assert.False(string.IsNullOrWhiteSpace(info.ImageId));
    }
}
