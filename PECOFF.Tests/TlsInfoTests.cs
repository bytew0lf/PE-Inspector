using System;
using System.Security.Cryptography;
using System.Text;
using PECoff;
using Xunit;

public class TlsInfoTests
{
    [Fact]
    public void Tls_RawData_Info_Text()
    {
        byte[] data = Encoding.UTF8.GetBytes("Hello TLS raw data");
        bool ok = PECOFF.TryComputeTlsRawDataInfoForTest(data, out string hash, out bool isText, out string preview);

        Assert.True(ok);
        Assert.True(isText);
        Assert.Contains("Hello", preview, StringComparison.Ordinal);
        Assert.Equal(ToHex(SHA256.HashData(data)), hash);
    }

    [Fact]
    public void Tls_RawData_Info_Binary()
    {
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03 };
        bool ok = PECOFF.TryComputeTlsRawDataInfoForTest(data, out string hash, out bool isText, out string preview);

        Assert.True(ok);
        Assert.False(isText);
        Assert.Equal("00010203", preview);
        Assert.Equal(ToHex(SHA256.HashData(data)), hash);
    }

    private static string ToHex(byte[] data)
    {
        StringBuilder sb = new StringBuilder(data.Length * 2);
        foreach (byte b in data)
        {
            sb.Append(b.ToString("X2"));
        }
        return sb.ToString();
    }
}
