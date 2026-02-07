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

    [Fact]
    public void Tls_Template_Info_ZeroFill_Only()
    {
        TlsTemplateInfo info = PECOFF.BuildTlsTemplateInfoForTest(
            0,
            0,
            0,
            32,
            16,
            rawDataMapped: true,
            rawDataHash: string.Empty,
            rawDataPreviewIsText: false,
            rawDataPreview: string.Empty);

        Assert.Equal((uint)32, info.TotalSize);
        Assert.Contains("zero-fill only", info.Notes, StringComparison.Ordinal);
    }

    [Fact]
    public void Tls_Template_Info_Alignment_Check()
    {
        TlsTemplateInfo info = PECOFF.BuildTlsTemplateInfoForTest(
            0x1000,
            0x100A,
            10,
            0,
            8,
            rawDataMapped: true,
            rawDataHash: "hash",
            rawDataPreviewIsText: false,
            rawDataPreview: "preview");

        Assert.False(info.IsAligned);
        Assert.Contains("template size not aligned", info.Notes, StringComparison.Ordinal);
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
