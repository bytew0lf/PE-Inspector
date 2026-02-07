using System;
using System.Text;
using PECoff;
using Xunit;

public class RcDataFormatTests
{
    [Fact]
    public void RcData_Detects_Json()
    {
        byte[] data = Encoding.UTF8.GetBytes("{\"value\":1}");
        string format = PECOFF.DetectRcDataFormatForTest(data);
        Assert.Equal("JSON", format);
    }

    [Fact]
    public void RcData_Detects_EmbeddedPe()
    {
        byte[] data = new byte[] { 0x4D, 0x5A, 0x90, 0x00 };
        string format = PECOFF.DetectRcDataFormatForTest(data);
        Assert.Equal("EmbeddedPE", format);
    }
}
