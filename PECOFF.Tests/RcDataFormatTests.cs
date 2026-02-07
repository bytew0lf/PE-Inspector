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
    public void RcData_Detects_JsonSchema()
    {
        byte[] data = Encoding.UTF8.GetBytes("{\"$schema\":\"https://example.com/schema\",\"title\":\"Test\"}");
        string format = PECOFF.DetectRcDataFormatForTest(data);
        Assert.Equal("JSON-Schema", format);
    }

    [Fact]
    public void RcData_Detects_XmlManifest()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                     "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" +
                     "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" +
                     "<security>" +
                     "<requestedPrivileges>" +
                     "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" +
                     "</requestedPrivileges>" +
                     "</security>" +
                     "</trustInfo>" +
                     "</assembly>";
        byte[] data = Encoding.UTF8.GetBytes(xml);
        string format = PECOFF.DetectRcDataFormatForTest(data);
        Assert.Equal("XML-Manifest", format);
    }

    [Fact]
    public void RcData_Detects_EmbeddedPe()
    {
        byte[] data = new byte[] { 0x4D, 0x5A, 0x90, 0x00 };
        string format = PECOFF.DetectRcDataFormatForTest(data);
        Assert.Equal("EmbeddedPE", format);
    }
}
