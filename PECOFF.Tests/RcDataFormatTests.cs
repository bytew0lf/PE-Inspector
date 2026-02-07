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

    [Fact]
    public void RcData_Detects_UnityRaw()
    {
        byte[] data = Encoding.ASCII.GetBytes("UnityRaw");
        string format = PECOFF.DetectRcDataFormatForTest(data);
        Assert.Equal("UnityRaw", format);
    }

    [Fact]
    public void RcData_Detects_FlatBuffers()
    {
        byte[] data = new byte[16];
        BitConverter.GetBytes(8).CopyTo(data, 0); // root table offset
        Encoding.ASCII.GetBytes("TEST").CopyTo(data, 4);
        BitConverter.GetBytes(-4).CopyTo(data, 8); // vtable offset
        BitConverter.GetBytes((ushort)4).CopyTo(data, 12); // vtable length
        BitConverter.GetBytes((ushort)4).CopyTo(data, 14); // object size

        string format = PECOFF.DetectRcDataFormatForTest(data);
        Assert.Equal("FlatBuffers", format);
    }

    [Fact]
    public void RcData_Detects_Protobuf()
    {
        byte[] data = new byte[] { 0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69 };
        string format = PECOFF.DetectRcDataFormatForTest(data);
        Assert.Equal("Protobuf", format);
    }
}
