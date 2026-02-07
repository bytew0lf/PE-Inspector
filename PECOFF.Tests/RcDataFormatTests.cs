using System;
using System.Collections.Generic;
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
    public void RcData_Detects_UnityFs_Details()
    {
        List<byte> bytes = new List<byte>();
        bytes.AddRange(Encoding.ASCII.GetBytes("UnityFS"));
        bytes.Add(0);
        bytes.AddRange(BitConverter.GetBytes(1u));
        bytes.AddRange(Encoding.ASCII.GetBytes("2020.1.0f1"));
        bytes.Add(0);
        bytes.AddRange(Encoding.ASCII.GetBytes("abcd"));
        bytes.Add(0);

        bool parsed = PECOFF.TryDetectRcDataFormatForTest(bytes.ToArray(), out string format, out string details);

        Assert.True(parsed);
        Assert.Equal("UnityFS", format);
        Assert.Contains("ver=1", details, StringComparison.Ordinal);
        Assert.Contains("unity=2020.1.0f1", details, StringComparison.Ordinal);
        Assert.Contains("rev=abcd", details, StringComparison.Ordinal);
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
    public void RcData_Detects_FlatBuffers_Details()
    {
        byte[] data = new byte[16];
        BitConverter.GetBytes(8).CopyTo(data, 0); // root table offset
        Encoding.ASCII.GetBytes("TEST").CopyTo(data, 4);
        BitConverter.GetBytes(-4).CopyTo(data, 8); // vtable offset
        BitConverter.GetBytes((ushort)4).CopyTo(data, 12); // vtable length
        BitConverter.GetBytes((ushort)4).CopyTo(data, 14); // object size

        bool parsed = PECOFF.TryDetectRcDataFormatForTest(data, out string format, out string details);

        Assert.True(parsed);
        Assert.Equal("FlatBuffers", format);
        Assert.Contains("root=0x8", details, StringComparison.Ordinal);
        Assert.Contains("vtbl=4", details, StringComparison.Ordinal);
        Assert.Contains("obj=4", details, StringComparison.Ordinal);
        Assert.Contains("id=TEST", details, StringComparison.Ordinal);
    }

    [Fact]
    public void RcData_Detects_Protobuf()
    {
        byte[] data = new byte[] { 0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69 };
        string format = PECOFF.DetectRcDataFormatForTest(data);
        Assert.Equal("Protobuf", format);
    }

    [Fact]
    public void RcData_Detects_Protobuf_Details()
    {
        byte[] data = new byte[] { 0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69 };
        bool parsed = PECOFF.TryDetectRcDataFormatForTest(data, out string format, out string details);

        Assert.True(parsed);
        Assert.Equal("Protobuf", format);
        Assert.Contains("fields=2", details, StringComparison.Ordinal);
    }
}
