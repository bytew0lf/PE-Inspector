using System;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class OverlayContainerParsingTests
{
    [Fact]
    public void Overlay_Zip_Container_Parses_Entries()
    {
        byte[] data = BuildMinimalZip("test.txt", Encoding.ASCII.GetBytes("hi"));
        OverlayContainerInfo info = PECOFF.ParseZipContainerForTest(data);
        Assert.NotNull(info);
        Assert.Equal("ZIP", info.Type);
        Assert.Equal(1, info.EntryCount);
        Assert.Single(info.Entries);
        Assert.Equal("test.txt", info.Entries[0].Name);
        Assert.Equal("Stored", info.Entries[0].CompressionMethod);
    }

    private static byte[] BuildMinimalZip(string fileName, byte[] payload)
    {
        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        byte[] nameBytes = Encoding.UTF8.GetBytes(fileName);
        int localHeaderOffset = (int)ms.Position;

        writer.Write(0x04034B50u);
        writer.Write((ushort)20); // version needed
        writer.Write((ushort)0); // flags
        writer.Write((ushort)0); // method store
        writer.Write((ushort)0); // mod time
        writer.Write((ushort)0); // mod date
        writer.Write(0u); // crc32
        writer.Write((uint)payload.Length);
        writer.Write((uint)payload.Length);
        writer.Write((ushort)nameBytes.Length);
        writer.Write((ushort)0); // extra length
        writer.Write(nameBytes);
        writer.Write(payload);

        int centralDirOffset = (int)ms.Position;

        writer.Write(0x02014B50u);
        writer.Write((ushort)20); // version made by
        writer.Write((ushort)20); // version needed
        writer.Write((ushort)0); // flags
        writer.Write((ushort)0); // method store
        writer.Write((ushort)0); // mod time
        writer.Write((ushort)0); // mod date
        writer.Write(0u); // crc32
        writer.Write((uint)payload.Length);
        writer.Write((uint)payload.Length);
        writer.Write((ushort)nameBytes.Length);
        writer.Write((ushort)0); // extra
        writer.Write((ushort)0); // comment
        writer.Write((ushort)0); // disk start
        writer.Write((ushort)0); // int attr
        writer.Write(0u); // ext attr
        writer.Write((uint)localHeaderOffset);
        writer.Write(nameBytes);

        int centralDirSize = (int)ms.Position - centralDirOffset;

        writer.Write(0x06054B50u);
        writer.Write((ushort)0); // disk
        writer.Write((ushort)0); // start disk
        writer.Write((ushort)1); // entries on disk
        writer.Write((ushort)1); // total entries
        writer.Write((uint)centralDirSize);
        writer.Write((uint)centralDirOffset);
        writer.Write((ushort)0); // comment length

        writer.Flush();
        return ms.ToArray();
    }
}
