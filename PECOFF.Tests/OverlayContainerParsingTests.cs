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

    [Fact]
    public void Overlay_SevenZip_NextHeader_Parses_FileNames()
    {
        byte[] data = BuildMinimalSevenZip("file.txt");
        OverlayContainerInfo info = PECOFF.ParseSevenZipContainerForTest(data);
        Assert.NotNull(info);
        Assert.Equal("7-Zip", info.Type);
        Assert.Single(info.Entries);
        Assert.Equal("file.txt", info.Entries[0].Name);
    }

    [Fact]
    public void Overlay_SevenZip_EncodedHeader_Parses_FileNames()
    {
        byte[] data = BuildMinimalSevenZipEncoded("encoded.txt");
        OverlayContainerInfo info = PECOFF.ParseSevenZipContainerForTest(data);
        Assert.NotNull(info);
        Assert.Equal("7-Zip", info.Type);
        Assert.Single(info.Entries);
        Assert.Equal("encoded.txt", info.Entries[0].Name);
        Assert.Contains("pack=", info.Notes, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rar5_Vint_Decodes()
    {
        byte[] data = new byte[] { 0xAC, 0x02 };
        bool ok = PECOFF.TryReadRar5VintForTest(data, out ulong value, out int bytesRead);
        Assert.True(ok);
        Assert.Equal(300u, value);
        Assert.Equal(2, bytesRead);
    }

    [Fact]
    public void Overlay_Rar5_FileEntry_Parses_Name()
    {
        byte[] data = BuildMinimalRar5("hello.txt");
        OverlayContainerInfo info = PECOFF.ParseRar5ContainerForTest(data);
        Assert.NotNull(info);
        Assert.Equal("RAR", info.Type);
        Assert.Equal("RAR5", info.Version);
        Assert.Single(info.Entries);
        Assert.Equal("hello.txt", info.Entries[0].Name);
        Assert.Equal(2, info.Entries[0].UncompressedSize);
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

    private static byte[] BuildMinimalSevenZip(string fileName)
    {
        byte[] nextHeader = BuildSevenZipNextHeader(fileName);
        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        writer.Write(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C });
        writer.Write((byte)0);
        writer.Write((byte)4);
        writer.Write(0u);
        writer.Write((ulong)0);
        writer.Write((ulong)nextHeader.Length);
        writer.Write(0u);
        writer.Write(nextHeader);

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildMinimalSevenZipEncoded(string fileName)
    {
        byte[] packedHeader = BuildSevenZipNextHeader(fileName);
        byte[] encodedHeader = BuildSevenZipEncodedHeader(packedHeader.Length);

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        writer.Write(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C });
        writer.Write((byte)0);
        writer.Write((byte)4);
        writer.Write(0u);
        writer.Write((ulong)0); // NextHeaderOffset
        writer.Write((ulong)encodedHeader.Length);
        writer.Write(0u);
        writer.Write(encodedHeader);
        writer.Write(packedHeader);

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildSevenZipNextHeader(string fileName)
    {
        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        writer.Write((byte)0x01); // Header
        writer.Write((byte)0x05); // FilesInfo
        Write7zUInt64(writer, 1);
        writer.Write((byte)0x11); // Name
        byte[] nameBytes = Encoding.Unicode.GetBytes(fileName + "\0");
        Write7zUInt64(writer, (ulong)(nameBytes.Length + 1));
        writer.Write((byte)0x00); // external = 0
        writer.Write(nameBytes);
        writer.Write((byte)0x00); // end FilesInfo
        writer.Write((byte)0x00); // end Header

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildSevenZipEncodedHeader(int packedSize)
    {
        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        writer.Write((byte)0x17); // EncodedHeader
        writer.Write((byte)0x06); // PackInfo
        Write7zUInt64(writer, 0); // PackPos
        Write7zUInt64(writer, 1); // NumPackStreams
        writer.Write((byte)0x09); // Size
        Write7zUInt64(writer, (ulong)packedSize);
        writer.Write((byte)0x00); // End PackInfo

        writer.Write((byte)0x07); // UnpackInfo
        writer.Write((byte)0x0B); // Folder
        Write7zUInt64(writer, 1); // NumFolders
        writer.Write((byte)0x00); // External
        Write7zUInt64(writer, 1); // NumCoders
        writer.Write((byte)0x01); // coder flags (id size 1)
        writer.Write((byte)0x00); // Copy method
        writer.Write((byte)0x0C); // UnpackSize
        Write7zUInt64(writer, (ulong)packedSize);
        writer.Write((byte)0x00); // End UnpackInfo

        writer.Write((byte)0x08); // SubStreamsInfo
        writer.Write((byte)0x00); // End SubStreamsInfo
        writer.Write((byte)0x00); // End StreamsInfo

        writer.Flush();
        return ms.ToArray();
    }

    private static void Write7zUInt64(BinaryWriter writer, ulong value)
    {
        if (value < 0x80)
        {
            writer.Write((byte)value);
            return;
        }

        int extra = 0;
        while (extra < 8)
        {
            ulong max = (1UL << (7 + (extra * 8))) - 1;
            if (value <= max)
            {
                break;
            }

            extra++;
        }

        int lowBits = 7 - extra;
        byte first = (byte)((0xFF << (8 - extra)) & 0xFF);
        first |= (byte)(value & ((1UL << lowBits) - 1));
        writer.Write(first);
        for (int i = 0; i < extra; i++)
        {
            writer.Write((byte)((value >> (lowBits + (8 * i))) & 0xFF));
        }
    }

    private static byte[] BuildMinimalRar5(string fileName)
    {
        byte[] nameBytes = Encoding.UTF8.GetBytes(fileName);
        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        writer.Write(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 });

        using MemoryStream headerData = new MemoryStream();
        using (BinaryWriter headerWriter = new BinaryWriter(headerData, Encoding.UTF8, leaveOpen: true))
        {
            WriteRar5Vint(headerWriter, 0); // file flags
            WriteRar5Vint(headerWriter, 2); // uncompressed size
            WriteRar5Vint(headerWriter, (ulong)nameBytes.Length);
            headerWriter.Write(nameBytes);
        }

        byte[] headerDataBytes = headerData.ToArray();

        using MemoryStream header = new MemoryStream();
        using (BinaryWriter headerWriter = new BinaryWriter(header, Encoding.UTF8, leaveOpen: true))
        {
            headerWriter.Write(0u); // CRC32 placeholder
            WriteRar5Vint(headerWriter, (ulong)(1 + 1 + headerDataBytes.Length)); // header size
            WriteRar5Vint(headerWriter, 2); // file header type
            WriteRar5Vint(headerWriter, 0); // header flags
            headerWriter.Write(headerDataBytes);
        }

        writer.Write(header.ToArray());
        writer.Flush();
        return ms.ToArray();
    }

    private static void WriteRar5Vint(BinaryWriter writer, ulong value)
    {
        while (true)
        {
            byte b = (byte)(value & 0x7F);
            value >>= 7;
            if (value != 0)
            {
                b |= 0x80;
            }

            writer.Write(b);
            if (value == 0)
            {
                break;
            }
        }
    }
}
