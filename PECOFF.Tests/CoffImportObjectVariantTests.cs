using System;
using System.Globalization;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffImportObjectVariantTests
{
    [Fact]
    public void CoffArchive_Parses_Ordinal_Import_Object()
    {
        byte[] data = BuildArchiveBytes();
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF parser = new PECOFF(path);

            Assert.NotNull(parser.CoffArchive);
            CoffArchiveMemberInfo member = Assert.Single(parser.CoffArchive.Members);
            Assert.True(member.IsImportObject);
            Assert.NotNull(member.ImportObject);
            Assert.True(member.ImportObject.IsImportByOrdinal);
            Assert.Equal((ushort)7, member.ImportObject.Ordinal);
            Assert.Null(member.ImportObject.Hint);
            Assert.Equal("#7", member.ImportObject.ImportName);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildArchiveBytes()
    {
        using MemoryStream ms = new MemoryStream();
        WriteAscii(ms, "!<arch>\n");

        byte[] importObject = BuildImportObject();
        WriteMember(ms, "imp.obj", importObject);

        return ms.ToArray();
    }

    private static byte[] BuildImportObject()
    {
        byte[] data = new byte[20 + 1 + 7 + 1 + 7 + 1];
        WriteUInt16(data, 0, 0);
        WriteUInt16(data, 2, 0xFFFF);
        WriteUInt16(data, 4, 0);
        WriteUInt16(data, 6, 0x14C); // x86
        WriteUInt32(data, 8, 0);
        WriteUInt32(data, 12, 0);
        WriteUInt16(data, 16, 7);
        WriteUInt16(data, 18, 0); // type=0, nameType=ordinal

        int offset = 20;
        offset += WriteAsciiZ(data, offset, "ORDSYM");
        offset += WriteAsciiZ(data, offset, "ORDDLL");
        return data;
    }

    private static void WriteMember(Stream stream, string name, byte[] data)
    {
        string header = (name ?? string.Empty).PadRight(16).Substring(0, 16) +
                        "0".PadRight(12) +
                        "0".PadRight(6) +
                        "0".PadRight(6) +
                        "0".PadRight(8) +
                        data.Length.ToString(CultureInfo.InvariantCulture).PadRight(10) +
                        "`\n";
        WriteAscii(stream, header);
        stream.Write(data, 0, data.Length);
        if ((data.Length & 1) == 1)
        {
            stream.WriteByte((byte)'\n');
        }
    }

    private static void WriteAscii(Stream stream, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);
        stream.Write(bytes, 0, bytes.Length);
    }

    private static void WriteUInt16(byte[] buffer, int offset, ushort value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }

    private static int WriteAsciiZ(byte[] buffer, int offset, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value ?? string.Empty);
        Array.Copy(bytes, 0, buffer, offset, bytes.Length);
        buffer[offset + bytes.Length] = 0;
        return bytes.Length + 1;
    }
}
