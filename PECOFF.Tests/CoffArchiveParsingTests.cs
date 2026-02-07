using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using PECoff;
using Xunit;

public class CoffArchiveParsingTests
{
    [Fact]
    public void CoffArchive_Parses_ImportObject_And_LongName()
    {
        string path = Path.Combine(Path.GetTempPath(), "pecoff-archive-" + Guid.NewGuid().ToString("N") + ".lib");
        File.WriteAllBytes(path, BuildArchiveBytes());
        try
        {
            PECOFF parser = new PECOFF(path);
            Assert.NotNull(parser.CoffArchive);
            Assert.Equal("COFF-Archive", parser.ImageKind);
            Assert.Equal(3, parser.CoffArchive.MemberCount);
            Assert.NotNull(parser.CoffArchive.SymbolTable);

            CoffArchiveMemberInfo? member = parser.CoffArchive.Members.FirstOrDefault(m => m.IsImportObject);
            Assert.NotNull(member);
            Assert.Equal("longmember.obj", member.Name);
            Assert.NotNull(member.ImportObject);
            Assert.Equal("MySymbol", member.ImportObject.SymbolName);
            Assert.Equal("MyDll.dll", member.ImportObject.DllName);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static byte[] BuildArchiveBytes()
    {
        using MemoryStream ms = new MemoryStream();
        WriteAscii(ms, "!<arch>\n");

        byte[] symbolTable = new byte[4];
        WriteMember(ms, "/", symbolTable);

        byte[] longNames = Encoding.ASCII.GetBytes("longmember.obj/\n");
        WriteMember(ms, "//", longNames);

        byte[] importObject = BuildImportObject();
        WriteMember(ms, "/0", importObject);

        return ms.ToArray();
    }

    private static byte[] BuildImportObject()
    {
        byte[] data = new byte[20 + 1 + 8 + 1 + 9 + 1];
        WriteUInt16(data, 0, 0);
        WriteUInt16(data, 2, 0xFFFF);
        WriteUInt16(data, 4, 0);
        WriteUInt16(data, 6, 0x8664); // AMD64
        WriteUInt32(data, 8, 0x12345678);
        WriteUInt32(data, 12, 0);
        WriteUInt16(data, 16, 1);
        WriteUInt16(data, 18, (ushort)((1 << 2) | 0));

        int offset = 20;
        offset += WriteAsciiZ(data, offset, "MySymbol");
        offset += WriteAsciiZ(data, offset, "MyDll.dll");
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
