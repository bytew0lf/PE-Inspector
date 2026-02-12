using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using PECoff;
using Xunit;

public class CoffArchiveLinkerMemberTests
{
    [Fact]
    public void CoffArchive_Parses_FirstLinkerMember_SymbolReferences()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, BuildArchiveWithFirstLinkerMember());
            PECOFF pe = new PECOFF(path);

            Assert.NotNull(pe.CoffArchive);
            Assert.NotNull(pe.CoffArchive.SymbolTable);
            Assert.Equal("FirstLinkerMember", pe.CoffArchive.SymbolTable.Format);
            Assert.Equal(1, pe.CoffArchive.SymbolTable.SymbolCount);

            CoffArchiveSymbolReferenceInfo symbol = Assert.Single(pe.CoffArchive.SymbolTable.References);
            Assert.Equal("alpha", symbol.Name);
            Assert.True(symbol.MemberFound);
            Assert.Equal("obj1.obj", symbol.MemberName);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffArchive_Parses_SecondLinkerMember_SymbolReferences()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, BuildArchiveWithSecondLinkerMember());
            PECOFF pe = new PECOFF(path);

            Assert.NotNull(pe.CoffArchive);
            Assert.NotNull(pe.CoffArchive.SymbolTable);
            Assert.Equal("SecondLinkerMember", pe.CoffArchive.SymbolTable.Format);
            Assert.Equal(1, pe.CoffArchive.SymbolTable.SymbolCount);

            CoffArchiveSymbolReferenceInfo symbol = Assert.Single(pe.CoffArchive.SymbolTable.References);
            Assert.Equal("beta", symbol.Name);
            Assert.True(symbol.MemberFound);
            Assert.Equal("obj2.obj", symbol.MemberName);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CoffArchive_Reports_SpecViolation_For_ImportObjectReservedFlags()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, BuildArchiveWithReservedImportFlags());
            PECOFF pe = new PECOFF(path);

            CoffArchiveMemberInfo member = Assert.Single(pe.CoffArchive.Members);
            Assert.True(member.IsImportObject);
            Assert.NotNull(member.ImportObject);
            Assert.True(member.ImportObject.HasReservedFlags);
            Assert.Equal((ushort)0x0020, member.ImportObject.ReservedFlags);
            Assert.Contains(pe.ParseResult.Warnings, warning => warning.Contains("SPEC violation: COFF import object reserved flag bits", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildArchiveWithFirstLinkerMember()
    {
        byte[] symbolName = Encoding.ASCII.GetBytes("alpha\0");
        int linkerDataLength = 4 + 4 + symbolName.Length;
        uint memberHeaderOffset = (uint)(8 + 60 + linkerDataLength + ((linkerDataLength & 1) == 1 ? 1 : 0));

        byte[] linker = new byte[linkerDataLength];
        WriteUInt32BigEndian(linker, 0, 1);
        WriteUInt32BigEndian(linker, 4, memberHeaderOffset);
        Array.Copy(symbolName, 0, linker, 8, symbolName.Length);

        using MemoryStream ms = new MemoryStream();
        WriteAscii(ms, "!<arch>\n");
        WriteMember(ms, "/", linker);
        WriteMember(ms, "obj1.obj", new byte[] { 0xAA, 0xBB });
        return ms.ToArray();
    }

    private static byte[] BuildArchiveWithSecondLinkerMember()
    {
        byte[] symbolName = Encoding.ASCII.GetBytes("beta\0");
        int linkerDataLength = 4 + 4 + 4 + 2 + symbolName.Length;
        uint memberHeaderOffset = (uint)(8 + 60 + linkerDataLength + ((linkerDataLength & 1) == 1 ? 1 : 0));

        byte[] linker = new byte[linkerDataLength];
        WriteUInt32BigEndian(linker, 0, 1);  // number of members
        WriteUInt32BigEndian(linker, 4, memberHeaderOffset); // member offsets
        WriteUInt32BigEndian(linker, 8, 1);  // number of symbols
        WriteUInt16BigEndian(linker, 12, 1); // 1-based member index
        Array.Copy(symbolName, 0, linker, 14, symbolName.Length);

        using MemoryStream ms = new MemoryStream();
        WriteAscii(ms, "!<arch>\n");
        WriteMember(ms, "/", linker);
        WriteMember(ms, "obj2.obj", new byte[] { 0xCC, 0xDD, 0xEE });
        return ms.ToArray();
    }

    private static byte[] BuildArchiveWithReservedImportFlags()
    {
        byte[] importObject = BuildImportObjectWithReservedFlags();
        using MemoryStream ms = new MemoryStream();
        WriteAscii(ms, "!<arch>\n");
        WriteMember(ms, "imp.obj", importObject);
        return ms.ToArray();
    }

    private static byte[] BuildImportObjectWithReservedFlags()
    {
        byte[] data = new byte[20 + 9 + 1 + 9 + 1];
        WriteUInt16(data, 0, 0);
        WriteUInt16(data, 2, 0xFFFF);
        WriteUInt16(data, 4, 0);
        WriteUInt16(data, 6, 0x8664);
        WriteUInt32(data, 8, 0);
        WriteUInt32(data, 12, 0);
        WriteUInt16(data, 16, 1);
        WriteUInt16(data, 18, 0x0024); // nameType=1 plus reserved bit 0x20

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

    private static void WriteUInt16BigEndian(byte[] buffer, int offset, ushort value)
    {
        buffer[offset] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 1] = (byte)(value & 0xFF);
    }

    private static void WriteUInt32BigEndian(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)((value >> 24) & 0xFF);
        buffer[offset + 1] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 3] = (byte)(value & 0xFF);
    }

    private static int WriteAsciiZ(byte[] buffer, int offset, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value ?? string.Empty);
        Array.Copy(bytes, 0, buffer, offset, bytes.Length);
        buffer[offset + bytes.Length] = 0;
        return bytes.Length + 1;
    }
}
