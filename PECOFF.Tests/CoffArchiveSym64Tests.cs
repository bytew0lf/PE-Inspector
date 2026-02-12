using System;
using System.Globalization;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffArchiveSym64Tests
{
    [Fact]
    public void CoffArchive_Parses_Sym64_Table()
    {
        byte[] data = BuildArchive();
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF pe = new PECOFF(path);

            Assert.Equal("COFF-Archive", pe.ImageKind);
            Assert.NotNull(pe.CoffArchive);
            Assert.NotNull(pe.CoffArchive.SymbolTable);
            Assert.Single(pe.CoffArchive.SymbolTables);
            Assert.True(pe.CoffArchive.SymbolTable.Is64Bit);
            Assert.False(pe.CoffArchive.SymbolTable.IsTruncated);
            Assert.Equal(1, pe.CoffArchive.SymbolTable.SymbolCount);
            Assert.Equal(4, pe.CoffArchive.SymbolTable.NameTableSize);
            Assert.Equal("FirstLinkerMember64", pe.CoffArchive.SymbolTable.Format);
            CoffArchiveSymbolReferenceInfo symbol = Assert.Single(pe.CoffArchive.SymbolTable.References);
            Assert.Equal("sym", symbol.Name);
            Assert.True(symbol.MemberFound);
            Assert.Equal("mod.obj", symbol.MemberName);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildArchive()
    {
        using MemoryStream ms = new MemoryStream();
        WriteAscii(ms, "!<arch>\n");

        byte[] symData = BuildSym64Table(GetNextMemberHeaderOffset(symTableDataLength: 20));
        WriteMember(ms, "/SYM64", symData);
        WriteMember(ms, "mod.obj", new byte[] { 0x01, 0x02, 0x03, 0x04 });
        return ms.ToArray();
    }

    private static long GetNextMemberHeaderOffset(int symTableDataLength)
    {
        long offset = 8 + 60 + symTableDataLength;
        if ((symTableDataLength & 1) == 1)
        {
            offset++;
        }

        return offset;
    }

    private static byte[] BuildSym64Table(long memberHeaderOffset)
    {
        byte[] data = new byte[8 + 8 + 4];
        WriteUInt64BigEndian(data, 0, 1);
        WriteUInt64BigEndian(data, 8, (ulong)memberHeaderOffset);
        Encoding.ASCII.GetBytes("sym\0").CopyTo(data, 16);
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

    private static void WriteUInt64BigEndian(byte[] buffer, int offset, ulong value)
    {
        buffer[offset] = (byte)((value >> 56) & 0xFF);
        buffer[offset + 1] = (byte)((value >> 48) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 40) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 32) & 0xFF);
        buffer[offset + 4] = (byte)((value >> 24) & 0xFF);
        buffer[offset + 5] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 6] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 7] = (byte)(value & 0xFF);
    }
}
