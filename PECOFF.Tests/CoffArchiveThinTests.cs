using System;
using System.Globalization;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffArchiveThinTests
{
    [Fact]
    public void CoffArchive_Parses_Thin_Archive_With_External_Member()
    {
        byte[] data = BuildThinArchive();
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF pe = new PECOFF(path);

            Assert.Equal("COFF-Archive", pe.ImageKind);
            Assert.NotNull(pe.CoffArchive);
            Assert.True(pe.CoffArchive.IsThinArchive);
            Assert.Single(pe.CoffArchive.Members);

            CoffArchiveMemberInfo member = pe.CoffArchive.Members[0];
            Assert.Equal("external.obj", member.Name);
            Assert.False(member.DataInArchive);
            Assert.Equal(0x120, member.Size);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildThinArchive()
    {
        using MemoryStream ms = new MemoryStream();
        WriteAscii(ms, "!<thin>\n");

        string name = "external.obj";
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        int payloadSize = 0x120;
        int memberSize = nameBytes.Length + payloadSize;

        string nameField = ("#1/" + nameBytes.Length.ToString(CultureInfo.InvariantCulture)).PadRight(16);
        WriteMemberHeader(ms, nameField, memberSize);
        ms.Write(nameBytes, 0, nameBytes.Length);
        if ((nameBytes.Length & 1) == 1)
        {
            ms.WriteByte((byte)'\n');
        }

        return ms.ToArray();
    }

    private static void WriteMemberHeader(Stream stream, string nameField, int size)
    {
        string header = (nameField ?? string.Empty).PadRight(16).Substring(0, 16) +
                        "0".PadRight(12) +
                        "0".PadRight(6) +
                        "0".PadRight(6) +
                        "0".PadRight(8) +
                        size.ToString(CultureInfo.InvariantCulture).PadRight(10) +
                        "`\n";
        WriteAscii(stream, header);
    }

    private static void WriteAscii(Stream stream, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);
        stream.Write(bytes, 0, bytes.Length);
    }
}
