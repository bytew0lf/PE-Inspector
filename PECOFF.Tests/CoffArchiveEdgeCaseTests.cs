using System;
using System.Globalization;
using System.IO;
using System.Text;
using PECoff;
using Xunit;

public class CoffArchiveEdgeCaseTests
{
    [Fact]
    public void CoffArchive_Parses_GnuExtendedName()
    {
        byte[] data = BuildArchiveWithExtendedName("longfilename.obj", new byte[] { 0x01, 0x02, 0x03 });
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, data);
            PECOFF pe = new PECOFF(path);

            Assert.Equal("COFF-Archive", pe.ImageKind);
            Assert.NotNull(pe.CoffArchive);
            Assert.Single(pe.CoffArchive.Members);
            Assert.Equal("longfilename.obj", pe.CoffArchive.Members[0].Name);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildArchiveWithExtendedName(string name, byte[] payload)
    {
        string signature = "!<arch>\n";
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        int dataSize = nameBytes.Length + payload.Length;

        string nameField = ("#1/" + nameBytes.Length.ToString(CultureInfo.InvariantCulture)).PadRight(16);
        string dateField = "0".PadRight(12);
        string uidField = "0".PadRight(6);
        string gidField = "0".PadRight(6);
        string modeField = "100644".PadRight(8);
        string sizeField = dataSize.ToString(CultureInfo.InvariantCulture).PadRight(10);
        string endField = "`\n";

        using MemoryStream ms = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);
        writer.Write(Encoding.ASCII.GetBytes(signature));
        writer.Write(Encoding.ASCII.GetBytes(nameField));
        writer.Write(Encoding.ASCII.GetBytes(dateField));
        writer.Write(Encoding.ASCII.GetBytes(uidField));
        writer.Write(Encoding.ASCII.GetBytes(gidField));
        writer.Write(Encoding.ASCII.GetBytes(modeField));
        writer.Write(Encoding.ASCII.GetBytes(sizeField));
        writer.Write(Encoding.ASCII.GetBytes(endField));
        writer.Write(nameBytes);
        writer.Write(payload);
        if ((dataSize & 1) == 1)
        {
            writer.Write((byte)'\n');
        }
        writer.Flush();
        return ms.ToArray();
    }
}
