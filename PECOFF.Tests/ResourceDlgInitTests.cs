using PECoff;
using Xunit;

public class ResourceDlgInitTests
{
    [Fact]
    public void DlgInit_Parses_Entries()
    {
        byte[] data = new byte[]
        {
            0x64, 0x00, // control id = 100
            0x01, 0x04, // message = 0x0401
            0x04, 0x00, // length = 4
            0x01, 0x02, 0x03, 0x04,
            0x00, 0x00, // terminator
            0x00, 0x00,
            0x00, 0x00
        };

        bool parsed = PECOFF.TryParseDlgInitForTest(data, out ResourceDlgInitEntryInfo[] entries);
        Assert.True(parsed);
        Assert.Single(entries);
        Assert.Equal((ushort)100, entries[0].ControlId);
        Assert.Equal((ushort)0x0401, entries[0].Message);
        Assert.Equal((ushort)4, entries[0].DataLength);
        Assert.Equal("01020304", entries[0].DataPreview);
    }
}
