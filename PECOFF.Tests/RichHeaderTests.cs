using System.Linq;
using PECoff;
using Xunit;

public class RichHeaderTests
{
    [Fact]
    public void RichHeader_ToolchainHints_Aggregate()
    {
        RichHeaderEntry[] entries = new[]
        {
            new RichHeaderEntry(0x00C2, 5000, 2, 0, "Linker (14.00)", "5000"),
            new RichHeaderEntry(0x00C8, 5000, 3, 0, "Cvtres (14.00)", "5000"),
            new RichHeaderEntry(0x00E6, 10000, 1, 0, "Linker (10.00)", "10000")
        };

        RichToolchainInfo[] toolchains = PECOFF.BuildRichToolchainHintsForTest(entries);
        RichToolchainInfo toolchain = toolchains.Single(info => info.Version == "14.00");

        Assert.Equal((uint)5, toolchain.TotalCount);
        Assert.Contains("Linker", toolchain.Tools);
        Assert.Contains("Cvtres", toolchain.Tools);
    }

    [Fact]
    public void RichHeader_Decode_Extended_Product_Names()
    {
        string name = PECOFF.DecodeRichProductNameForTest(0x00F6);
        Assert.Contains("Linker", name);
        Assert.Contains("14.00", name);
    }
}
