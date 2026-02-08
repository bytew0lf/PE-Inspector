using System.IO;
using PECoff;
using Xunit;

public class CoffSymbolSemanticsTests
{
    [Theory]
    [InlineData((byte)0x02, "EXTERNAL")]
    [InlineData((byte)0x03, "STATIC")]
    [InlineData((byte)0x67, "FILE")]
    [InlineData((byte)0x69, "WEAK_EXTERNAL")]
    public void CoffStorageClassName_Maps(byte storageClass, string expected)
    {
        string name = PECOFF.GetCoffStorageClassNameForTest(storageClass);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((short)0, (byte)0x02, "Undefined")]
    [InlineData((short)-1, (byte)0x02, "Absolute")]
    [InlineData((short)-2, (byte)0x02, "Debug")]
    [InlineData((short)1, (byte)0x02, "External")]
    [InlineData((short)1, (byte)0x03, "Static")]
    [InlineData((short)1, (byte)0x69, "WeakExternal")]
    public void CoffSymbolScope_Resolves(short sectionNumber, byte storageClass, string expected)
    {
        string scope = PECOFF.GetCoffSymbolScopeNameForTest(sectionNumber, storageClass);
        Assert.Equal(expected, scope);
    }

    [Fact]
    public void CoffAuxSectionDefinition_Invalid_Comdat_Selection_Is_Flagged()
    {
        byte[] aux = new byte[18];
        using (MemoryStream stream = new MemoryStream(aux))
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(0u); // length
            writer.Write((ushort)0); // relocations
            writer.Write((ushort)0); // line numbers
            writer.Write(0u); // checksum
            writer.Write((ushort)1); // section number
            writer.Write((byte)9); // selection
        }

        CoffAuxSymbolInfo[] auxSymbols = PECOFF.DecodeCoffAuxSymbolsForTest(".text", 0, 0x03, 1, aux);
        Assert.Single(auxSymbols);
        CoffAuxSymbolInfo info = auxSymbols[0];
        Assert.True(info.IsComdat);
        Assert.False(info.ComdatSelectionValid);
    }
}
