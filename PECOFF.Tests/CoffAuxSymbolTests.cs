using System.IO;
using PECoff;
using Xunit;

public class CoffAuxSymbolTests
{
    [Fact]
    public void CoffAuxSymbol_ClrToken_Decodes()
    {
        const uint token = 0x02000001;
        byte[] data = new byte[18];
        using (MemoryStream stream = new MemoryStream(data))
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(token);
        }

        CoffAuxSymbolInfo[] aux = PECOFF.DecodeCoffAuxSymbolsForTest("CLR", 0, 0x6B, 1, data);
        Assert.Single(aux);
        Assert.Equal("ClrToken", aux[0].Kind);
        Assert.Equal(token, aux[0].TagIndex);
    }
}
