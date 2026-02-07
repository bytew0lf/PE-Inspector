using System;
using System.Text;
using PECoff;
using Xunit;

public class CoffSymbolTests
{
    [Fact]
    public void Coff_Symbols_Parse_StringTable_Names()
    {
        byte[] stringTable = Encoding.UTF8.GetBytes("LongSymbolName\0");

        byte[] symbol1 = new byte[18];
        BitConverter.GetBytes(0u).CopyTo(symbol1, 0);
        BitConverter.GetBytes(4u).CopyTo(symbol1, 4);
        BitConverter.GetBytes(0x1234u).CopyTo(symbol1, 8);
        BitConverter.GetBytes((short)1).CopyTo(symbol1, 12);
        BitConverter.GetBytes((ushort)0x20).CopyTo(symbol1, 14);
        symbol1[16] = 2;
        symbol1[17] = 0;

        byte[] symbol2 = new byte[18];
        Encoding.ASCII.GetBytes("short").CopyTo(symbol2, 0);
        BitConverter.GetBytes(0x5678u).CopyTo(symbol2, 8);
        BitConverter.GetBytes((short)2).CopyTo(symbol2, 12);
        BitConverter.GetBytes((ushort)0x20).CopyTo(symbol2, 14);
        symbol2[16] = 3;
        symbol2[17] = 0;

        byte[] symbolData = new byte[36];
        Array.Copy(symbol1, 0, symbolData, 0, symbol1.Length);
        Array.Copy(symbol2, 0, symbolData, symbol1.Length, symbol2.Length);

        bool parsed = PECOFF.TryParseCoffSymbolTableForTest(
            symbolData,
            stringTable,
            new[] { ".text", ".data" },
            out CoffSymbolInfo[] symbols,
            out CoffStringTableEntry[] stringEntries);

        Assert.True(parsed);
        Assert.Equal(2, symbols.Length);
        Assert.Equal("LongSymbolName", symbols[0].Name);
        Assert.Equal(".text", symbols[0].SectionName);
        Assert.Equal("short", symbols[1].Name);
        Assert.Equal(".data", symbols[1].SectionName);
        Assert.Single(stringEntries);
        Assert.Equal((uint)4, stringEntries[0].Offset);
        Assert.Equal("LongSymbolName", stringEntries[0].Value);
    }
}
