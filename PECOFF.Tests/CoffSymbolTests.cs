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

    [Fact]
    public void Coff_Symbols_Parse_File_Aux()
    {
        byte[] symbol = new byte[18];
        Encoding.ASCII.GetBytes(".file").CopyTo(symbol, 0);
        BitConverter.GetBytes(0u).CopyTo(symbol, 8);
        BitConverter.GetBytes((short)0).CopyTo(symbol, 12);
        BitConverter.GetBytes((ushort)0).CopyTo(symbol, 14);
        symbol[16] = 0x67; // IMAGE_SYM_CLASS_FILE
        symbol[17] = 1;

        byte[] aux = new byte[18];
        Encoding.ASCII.GetBytes("main.c").CopyTo(aux, 0);

        byte[] symbolData = new byte[36];
        Array.Copy(symbol, 0, symbolData, 0, symbol.Length);
        Array.Copy(aux, 0, symbolData, symbol.Length, aux.Length);

        bool parsed = PECOFF.TryParseCoffSymbolTableForTest(
            symbolData,
            Array.Empty<byte>(),
            Array.Empty<string>(),
            out CoffSymbolInfo[] symbols,
            out CoffStringTableEntry[] stringEntries);

        Assert.True(parsed);
        Assert.Single(symbols);
        Assert.Empty(stringEntries);
        Assert.Single(symbols[0].AuxSymbols);
        Assert.Equal("File", symbols[0].AuxSymbols[0].Kind);
        Assert.Equal("main.c", symbols[0].AuxSymbols[0].FileName);
    }

    [Fact]
    public void Coff_Symbols_Resolve_WeakExtern_Default()
    {
        byte[] baseSymbol = new byte[18];
        Encoding.ASCII.GetBytes("base").CopyTo(baseSymbol, 0);
        BitConverter.GetBytes(0u).CopyTo(baseSymbol, 8);
        BitConverter.GetBytes((short)1).CopyTo(baseSymbol, 12);
        BitConverter.GetBytes((ushort)0).CopyTo(baseSymbol, 14);
        baseSymbol[16] = 2;
        baseSymbol[17] = 0;

        byte[] weakSymbol = new byte[18];
        Encoding.ASCII.GetBytes("weak").CopyTo(weakSymbol, 0);
        BitConverter.GetBytes(0u).CopyTo(weakSymbol, 8);
        BitConverter.GetBytes((short)1).CopyTo(weakSymbol, 12);
        BitConverter.GetBytes((ushort)0).CopyTo(weakSymbol, 14);
        weakSymbol[16] = 0x69;
        weakSymbol[17] = 1;

        byte[] weakAux = new byte[18];
        BitConverter.GetBytes(0u).CopyTo(weakAux, 0); // tag index -> base symbol
        BitConverter.GetBytes(2u).CopyTo(weakAux, 4); // SEARCH_LIBRARY

        byte[] symbolData = new byte[54];
        Array.Copy(baseSymbol, 0, symbolData, 0, baseSymbol.Length);
        Array.Copy(weakSymbol, 0, symbolData, baseSymbol.Length, weakSymbol.Length);
        Array.Copy(weakAux, 0, symbolData, baseSymbol.Length + weakSymbol.Length, weakAux.Length);

        bool parsed = PECOFF.TryParseCoffSymbolTableForTest(
            symbolData,
            Array.Empty<byte>(),
            new[] { ".text" },
            out CoffSymbolInfo[] symbols,
            out CoffStringTableEntry[] _);

        Assert.True(parsed);
        Assert.Equal(2, symbols.Length);
        Assert.Single(symbols[1].AuxSymbols);
        Assert.Equal("WeakExternal", symbols[1].AuxSymbols[0].Kind);
        Assert.Equal("base", symbols[1].AuxSymbols[0].WeakDefaultSymbol);
    }
}
