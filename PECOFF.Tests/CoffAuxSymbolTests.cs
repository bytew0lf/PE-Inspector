using System;
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

    [Fact]
    public void CoffAuxSymbol_File_MultiRecord_Decodes_LongName()
    {
        byte[] data = new byte[36];
        byte[] name = System.Text.Encoding.ASCII.GetBytes("very_long_source_file_name.c");
        Array.Copy(name, 0, data, 0, Math.Min(name.Length, data.Length));

        CoffAuxSymbolInfo[] aux = PECOFF.DecodeCoffAuxSymbolsForTest(".file", 0, 0x67, 2, data);

        Assert.Single(aux);
        Assert.Equal("File", aux[0].Kind);
        Assert.Contains("very_long_source_file_name.c", aux[0].FileName, StringComparison.Ordinal);
    }

    [Fact]
    public void CoffAuxSymbol_FunctionStorage_Decodes_LineInfo()
    {
        byte[] data = new byte[18];
        using (MemoryStream stream = new MemoryStream(data))
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write((ushort)42); // line
            writer.Write((ushort)0); // pad
            writer.Write(0x12345678u); // next function
        }

        CoffAuxSymbolInfo[] aux = PECOFF.DecodeCoffAuxSymbolsForTest("func", 0, 0x14, 1, data);

        Assert.Single(aux);
        Assert.Equal("FunctionLineInfo", aux[0].Kind);
        Assert.Equal((ushort)42, aux[0].FunctionLineNumber);
        Assert.Equal(0x12345678u, aux[0].PointerToNextFunction);
    }

    [Fact]
    public void CoffAuxSymbol_GenericExternal_Decodes_SymbolDefinition()
    {
        byte[] data = new byte[18];
        using (MemoryStream stream = new MemoryStream(data))
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(7u); // tag index
            writer.Write(0x200u); // total size
            writer.Write(0x11111111u); // pointer to line
            writer.Write(0x22222222u); // pointer to next function
            writer.Write((ushort)3); // tv index
        }

        CoffAuxSymbolInfo[] aux = PECOFF.DecodeCoffAuxSymbolsForTest("sym", 0, 0x02, 1, data);

        Assert.Single(aux);
        Assert.Equal("SymbolDefinition", aux[0].Kind);
        Assert.Equal(7u, aux[0].TagIndex);
        Assert.Equal(0x200u, aux[0].TotalSize);
        Assert.Equal(0x11111111u, aux[0].PointerToLineNumber);
        Assert.Equal(0x22222222u, aux[0].PointerToNextFunction);
        Assert.Contains("TvIndex=3", aux[0].ComdatSelectionNote, StringComparison.Ordinal);
    }

    [Fact]
    public void CoffAuxSymbol_SectionStorageClass_Decodes_SectionDefinition()
    {
        byte[] data = new byte[18];
        using (MemoryStream stream = new MemoryStream(data))
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(0x40u); // length
            writer.Write((ushort)2); // relocations
            writer.Write((ushort)1); // line numbers
            writer.Write(0xABCD1234u); // checksum
            writer.Write((ushort)3); // section number
            writer.Write((byte)0); // selection
        }

        CoffAuxSymbolInfo[] aux = PECOFF.DecodeCoffAuxSymbolsForTest(".sec", 0, 0x68, 1, data);

        Assert.Single(aux);
        Assert.Equal("SectionDefinition", aux[0].Kind);
        Assert.Equal(0x40u, aux[0].SectionLength);
        Assert.Equal((ushort)2, aux[0].RelocationCount);
        Assert.Equal((ushort)1, aux[0].LineNumberCount);
    }
}
