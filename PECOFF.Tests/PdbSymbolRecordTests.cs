using System;
using PECoff;
using Xunit;

public class PdbSymbolRecordTests
{
    [Fact]
    public void Pdb_Symbol_Record_Stream_Parses_Common_Types()
    {
        byte[] pub = BuildPub32Record("PublicOne", 0x1234, 0x2);
        byte[] gdata = BuildData32Record(0x110D, "GlobalVar", 0x40, 0x1, 0x1000);
        byte[] lproc = BuildProc32Record(0x1110, "ProcName", 0x200, 0x3, 0x2000);
        byte[] local = BuildLocalRecord("LocalVar", 0x3000);

        byte[] stream = Concat(pub, gdata, lproc, local);

        bool parsed = PECOFF.TryParsePdbSymbolRecordsForTest(stream, out int total, out PdbSymbolRecordInfo[] records, out string note);

        Assert.True(parsed);
        Assert.Equal(4, total);
        Assert.Empty(note);
        Assert.Equal(4, records.Length);
        Assert.Contains(records, r => r.Kind == "Public" && r.Name == "PublicOne");
        Assert.Contains(records, r => r.Kind == "Global" && r.Name == "GlobalVar");
        Assert.Contains(records, r => r.Kind == "Proc" && r.Name == "ProcName");
        Assert.Contains(records, r => r.Kind == "Local" && r.Name == "LocalVar");
    }

    private static byte[] BuildPub32Record(string name, uint offset, ushort segment)
    {
        byte[] nameBytes = BuildAscii(name);
        byte[] data = new byte[10 + nameBytes.Length + 1];
        WriteUInt32(data, 0, 0); // flags
        WriteUInt32(data, 4, offset);
        WriteUInt16(data, 8, segment);
        Array.Copy(nameBytes, 0, data, 10, nameBytes.Length);
        data[data.Length - 1] = 0;
        return BuildRecord(0x110E, data);
    }

    private static byte[] BuildData32Record(ushort recordType, string name, uint offset, ushort segment, uint typeIndex)
    {
        byte[] nameBytes = BuildAscii(name);
        byte[] data = new byte[10 + nameBytes.Length + 1];
        WriteUInt32(data, 0, typeIndex);
        WriteUInt32(data, 4, offset);
        WriteUInt16(data, 8, segment);
        Array.Copy(nameBytes, 0, data, 10, nameBytes.Length);
        data[data.Length - 1] = 0;
        return BuildRecord(recordType, data);
    }

    private static byte[] BuildProc32Record(ushort recordType, string name, uint offset, ushort segment, uint typeIndex)
    {
        byte[] nameBytes = BuildAscii(name);
        byte[] data = new byte[35 + nameBytes.Length + 1];
        WriteUInt32(data, 24, typeIndex);
        WriteUInt32(data, 28, offset);
        WriteUInt16(data, 32, segment);
        data[34] = 0; // flags
        Array.Copy(nameBytes, 0, data, 35, nameBytes.Length);
        data[data.Length - 1] = 0;
        return BuildRecord(recordType, data);
    }

    private static byte[] BuildLocalRecord(string name, uint typeIndex)
    {
        byte[] nameBytes = BuildAscii(name);
        byte[] data = new byte[8 + nameBytes.Length + 1];
        WriteUInt32(data, 0, typeIndex);
        WriteUInt32(data, 4, 0);
        Array.Copy(nameBytes, 0, data, 8, nameBytes.Length);
        data[data.Length - 1] = 0;
        return BuildRecord(0x113E, data);
    }

    private static byte[] BuildRecord(ushort recordType, byte[] data)
    {
        ushort length = (ushort)(data.Length + 2);
        byte[] record = new byte[2 + length];
        WriteUInt16(record, 0, length);
        WriteUInt16(record, 2, recordType);
        Array.Copy(data, 0, record, 4, data.Length);
        return record;
    }

    private static byte[] BuildAscii(string value) => System.Text.Encoding.ASCII.GetBytes(value);

    private static byte[] Concat(params byte[][] buffers)
    {
        int length = 0;
        foreach (byte[] buffer in buffers)
        {
            length += buffer.Length;
        }

        byte[] combined = new byte[length];
        int offset = 0;
        foreach (byte[] buffer in buffers)
        {
            Array.Copy(buffer, 0, combined, offset, buffer.Length);
            offset += buffer.Length;
        }

        return combined;
    }

    private static void WriteUInt16(byte[] buffer, int offset, ushort value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
