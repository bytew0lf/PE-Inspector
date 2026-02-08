using PECoff;
using Xunit;

public class ClrMethodBodyParsingTests
{
    [Fact]
    public void MethodBody_Parses_Eh_Clauses()
    {
        byte[] body = BuildMethodBodyWithEh();

        bool parsed = PECOFF.TryParseMethodBodySummaryForTest(body, out ClrMethodBodySummaryInfo summary);

        Assert.True(parsed);
        Assert.NotNull(summary);
        Assert.Equal(1, summary.ExceptionClauseCount);
        Assert.Equal(1, summary.ExceptionClauseCatchCount);
    }

    private static byte[] BuildMethodBodyWithEh()
    {
        byte[] buffer = new byte[32];

        ushort flags = 0x300B; // fat format, more sections, header size 3
        WriteUInt16(buffer, 0, flags);
        WriteUInt16(buffer, 2, 8); // maxStack
        WriteUInt32(buffer, 4, 1); // code size
        WriteUInt32(buffer, 8, 0); // local sig
        buffer[12] = 0x00; // IL: nop

        int sectionOffset = 16;
        buffer[sectionOffset] = 0x01; // EH section, no more sections
        buffer[sectionOffset + 1] = 0x10; // data size
        buffer[sectionOffset + 2] = 0x00;
        buffer[sectionOffset + 3] = 0x00;

        int clauseOffset = sectionOffset + 4;
        WriteUInt16(buffer, clauseOffset, 0); // flags: catch
        WriteUInt16(buffer, clauseOffset + 2, 0); // try offset
        buffer[clauseOffset + 4] = 1; // try length
        WriteUInt16(buffer, clauseOffset + 5, 0); // handler offset
        buffer[clauseOffset + 7] = 1; // handler length
        WriteUInt32(buffer, clauseOffset + 8, 0); // class token

        return buffer;
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
