using PECoff;
using Xunit;

public class CoffRelocationTypeTests
{
    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "DIR16")]
    [InlineData((ushort)0x0002, "REL16")]
    [InlineData((ushort)0x0006, "DIR32")]
    [InlineData((ushort)0x0007, "DIR32NB")]
    [InlineData((ushort)0x0009, "SEG12")]
    [InlineData((ushort)0x000A, "SECTION")]
    [InlineData((ushort)0x000B, "SECREL")]
    [InlineData((ushort)0x000C, "TOKEN")]
    [InlineData((ushort)0x000D, "SECREL7")]
    [InlineData((ushort)0x0014, "REL32")]
    public void CoffRelocationTypeName_I386Table_MatchesSpec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x014C, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "ADDR64")]
    [InlineData((ushort)0x0002, "ADDR32")]
    [InlineData((ushort)0x0003, "ADDR32NB")]
    [InlineData((ushort)0x0004, "REL32")]
    [InlineData((ushort)0x0005, "REL32_1")]
    [InlineData((ushort)0x0006, "REL32_2")]
    [InlineData((ushort)0x0007, "REL32_3")]
    [InlineData((ushort)0x0008, "REL32_4")]
    [InlineData((ushort)0x0009, "REL32_5")]
    [InlineData((ushort)0x000A, "SECTION")]
    [InlineData((ushort)0x000B, "SECREL")]
    [InlineData((ushort)0x000C, "SECREL7")]
    [InlineData((ushort)0x000D, "TOKEN")]
    [InlineData((ushort)0x000E, "SREL32")]
    [InlineData((ushort)0x000F, "PAIR")]
    [InlineData((ushort)0x0010, "SSPAN32")]
    public void CoffRelocationTypeName_Amd64Table_MatchesSpec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x8664, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "ADDR32")]
    [InlineData((ushort)0x0002, "ADDR32NB")]
    [InlineData((ushort)0x0003, "BRANCH24")]
    [InlineData((ushort)0x0004, "BRANCH11")]
    [InlineData((ushort)0x000A, "REL32")]
    [InlineData((ushort)0x000E, "SECTION")]
    [InlineData((ushort)0x000F, "SECREL")]
    [InlineData((ushort)0x0010, "ARM_MOV32")]
    [InlineData((ushort)0x0011, "THUMB_MOV32")]
    [InlineData((ushort)0x0012, "THUMB_BRANCH20")]
    [InlineData((ushort)0x0013, "UNUSED")]
    [InlineData((ushort)0x0014, "THUMB_BRANCH24")]
    [InlineData((ushort)0x0015, "THUMB_BLX23")]
    [InlineData((ushort)0x0016, "PAIR")]
    public void CoffRelocationTypeName_ArmTable_MatchesSpec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x01C2, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "ADDR32")]
    [InlineData((ushort)0x0002, "ADDR32NB")]
    [InlineData((ushort)0x0003, "BRANCH26")]
    [InlineData((ushort)0x0004, "PAGEBASE_REL21")]
    [InlineData((ushort)0x0005, "REL21")]
    [InlineData((ushort)0x0006, "PAGEOFFSET_12A")]
    [InlineData((ushort)0x0007, "PAGEOFFSET_12L")]
    [InlineData((ushort)0x0008, "SECREL")]
    [InlineData((ushort)0x0009, "SECREL_LOW12A")]
    [InlineData((ushort)0x000A, "SECREL_HIGH12A")]
    [InlineData((ushort)0x000B, "SECREL_LOW12L")]
    [InlineData((ushort)0x000C, "TOKEN")]
    [InlineData((ushort)0x000D, "SECTION")]
    [InlineData((ushort)0x000E, "ADDR64")]
    [InlineData((ushort)0x000F, "BRANCH19")]
    [InlineData((ushort)0x0010, "BRANCH14")]
    [InlineData((ushort)0x0011, "REL32")]
    public void CoffRelocationTypeName_Arm64Table_MatchesSpec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0xAA64, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "IMM14")]
    [InlineData((ushort)0x0002, "IMM22")]
    [InlineData((ushort)0x0003, "IMM64")]
    [InlineData((ushort)0x0004, "DIR32")]
    [InlineData((ushort)0x0005, "DIR64")]
    [InlineData((ushort)0x0006, "PCREL21B")]
    [InlineData((ushort)0x0007, "PCREL21M")]
    [InlineData((ushort)0x0008, "PCREL21F")]
    [InlineData((ushort)0x0009, "GPREL22")]
    [InlineData((ushort)0x000A, "LTOFF22")]
    [InlineData((ushort)0x000B, "SECTION")]
    [InlineData((ushort)0x000C, "SECREL22")]
    [InlineData((ushort)0x000D, "SECREL64I")]
    [InlineData((ushort)0x000E, "SECREL32")]
    [InlineData((ushort)0x0010, "DIR32NB")]
    [InlineData((ushort)0x0011, "SREL14")]
    [InlineData((ushort)0x0012, "SREL22")]
    [InlineData((ushort)0x0013, "SREL32")]
    [InlineData((ushort)0x0014, "UREL32")]
    [InlineData((ushort)0x0015, "PCREL60X")]
    [InlineData((ushort)0x0016, "PCREL60B")]
    [InlineData((ushort)0x0017, "PCREL60F")]
    [InlineData((ushort)0x0018, "PCREL60I")]
    [InlineData((ushort)0x0019, "PCREL60M")]
    [InlineData((ushort)0x001A, "IMMGPREL64")]
    [InlineData((ushort)0x001B, "TOKEN")]
    [InlineData((ushort)0x001C, "GPREL32")]
    [InlineData((ushort)0x001D, "PCREL21BI")]
    [InlineData((ushort)0x001E, "PCREL22")]
    [InlineData((ushort)0x001F, "ADDEND")]
    public void CoffRelocationTypeName_Ia64Table_MatchesSpec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x0200, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "ADDR64")]
    [InlineData((ushort)0x0002, "ADDR32")]
    [InlineData((ushort)0x0003, "ADDR24")]
    [InlineData((ushort)0x0004, "ADDR16")]
    [InlineData((ushort)0x0005, "ADDR14")]
    [InlineData((ushort)0x0006, "REL24")]
    [InlineData((ushort)0x0007, "REL14")]
    [InlineData((ushort)0x0008, "TOCREL16")]
    [InlineData((ushort)0x0009, "TOCREL14")]
    [InlineData((ushort)0x000A, "ADDR32NB")]
    [InlineData((ushort)0x000B, "SECREL")]
    [InlineData((ushort)0x000C, "SECTION")]
    [InlineData((ushort)0x000D, "ADDR14BRTAKEN")]
    [InlineData((ushort)0x000E, "ADDR14BRNTAKEN")]
    [InlineData((ushort)0x000F, "SECREL16")]
    [InlineData((ushort)0x0010, "REFHI")]
    [InlineData((ushort)0x0011, "REFLO")]
    [InlineData((ushort)0x0012, "PAIR")]
    [InlineData((ushort)0x0013, "SECRELLO")]
    [InlineData((ushort)0x0014, "GPREL")]
    [InlineData((ushort)0x0015, "TOKEN")]
    public void CoffRelocationTypeName_PowerPcTable_MatchesSpec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x01F0, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "REFHALF")]
    [InlineData((ushort)0x0002, "REFWORD")]
    [InlineData((ushort)0x0003, "JMPADDR")]
    [InlineData((ushort)0x0004, "REFHI")]
    [InlineData((ushort)0x0005, "REFLO")]
    [InlineData((ushort)0x0006, "GPREL")]
    [InlineData((ushort)0x0007, "LITERAL")]
    [InlineData((ushort)0x000A, "SECTION")]
    [InlineData((ushort)0x000B, "SECREL")]
    [InlineData((ushort)0x000C, "SECRELLO")]
    [InlineData((ushort)0x000D, "SECRELHI")]
    [InlineData((ushort)0x0010, "JMPADDR16")]
    [InlineData((ushort)0x0022, "REFWORDNB")]
    [InlineData((ushort)0x0025, "PAIR")]
    public void CoffRelocationTypeName_MipsTable_MatchesSpec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x0166, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "DIRECT16")]
    [InlineData((ushort)0x0002, "DIRECT32")]
    [InlineData((ushort)0x0003, "DIRECT8")]
    [InlineData((ushort)0x0004, "DIRECT8_WORD")]
    [InlineData((ushort)0x0005, "DIRECT8_LONG")]
    [InlineData((ushort)0x0006, "DIRECT4")]
    [InlineData((ushort)0x0007, "DIRECT4_WORD")]
    [InlineData((ushort)0x0008, "DIRECT4_LONG")]
    [InlineData((ushort)0x0009, "PCREL8_WORD")]
    [InlineData((ushort)0x000A, "PCREL8_LONG")]
    [InlineData((ushort)0x000B, "PCREL12_WORD")]
    [InlineData((ushort)0x000C, "STARTOF_SECTION")]
    [InlineData((ushort)0x000D, "SIZEOF_SECTION")]
    [InlineData((ushort)0x000E, "SECTION")]
    [InlineData((ushort)0x000F, "SECREL")]
    [InlineData((ushort)0x0010, "DIRECT32_NB")]
    [InlineData((ushort)0x0011, "GPREL4_LONG")]
    [InlineData((ushort)0x0012, "TOKEN")]
    [InlineData((ushort)0x0013, "SHM_PCRELPT")]
    [InlineData((ushort)0x0014, "SHM_REFLO")]
    [InlineData((ushort)0x0015, "SHM_REFHALF")]
    [InlineData((ushort)0x0016, "SHM_RELLO")]
    [InlineData((ushort)0x0017, "SHM_RELHALF")]
    [InlineData((ushort)0x0018, "SHM_PAIR")]
    [InlineData((ushort)0x8000, "SHM_NOMODE")]
    public void CoffRelocationTypeName_ShTable_MatchesSpec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x01A6, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x0000, "ABSOLUTE")]
    [InlineData((ushort)0x0001, "ADDR32")]
    [InlineData((ushort)0x0002, "ADDR32NB")]
    [InlineData((ushort)0x0003, "ADDR24")]
    [InlineData((ushort)0x0004, "GPREL16")]
    [InlineData((ushort)0x0005, "PCREL24")]
    [InlineData((ushort)0x0006, "PCREL16")]
    [InlineData((ushort)0x0007, "PCREL8")]
    [InlineData((ushort)0x0008, "REFHALF")]
    [InlineData((ushort)0x0009, "REFHI")]
    [InlineData((ushort)0x000A, "REFLO")]
    [InlineData((ushort)0x000B, "PAIR")]
    [InlineData((ushort)0x000C, "SECTION")]
    [InlineData((ushort)0x000D, "SECREL")]
    [InlineData((ushort)0x000E, "TOKEN")]
    public void CoffRelocationTypeName_M32RTable_MatchesSpec(ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest((ushort)0x9041, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0xA641, (ushort)0x000E, "ADDR64")] // ARM64EC
    [InlineData((ushort)0x01C2, (ushort)0x0010, "ARM_MOV32")] // THUMB/ARM table
    public void CoffRelocationTypeName_Maps_Additional_Machines(ushort machine, ushort type, string expected)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest(machine, type);
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData((ushort)0x01C2, (ushort)0x0008)] // ARM
    [InlineData((ushort)0x01C2, (ushort)0x000B)] // ARM non-spec legacy
    [InlineData((ushort)0x01C2, (ushort)0x000C)] // ARM non-spec legacy
    [InlineData((ushort)0x01C2, (ushort)0x000D)] // ARM non-spec legacy
    [InlineData((ushort)0x0200, (ushort)0x000F)] // IA64
    [InlineData((ushort)0x0200, (ushort)0x0020)] // IA64
    [InlineData((ushort)0x01F0, (ushort)0x0016)] // PPC
    [InlineData((ushort)0x01F0, (ushort)0x0020)] // PPC
    [InlineData((ushort)0x01A4, (ushort)0x0019)] // SH3E
    [InlineData((ushort)0x01A6, (ushort)0x0019)] // SH4
    [InlineData((ushort)0x9041, (ushort)0x000F)] // M32R
    public void CoffRelocationTypeName_UsesUnknownFallback_ForUndefinedValues(ushort machine, ushort type)
    {
        string name = PECOFF.GetCoffRelocationTypeNameForTest(machine, type);
        Assert.Equal($"TYPE_0x{type:X4}", name);
    }
}
