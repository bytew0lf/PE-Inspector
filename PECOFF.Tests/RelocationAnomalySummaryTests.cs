using PECoff;
using Xunit;

public class RelocationAnomalySummaryTests
{
    [Fact]
    public void RelocationAnomalySummary_Aggregates_Block_Counts()
    {
        BaseRelocationBlockInfo[] blocks = new[]
        {
            new BaseRelocationBlockInfo(0x1000, 12, 2, new int[16], 1, 2, 3, true),
            new BaseRelocationBlockInfo(0x2000, 12, 1, new int[16], 4, 5, 6, true)
        };

        RelocationAnomalySummary summary = PECOFF.BuildRelocationAnomalySummaryForTest(
            blocks,
            zeroSizedBlocks: 1,
            emptyBlocks: 2,
            invalidBlocks: 3,
            orphanedBlocks: 4,
            discardableBlocks: 5);

        Assert.Equal(1, summary.ZeroSizedBlockCount);
        Assert.Equal(2, summary.EmptyBlockCount);
        Assert.Equal(3, summary.InvalidBlockCount);
        Assert.Equal(4, summary.OrphanedBlockCount);
        Assert.Equal(5, summary.DiscardableBlockCount);
        Assert.Equal(5, summary.ReservedTypeCount);
        Assert.Equal(7, summary.OutOfRangeEntryCount);
        Assert.Equal(9, summary.UnmappedEntryCount);
    }
}
