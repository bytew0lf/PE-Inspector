using System;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using PECoff;
using Xunit;

public class ClrMetadataExtendedTests
{
    [Fact]
    public void ClrMetadata_ModuleRefs_And_Resources_Match_TableCounts()
    {
        string assemblyPath = typeof(PECOFF).Assembly.Location;
        Assert.False(string.IsNullOrWhiteSpace(assemblyPath));

        PECOFF parser = new PECOFF(assemblyPath);
        Assert.True(parser.ParseResult.IsSuccess);
        Assert.NotNull(parser.ClrMetadata);

        ClrMetadataInfo metadata = parser.ClrMetadata;
        MetadataTableCountInfo? moduleRefInfo = GetTableInfo(metadata, TableIndex.ModuleRef);
        MetadataTableCountInfo? resourceInfo = GetTableInfo(metadata, TableIndex.ManifestResource);
        int moduleRefCount = moduleRefInfo?.Count ?? 0;
        int resourceCount = resourceInfo?.Count ?? 0;

        Assert.Equal(moduleRefCount, metadata.ModuleReferences.Length);
        Assert.Equal(resourceCount, metadata.ManagedResources.Length);

        if (metadata.ModuleReferences.Length > 0)
        {
            Assert.All(metadata.ModuleReferences, name => Assert.False(string.IsNullOrWhiteSpace(name)));
        }

        if (metadata.ManagedResources.Length > 0)
        {
            Assert.All(metadata.ManagedResources, info => Assert.False(string.IsNullOrWhiteSpace(info.Name)));
        }

        int customAttributeCount = GetTableCount(metadata, TableIndex.CustomAttribute);
        if (customAttributeCount > 0)
        {
            Assert.True(metadata.AssemblyAttributes.Length > 0 || metadata.ModuleAttributes.Length > 0);
        }

        if (moduleRefInfo != null && moduleRefInfo.Count > 0)
        {
            uint expectedFirst = ((uint)TableIndex.ModuleRef << 24) | 0x00000001;
            uint expectedLast = expectedFirst + (uint)moduleRefInfo.Count - 1;
            Assert.Equal(expectedFirst, moduleRefInfo.FirstToken);
            Assert.Equal(expectedLast, moduleRefInfo.LastToken);
        }
    }

    [Fact]
    public void ClrMetadata_AssemblyReferences_Expose_PublicKeyTokens()
    {
        string assemblyPath = typeof(PECOFF).Assembly.Location;
        Assert.False(string.IsNullOrWhiteSpace(assemblyPath));

        PECOFF parser = new PECOFF(assemblyPath);
        Assert.True(parser.ParseResult.IsSuccess);
        Assert.NotNull(parser.ClrMetadata);

        ClrAssemblyReferenceInfo[] references = parser.ClrMetadata.AssemblyReferences;
        if (references.Length == 0)
        {
            return;
        }

        foreach (ClrAssemblyReferenceInfo reference in references)
        {
            if (string.IsNullOrWhiteSpace(reference.PublicKeyToken))
            {
                continue;
            }

            Assert.True(IsUpperHex(reference.PublicKeyToken));
            Assert.Equal(16, reference.PublicKeyToken.Length);
        }
    }

    [Fact]
    public void ClrMetadata_Validation_Is_Clean_For_Valid_Assembly()
    {
        string assemblyPath = typeof(PECOFF).Assembly.Location;
        Assert.False(string.IsNullOrWhiteSpace(assemblyPath));

        PECOFF parser = new PECOFF(assemblyPath);
        Assert.True(parser.ParseResult.IsSuccess);
        Assert.NotNull(parser.ClrMetadata);

        Assert.True(parser.ClrMetadata.IsValid);
        Assert.Empty(parser.ClrMetadata.ValidationMessages);
    }

    private static int GetTableCount(ClrMetadataInfo metadata, TableIndex table)
    {
        MetadataTableCountInfo? entry = GetTableInfo(metadata, table);
        return entry?.Count ?? 0;
    }

    private static MetadataTableCountInfo? GetTableInfo(ClrMetadataInfo metadata, TableIndex table)
    {
        return metadata.MetadataTableCounts.FirstOrDefault(info => info.TableIndex == (int)table);
    }

    private static bool IsUpperHex(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
            {
                return false;
            }
        }

        return true;
    }
}
