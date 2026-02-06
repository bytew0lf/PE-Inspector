using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Serialization;
using PECoff;
using Xunit;

public class ImportDescriptorTests
{
    [Fact]
    public void BuildImportDescriptorInfos_Reports_Mismatch_And_Stale_Bound()
    {
#pragma warning disable SYSLIB0050
        PECOFF parser = (PECOFF)FormatterServices.GetUninitializedObject(typeof(PECOFF));
#pragma warning restore SYSLIB0050

        SetField(parser, "_parseResult", new ParseResult());
        SetField(parser, "_options", new PECOFFOptions());

        List<ImportEntry> importEntries = new List<ImportEntry>
        {
            new ImportEntry("test.dll", "Foo", 0, 0, false, ImportThunkSource.ImportNameTable, 0),
            new ImportEntry("test.dll", "Bar", 0, 0, false, ImportThunkSource.ImportAddressTable, 0)
        };
        SetField(parser, "_importEntries", importEntries);
        SetField(parser, "_importDescriptors", new List<ImportDescriptorInfo>());
        SetField(parser, "_boundImports", new List<BoundImportEntry>
        {
            new BoundImportEntry("test.dll", 2, Array.Empty<BoundForwarderRef>())
        });

        Type? internalType = typeof(PECOFF).GetNestedType("ImportDescriptorInternal", BindingFlags.NonPublic);
        Assert.NotNull(internalType);

        IList internalList = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(internalType!))!;
        object? internalDescriptor = Activator.CreateInstance(
            internalType!,
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance,
            null,
            new object[] { "test.dll", (uint)1, (uint)0x1000, (uint)0x2000 },
            null);
        internalList.Add(internalDescriptor!);
        SetField(parser, "_importDescriptorInternals", internalList);

        InvokeNonPublic(parser, "BuildImportDescriptorInfos");

        List<ImportDescriptorInfo> descriptors = (List<ImportDescriptorInfo>)GetField(parser, "_importDescriptors");
        Assert.Single(descriptors);
        Assert.True(descriptors[0].IntOnlyFunctions.Count > 0);
        Assert.True(descriptors[0].IatOnlyFunctions.Count > 0);
        Assert.True(descriptors[0].IsBoundStale);

        Assert.Contains(parser.ParseResult.Warnings, w => w.Contains("INT/IAT mismatch", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(parser.ParseResult.Warnings, w => w.Contains("stale", StringComparison.OrdinalIgnoreCase));
    }

    private static void SetField(object target, string name, object value)
    {
        FieldInfo? field = target.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        field!.SetValue(target, value);
    }

    private static object GetField(object target, string name)
    {
        FieldInfo? field = target.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        return field!.GetValue(target)!;
    }

    private static void InvokeNonPublic(object target, string methodName)
    {
        MethodInfo? method = target.GetType().GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        method!.Invoke(target, Array.Empty<object>());
    }
}
