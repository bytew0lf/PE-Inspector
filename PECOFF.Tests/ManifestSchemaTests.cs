using PECoff;
using Xunit;

public class ManifestSchemaTests
{
    [Fact]
    public void ManifestSchema_Parses_ExecutionLevel_And_Dpi()
    {
        string xml = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" +
                     "<assemblyIdentity name=\"Test\" version=\"1.0.0.0\" processorArchitecture=\"x64\" type=\"win32\" language=\"de-DE\" />" +
                     "<trustInfo><security><requestedPrivileges>" +
                     "<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" +
                     "</requestedPrivileges></security></trustInfo>" +
                     "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>" +
                     "<dpiAware>true</dpiAware><dpiAwareness>PerMonitorV2</dpiAwareness><uiLanguage>en-US</uiLanguage>" +
                     "</windowsSettings></application>" +
                     "</assembly>";

        Assert.True(PECOFF.TryParseManifestSchemaForTest(xml, out ManifestSchemaInfo schema));
        Assert.Equal("requireAdministrator", schema.RequestedExecutionLevel);
        Assert.Equal("false", schema.UiAccess);
        Assert.Equal("true", schema.DpiAware);
        Assert.Equal("PerMonitorV2", schema.DpiAwareness);
        Assert.Equal("en-US", schema.UiLanguage);
        Assert.Equal("de-DE", schema.AssemblyIdentityLanguage);
    }
}
