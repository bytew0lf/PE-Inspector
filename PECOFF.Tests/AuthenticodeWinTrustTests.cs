using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using PECoff;
using Xunit;

public class AuthenticodeWinTrustTests
{
    [Fact]
    public void Authenticode_WinTrust_Checks_When_Enabled()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        string? testFilesDir = TestFilesHelper.TryGetTestFilesDirectory();
        if (string.IsNullOrWhiteSpace(testFilesDir))
        {
            return;
        }

        string path = Path.Combine(testFilesDir, "notepad.exe");
        if (!File.Exists(path))
        {
            return;
        }

        PECOFF parser = new PECOFF(path, new PECOFFOptions
        {
            ComputeAuthenticode = true,
            ParseCertificateSigners = true,
            AuthenticodePolicy = new AuthenticodePolicy
            {
                EnableWinTrustCheck = true
            }
        });

        CertificateEntry? entry = parser.CertificateEntries.FirstOrDefault();
        Assert.NotNull(entry);
        Assert.NotNull(entry.AuthenticodeStatus);
        Assert.NotNull(entry.AuthenticodeStatus.WinTrust);
        Assert.NotEqual("NotSupported", entry.AuthenticodeStatus.WinTrust.Status);
    }

}
