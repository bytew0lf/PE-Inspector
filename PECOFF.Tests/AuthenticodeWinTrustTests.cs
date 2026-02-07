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

        string? testFilesDir = FindTestFilesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(testFilesDir));

        string path = Path.Combine(testFilesDir!, "notepad.exe");
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

    private static string? FindTestFilesDirectory()
    {
        string? dir = AppContext.BaseDirectory;
        for (int i = 0; i < 6 && dir != null; i++)
        {
            string candidate = Path.Combine(dir, "testfiles");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
            dir = Directory.GetParent(dir)?.FullName;
        }

        return null;
    }
}
