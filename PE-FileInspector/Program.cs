using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using PECoff;

namespace PE_FileInspector
{
    internal static class Program
    {
        private sealed class Options
        {
            public string OutputFileName { get; set; } = string.Empty;
            public string OutputDir { get; set; } = string.Empty;
            public string FilePath { get; set; } = string.Empty;
            public bool? SuppressCssm { get; set; }
        }

        private static int Main(string[] args)
        {
            if (!TryParseArgs(args, out Options? options) || options == null)
            {
                PrintUsage();
                return 1;
            }

            bool suppressCssm = options.SuppressCssm ?? CssmStderrFilter.GetDefaultSuppressSetting();
            IDisposable? suppressor = CssmStderrFilter.TryStart(suppressCssm);
            try
            {
                if (!File.Exists(options.FilePath))
                {
                    Console.Error.WriteLine("Input file does not exist: {0}", options.FilePath);
                    return 1;
                }

                if (string.IsNullOrWhiteSpace(options.OutputDir))
                {
                    Console.Error.WriteLine("Output directory is required.");
                    return 1;
                }

                Directory.CreateDirectory(options.OutputDir);

                string reportFileName = Path.GetFileName(options.OutputFileName);
                if (string.IsNullOrWhiteSpace(reportFileName))
                {
                    Console.Error.WriteLine("Output file name is required.");
                    return 1;
                }

                string reportPath = Path.Combine(options.OutputDir, reportFileName);

                PECOFF pe = new PECOFF(options.FilePath);
                List<string> certPaths = new List<string>();
                List<string> pemPaths = new List<string>();
                CertificateEntry[] entries = pe.CertificateEntries.Length > 0
                    ? pe.CertificateEntries
                    : (pe.HasCertificate && pe.Certificate != null
                        ? new[] { new CertificateEntry(CertificateTypeKind.Unknown, pe.Certificate) }
                        : Array.Empty<CertificateEntry>());

                if (entries.Length > 0)
                {
                    string baseName = Path.GetFileNameWithoutExtension(options.FilePath);
                    if (string.IsNullOrWhiteSpace(baseName))
                    {
                        baseName = "certificate";
                    }

                    for (int i = 0; i < entries.Length; i++)
                    {
                        CertificateEntry entry = entries[i];
                        if (entry.Data.Length == 0)
                        {
                            continue;
                        }

                        string typeToken = CertificateUtilities.GetCertificateTypeToken(entry.Type);
                        string indexToken = (i + 1).ToString(CultureInfo.InvariantCulture);
                        string extension = CertificateUtilities.GetCertificateExtension(entry.Type);
                        string certFileName = baseName + "-" + typeToken + "-" + indexToken + extension;
                        string certPath = GetUniqueFilePath(options.OutputDir, certFileName);
                        File.WriteAllBytes(certPath, entry.Data);
                        certPaths.Add(certPath);

                        string pemLabel = CertificateUtilities.GetPemLabel(entry.Type);
                        string pemFileName = baseName + "-" + typeToken + "-" + indexToken + ".pem";
                        string pemPath = GetUniqueFilePath(options.OutputDir, pemFileName);
                        File.WriteAllText(pemPath, CertificateUtilities.ToPem(pemLabel, entry.Data), Encoding.ASCII);
                        pemPaths.Add(pemPath);
                    }
                }

                string report = BuildReport(options.FilePath, pe, certPaths, pemPaths);
                File.WriteAllText(reportPath, report, Encoding.UTF8);

                Console.WriteLine("Report written to: {0}", reportPath);
                if (certPaths.Count > 0)
                {
                    foreach (string path in certPaths)
                    {
                        Console.WriteLine("Certificate written to: {0}", path);
                    }
                }
                if (pemPaths.Count > 0)
                {
                    foreach (string path in pemPaths)
                    {
                        Console.WriteLine("PEM written to: {0}", path);
                    }
                }

                return 0;
            }
            finally
            {
                suppressor?.Dispose();
            }
        }

        private static string BuildReport(string filePath, PECOFF pe, List<string> certPaths, List<string> pemPaths)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("PE File Inspection Report");
            sb.AppendLine("=========================");
            sb.AppendLine("Generated: " + DateTimeOffset.Now.ToString("u", CultureInfo.InvariantCulture));
            sb.AppendLine();

            FileInfo fi = new FileInfo(filePath);
            sb.AppendLine("File Information:");
            sb.AppendLine("  Full Path: " + filePath);
            sb.AppendLine("  File Name: " + fi.Name);
            sb.AppendLine("  Extension: " + fi.Extension);
            sb.AppendLine("  Directory: " + fi.DirectoryName);
            sb.AppendLine("  Size (bytes): " + fi.Length.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("  SHA256: " + (pe.Hash ?? string.Empty));
            sb.AppendLine();

            sb.AppendLine("Version Information:");
            sb.AppendLine("  Product Version: " + Safe(pe.ProductVersion));
            sb.AppendLine("  File Version: " + Safe(pe.FileVersion));
            sb.AppendLine("  Company Name: " + Safe(pe.CompanyName));
            sb.AppendLine("  File Description: " + Safe(pe.FileDescription));
            sb.AppendLine("  Internal Name: " + Safe(pe.InternalName));
            sb.AppendLine("  Original Filename: " + Safe(pe.OriginalFilename));
            sb.AppendLine("  Product Name: " + Safe(pe.ProductName));
            sb.AppendLine("  Copyright: " + Safe(pe.LegalCopyright));
            sb.AppendLine("  Trademarks: " + Safe(pe.LegalTrademarks));
            sb.AppendLine("  Language: " + Safe(pe.Language));
            sb.AppendLine("  Comments: " + Safe(pe.Comments));
            sb.AppendLine("  Private Build: " + Safe(pe.PrivateBuild));
            sb.AppendLine("  Special Build: " + Safe(pe.SpecialBuild));
            sb.AppendLine();

            sb.AppendLine("PE Analysis:");
            sb.AppendLine("  Is .NET File: " + pe.IsDotNetFile);
            sb.AppendLine("  Is Obfuscated: " + pe.IsObfuscated);
            sb.AppendLine("  Obfuscation Percentage: " + pe.ObfuscationPercentage.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("  File Alignment: " + pe.FileAlignment.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("  Section Alignment: " + pe.SectionAlignment.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("  Size Of Headers: " + pe.SizeOfHeaders.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("  Optional Header Checksum: 0x" + pe.OptionalHeaderChecksum.ToString("X8", CultureInfo.InvariantCulture));
            sb.AppendLine("  Computed Checksum: 0x" + pe.ComputedChecksum.ToString("X8", CultureInfo.InvariantCulture));
            sb.AppendLine("  Checksum Valid: " + pe.IsChecksumValid);
            sb.AppendLine("  TimeDateStamp (raw): 0x" + pe.TimeDateStamp.ToString("X8", CultureInfo.InvariantCulture));
            sb.AppendLine("  TimeDateStamp (UTC): " + (pe.TimeDateStampUtc?.ToString("u", CultureInfo.InvariantCulture) ?? string.Empty));
            sb.AppendLine("  Has Certificate: " + pe.HasCertificate);
            sb.AppendLine("  Certificate Count: " + certPaths.Count.ToString(CultureInfo.InvariantCulture));
            if (certPaths.Count == 0)
            {
                sb.AppendLine("  Certificate Paths (Raw): (none)");
            }
            else
            {
                sb.AppendLine("  Certificate Paths (Raw):");
                foreach (string path in certPaths)
                {
                    sb.AppendLine("    - " + path);
                }
            }
            if (pemPaths.Count == 0)
            {
                sb.AppendLine("  Certificate Paths (PEM): (none)");
            }
            else
            {
                sb.AppendLine("  Certificate Paths (PEM):");
                foreach (string path in pemPaths)
                {
                    sb.AppendLine("    - " + path);
                }
            }
            sb.AppendLine();

            sb.AppendLine("Certificate Signer Information:");
            CertificateEntry[] certEntries = pe.CertificateEntries;
            if (certEntries.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                for (int i = 0; i < certEntries.Length; i++)
                {
                    CertificateEntry entry = certEntries[i];
                    string typeToken = CertificateUtilities.GetCertificateTypeToken(entry.Type);
                    sb.AppendLine("  Entry " + (i + 1).ToString(CultureInfo.InvariantCulture) +
                                  " (" + typeToken + ", " + entry.Data.Length.ToString(CultureInfo.InvariantCulture) + " bytes)");

                    if (entry.Pkcs7SignerInfos == null || entry.Pkcs7SignerInfos.Length == 0)
                    {
                        if (!string.IsNullOrWhiteSpace(entry.Pkcs7Error))
                        {
                            sb.AppendLine("    PKCS7 Error: " + entry.Pkcs7Error);
                        }
                        else
                        {
                            sb.AppendLine("    (no PKCS7 signer info)");
                        }
                        continue;
                    }

                    foreach (Pkcs7SignerInfo signer in entry.Pkcs7SignerInfos)
                    {
                        sb.AppendLine("    - Subject: " + Safe(signer.Subject));
                        sb.AppendLine("      Issuer: " + Safe(signer.Issuer));
                        sb.AppendLine("      Serial: " + Safe(signer.SerialNumber));
                        sb.AppendLine("      Thumbprint: " + Safe(signer.Thumbprint));
                        sb.AppendLine("      Digest: " + Safe(signer.DigestAlgorithm));
                        sb.AppendLine("      Signature: " + Safe(signer.SignatureAlgorithm));
                        sb.AppendLine("      Signer ID Type: " + Safe(signer.SignerIdentifierType));
                        sb.AppendLine("      Signing Time: " + (signer.SigningTime?.ToString("u", CultureInfo.InvariantCulture) ?? string.Empty));
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Parse Status:");
            sb.AppendLine("  Success: " + pe.ParseResult.IsSuccess);
            if (pe.ParseResult.Errors.Count > 0)
            {
                sb.AppendLine("  Errors:");
                foreach (string error in pe.ParseResult.Errors)
                {
                    sb.AppendLine("    - " + error);
                }
            }
            if (pe.ParseResult.Warnings.Count > 0)
            {
                sb.AppendLine("  Warnings:");
                foreach (string warning in pe.ParseResult.Warnings)
                {
                    sb.AppendLine("    - " + warning);
                }
            }
            sb.AppendLine();

            sb.AppendLine("CLR / .NET Metadata:");
            if (pe.ClrMetadata == null)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                sb.AppendLine("  Runtime Version: " + pe.ClrMetadata.MajorRuntimeVersion + "." + pe.ClrMetadata.MinorRuntimeVersion);
                sb.AppendLine("  Metadata Version: " + Safe(pe.ClrMetadata.MetadataVersion));
                sb.AppendLine("  Flags: 0x" + pe.ClrMetadata.Flags.ToString("X8", CultureInfo.InvariantCulture));
                sb.AppendLine("  EntryPoint Token: 0x" + pe.ClrMetadata.EntryPointToken.ToString("X8", CultureInfo.InvariantCulture));
                if (pe.ClrMetadata.Streams.Length == 0)
                {
                    sb.AppendLine("  Streams: (none)");
                }
                else
                {
                    sb.AppendLine("  Streams:");
                    foreach (ClrStreamInfo stream in pe.ClrMetadata.Streams)
                    {
                        sb.AppendLine("    - " + stream.Name + " (Offset: " + stream.Offset.ToString(CultureInfo.InvariantCulture) + ", Size: " + stream.Size.ToString(CultureInfo.InvariantCulture) + ")");
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Assembly References:");
            if (!pe.IsDotNetFile)
            {
                sb.AppendLine("  (not a .NET assembly)");
            }
            else if (pe.AssemblyReferenceInfos.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (AssemblyReferenceInfo reference in pe.AssemblyReferenceInfos)
                {
                    sb.AppendLine("  - " + reference.Name + " " + reference.Version);
                }
            }
            sb.AppendLine();

            sb.AppendLine("Imports:");
            if (pe.Imports.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (string import in pe.Imports)
                {
                    sb.AppendLine("  - " + import);
                }
            }
            sb.AppendLine();

            sb.AppendLine("Import Details:");
            if (pe.ImportEntries.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                var importGroups = pe.ImportEntries
                    .GroupBy(entry => entry.DllName, StringComparer.OrdinalIgnoreCase)
                    .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase);

                foreach (var group in importGroups)
                {
                    sb.AppendLine("  DLL: " + group.Key + " (" + group.Count().ToString(CultureInfo.InvariantCulture) + ")");
                    foreach (ImportEntry entry in group.OrderBy(e => e.IsByOrdinal).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        if (entry.IsByOrdinal)
                        {
                            sb.AppendLine("    - Ordinal: " + entry.Ordinal.ToString(CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.AppendLine("    - Hint: " + entry.Hint.ToString(CultureInfo.InvariantCulture) + ", Name: " + Safe(entry.Name));
                        }
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Delay Import Details:");
            if (pe.DelayImportEntries.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                var delayGroups = pe.DelayImportEntries
                    .GroupBy(entry => entry.DllName, StringComparer.OrdinalIgnoreCase)
                    .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase);

                foreach (var group in delayGroups)
                {
                    sb.AppendLine("  DLL: " + group.Key + " (" + group.Count().ToString(CultureInfo.InvariantCulture) + ")");
                    foreach (ImportEntry entry in group.OrderBy(e => e.IsByOrdinal).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        if (entry.IsByOrdinal)
                        {
                            sb.AppendLine("    - Ordinal: " + entry.Ordinal.ToString(CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.AppendLine("    - Hint: " + entry.Hint.ToString(CultureInfo.InvariantCulture) + ", Name: " + Safe(entry.Name));
                        }
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Exports:");
            if (pe.Exports.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (string exportName in pe.Exports)
                {
                    sb.AppendLine("  - " + exportName);
                }
            }
            sb.AppendLine();

            sb.AppendLine("Export Details:");
            if (pe.ExportEntries.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ExportEntry entry in pe.ExportEntries.OrderBy(e => e.Ordinal))
                {
                    string name = string.IsNullOrWhiteSpace(entry.Name) ? "(ordinal-only)" : entry.Name;
                    sb.AppendLine("  - Ordinal: " + entry.Ordinal.ToString(CultureInfo.InvariantCulture) +
                                  ", Name: " + name +
                                  ", AddressRVA: 0x" + entry.AddressRva.ToString("X8", CultureInfo.InvariantCulture));
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resources:");
            ResourceEntry[] resources = pe.Resources;
            if (resources.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                sb.AppendLine("  Total: " + resources.Length.ToString(CultureInfo.InvariantCulture));
                var grouped = resources
                    .GroupBy(r => string.IsNullOrWhiteSpace(r.TypeName) ? "Type#" + r.TypeId.ToString(CultureInfo.InvariantCulture) : r.TypeName)
                    .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase);

                foreach (var group in grouped)
                {
                    sb.AppendLine("  Type: " + group.Key + " (" + group.Count().ToString(CultureInfo.InvariantCulture) + ")");
                    foreach (ResourceEntry entry in group.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
                                                         .ThenBy(r => r.NameId)
                                                         .ThenBy(r => r.LanguageId))
                    {
                        string namePart = !string.IsNullOrWhiteSpace(entry.Name)
                            ? entry.Name
                            : "Id#" + entry.NameId.ToString(CultureInfo.InvariantCulture);

                        string codePage = entry.CodePage == 0
                            ? "n/a"
                            : "0x" + entry.CodePage.ToString("X4", CultureInfo.InvariantCulture);

                        string fileOffset = entry.FileOffset >= 0
                            ? "0x" + entry.FileOffset.ToString("X", CultureInfo.InvariantCulture)
                            : "n/a";

                        sb.AppendLine("    - " + namePart +
                                      " | Lang: 0x" + entry.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                      " | CodePage: " + codePage +
                                      " | Size: " + entry.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | DataRVA: 0x" + entry.DataRva.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | FileOffset: " + fileOffset);
                    }
                }
            }

            return sb.ToString();
        }

        private static string Safe(string? value)
        {
            return value ?? string.Empty;
        }

        private static bool TryParseArgs(string[] args, out Options? options)
        {
            options = null;
            if (args == null || args.Length == 0)
            {
                return false;
            }

            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (!arg.StartsWith("--", StringComparison.Ordinal))
                {
                    return false;
                }

                if (i + 1 >= args.Length)
                {
                    return false;
                }

                string key = arg.Substring(2);
                string value = args[i + 1];
                values[key] = value;
                i++;
            }

            if (!values.TryGetValue("output", out string? output) ||
                !values.TryGetValue("output-dir", out string? outputDir) ||
                !values.TryGetValue("file", out string? file))
            {
                return false;
            }

            bool? suppressCssm = null;
            if (values.TryGetValue("suppress-cssm", out string? suppressValue))
            {
                if (!TryParseBool(suppressValue, out bool suppressParsed))
                {
                    return false;
                }

                suppressCssm = suppressParsed;
            }

            options = new Options
            {
                OutputFileName = output,
                OutputDir = outputDir,
                FilePath = file,
                SuppressCssm = suppressCssm
            };

            return true;
        }

        private static bool TryParseBool(string value, out bool result)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                result = false;
                return false;
            }

            if (bool.TryParse(value, out result))
            {
                return true;
            }

            if (string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "y", StringComparison.OrdinalIgnoreCase))
            {
                result = true;
                return true;
            }

            if (string.Equals(value, "0", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "no", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(value, "n", StringComparison.OrdinalIgnoreCase))
            {
                result = false;
                return true;
            }

            result = false;
            return false;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  PE-FileInspector --output report.txt --output-dir <output-path> --file <file-to-analyze> [--suppress-cssm <true|false>]");
        }

        private static string GetUniqueFilePath(string directory, string fileName)
        {
            string baseName = Path.GetFileNameWithoutExtension(fileName);
            string extension = Path.GetExtension(fileName);
            string candidate = Path.Combine(directory, baseName + extension);
            int counter = 1;
            while (File.Exists(candidate))
            {
                candidate = Path.Combine(directory, baseName + "-" + counter.ToString(CultureInfo.InvariantCulture) + extension);
                counter++;
            }

            return candidate;
        }

        private static class CssmStderrFilter
        {
            private const string MessageToken = "CSSM_ModuleLoad()";

            public static bool GetDefaultSuppressSetting()
            {
                string? suppress = Environment.GetEnvironmentVariable("PE_INSPECTOR_SUPPRESS_CSSM");
                if (string.Equals(suppress, "0", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                return true;
            }

            public static IDisposable? TryStart(bool suppress)
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    return null;
                }

                if (!suppress)
                {
                    return null;
                }

                return StderrPipeFilter.TryCreate(MessageToken);
            }

            private sealed class StderrPipeFilter : IDisposable
            {
                private readonly int _savedFd;
                private readonly int _pipeRead;
                private readonly Thread _thread;
                private bool _disposed;

                private StderrPipeFilter(int savedFd, int pipeRead, Thread thread)
                {
                    _savedFd = savedFd;
                    _pipeRead = pipeRead;
                    _thread = thread;
                }

                public static StderrPipeFilter? TryCreate(string filterToken)
                {
                    int[] fds = new int[2];
                    if (pipe(fds) != 0)
                    {
                        return null;
                    }

                    int pipeRead = fds[0];
                    int pipeWrite = fds[1];

                    int saved = dup(2);
                    if (saved == -1)
                    {
                        close(pipeRead);
                        close(pipeWrite);
                        return null;
                    }

                    if (dup2(pipeWrite, 2) == -1)
                    {
                        close(saved);
                        close(pipeRead);
                        close(pipeWrite);
                        return null;
                    }

                    close(pipeWrite);

                    Thread thread = new Thread(() => FilterLoop(pipeRead, saved, filterToken))
                    {
                        IsBackground = true,
                        Name = "cssm-stderr-filter"
                    };
                    thread.Start();

                    return new StderrPipeFilter(saved, pipeRead, thread);
                }

                public void Dispose()
                {
                    if (_disposed)
                    {
                        return;
                    }

                    _disposed = true;
                    dup2(_savedFd, 2);
                    close(_savedFd);
                    close(_pipeRead);
                }

                private static void FilterLoop(int readFd, int writeFd, string filterToken)
                {
                    byte[] buffer = new byte[256];
                    StringBuilder lineBuffer = new StringBuilder();
                    while (true)
                    {
                        int read = read_bytes(readFd, buffer, buffer.Length);
                        if (read <= 0)
                        {
                            break;
                        }

                        string chunk = Encoding.UTF8.GetString(buffer, 0, read);
                        foreach (char ch in chunk)
                        {
                            if (ch == '\n')
                            {
                                WriteLineIfAllowed(writeFd, lineBuffer, filterToken);
                                lineBuffer.Clear();
                            }
                            else
                            {
                                lineBuffer.Append(ch);
                            }
                        }
                    }

                    if (lineBuffer.Length > 0)
                    {
                        WriteLineIfAllowed(writeFd, lineBuffer, filterToken);
                    }
                }

                private static void WriteLineIfAllowed(int writeFd, StringBuilder line, string filterToken)
                {
                    string text = line.ToString();
                    if (text.Contains(filterToken, StringComparison.Ordinal))
                    {
                        return;
                    }

                    byte[] data = Encoding.UTF8.GetBytes(text + "\n");
                    write_bytes(writeFd, data, data.Length);
                }

                [DllImport("libc")]
                private static extern int pipe(int[] fds);

                [DllImport("libc")]
                private static extern int dup(int oldfd);

                [DllImport("libc")]
                private static extern int dup2(int oldfd, int newfd);

                [DllImport("libc")]
                private static extern int close(int fd);

                [DllImport("libc", EntryPoint = "read")]
                private static extern int read_bytes(int fd, byte[] buffer, int count);

                [DllImport("libc", EntryPoint = "write")]
                private static extern int write_bytes(int fd, byte[] buffer, int count);
            }
        }
    }
}
