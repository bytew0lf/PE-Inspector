using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using PECoff;

namespace PE_FileInspector
{
    internal static class Program
    {
        private static IDisposable? _cssmSuppressor;

        [ModuleInitializer]
        internal static void InitializeCssmFilter()
        {
            Environment.SetEnvironmentVariable("OS_ACTIVITY_MODE", "disable");
            bool suppress = CssmStderrFilter.GetDefaultSuppressSetting();
            _cssmSuppressor = CssmStderrFilter.TryStart(suppress);
        }

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
            if (!suppressCssm && _cssmSuppressor != null)
            {
                _cssmSuppressor.Dispose();
                _cssmSuppressor = null;
            }
            else if (suppressCssm && _cssmSuppressor == null)
            {
                _cssmSuppressor = CssmStderrFilter.TryStart(true);
            }
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
                // Filter is kept until process exit to catch late CSSM warnings.
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
            sb.AppendLine("  Import Hash: " + Safe(pe.ImportHash));
            sb.AppendLine("  File Alignment: " + pe.FileAlignment.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("  Section Alignment: " + pe.SectionAlignment.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("  Size Of Headers: " + pe.SizeOfHeaders.ToString(CultureInfo.InvariantCulture));
            if (pe.OverlayInfo != null)
            {
                sb.AppendLine("  Overlay Start: 0x" + pe.OverlayInfo.StartOffset.ToString("X", CultureInfo.InvariantCulture));
                sb.AppendLine("  Overlay Size: " + pe.OverlayInfo.Size.ToString(CultureInfo.InvariantCulture));
            }
            sb.AppendLine("  Optional Header Checksum: 0x" + pe.OptionalHeaderChecksum.ToString("X8", CultureInfo.InvariantCulture));
            sb.AppendLine("  Computed Checksum: 0x" + pe.ComputedChecksum.ToString("X8", CultureInfo.InvariantCulture));
            sb.AppendLine("  Checksum Valid: " + pe.IsChecksumValid);
            if (pe.SubsystemInfo != null)
            {
                sb.AppendLine("  Subsystem: " + pe.SubsystemInfo.Name + " (0x" + pe.SubsystemInfo.Value.ToString("X4", CultureInfo.InvariantCulture) + ")");
                sb.AppendLine("  Subsystem GUI: " + pe.SubsystemInfo.IsGui);
                sb.AppendLine("  Subsystem Console: " + pe.SubsystemInfo.IsConsole);
            }
            if (pe.DllCharacteristicsInfo != null)
            {
                sb.AppendLine("  DllCharacteristics: 0x" + pe.DllCharacteristicsInfo.Value.ToString("X4", CultureInfo.InvariantCulture));
                sb.AppendLine("  NX Compat: " + pe.DllCharacteristicsInfo.NxCompat);
                sb.AppendLine("  ASLR: " + pe.DllCharacteristicsInfo.AslrEnabled);
                bool cfgEnabled = pe.DllCharacteristicsInfo.GuardCf || (pe.LoadConfig != null && pe.LoadConfig.GuardFlags != 0);
                sb.AppendLine("  CFG: " + cfgEnabled);
                sb.AppendLine("  High Entropy VA: " + pe.DllCharacteristicsInfo.HighEntropyVa);
                if (pe.DllCharacteristicsInfo.Flags.Length > 0)
                {
                    sb.AppendLine("  DllCharacteristics Flags:");
                    foreach (string flag in pe.DllCharacteristicsInfo.Flags)
                    {
                        sb.AppendLine("    - " + flag);
                    }
                }
            }
            if (pe.SecurityFeaturesInfo != null)
            {
                sb.AppendLine("  Security Features:");
                sb.AppendLine("    NX Compat: " + pe.SecurityFeaturesInfo.NxCompat);
                sb.AppendLine("    ASLR: " + pe.SecurityFeaturesInfo.AslrEnabled);
                sb.AppendLine("    High Entropy VA: " + pe.SecurityFeaturesInfo.HighEntropyVa);
                sb.AppendLine("    CFG: " + pe.SecurityFeaturesInfo.GuardCf);
                sb.AppendLine("    Security Cookie: " + pe.SecurityFeaturesInfo.HasSecurityCookie);
                sb.AppendLine("    SafeSEH: " + pe.SecurityFeaturesInfo.SafeSeh);
                sb.AppendLine("    NO_SEH: " + pe.SecurityFeaturesInfo.NoSeh);
            }
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

            sb.AppendLine("Section Entropy:");
            if (pe.SectionEntropies.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (SectionEntropyInfo entry in pe.SectionEntropies.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
                {
                    sb.AppendLine("  - " + entry.Name +
                                  " | Size: " + entry.RawSize.ToString(CultureInfo.InvariantCulture) +
                                  " | Entropy: " + entry.Entropy.ToString("F3", CultureInfo.InvariantCulture));
                }
            }
            sb.AppendLine();

            sb.AppendLine("Section Padding:");
            if (pe.SectionSlacks.Length == 0 && pe.SectionGaps.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                if (pe.SectionSlacks.Length > 0)
                {
                    sb.AppendLine("  Trailing Slack:");
                    foreach (SectionSlackInfo slack in pe.SectionSlacks)
                    {
                        sb.AppendLine("    - " + slack.SectionName +
                                      " | Offset: 0x" + slack.FileOffset.ToString("X", CultureInfo.InvariantCulture) +
                                      " | Size: " + slack.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | NonZero: " + slack.NonZeroCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Sampled: " + slack.SampledBytes.ToString(CultureInfo.InvariantCulture));
                    }
                }

                if (pe.SectionGaps.Length > 0)
                {
                    sb.AppendLine("  Gaps:");
                    foreach (SectionGapInfo gap in pe.SectionGaps)
                    {
                        sb.AppendLine("    - " + Safe(gap.PreviousSection) + " -> " + Safe(gap.NextSection) +
                                      " | Offset: 0x" + gap.FileOffset.ToString("X", CultureInfo.InvariantCulture) +
                                      " | Size: " + gap.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | NonZero: " + gap.NonZeroCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Sampled: " + gap.SampledBytes.ToString(CultureInfo.InvariantCulture));
                    }
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
                    if (entry.AuthenticodeStatus != null)
                    {
                        sb.AppendLine("    Status: Signers=" + entry.AuthenticodeStatus.SignerCount.ToString(CultureInfo.InvariantCulture) +
                                      " | SignatureValid=" + entry.AuthenticodeStatus.SignatureValid +
                                      " | ChainValid=" + entry.AuthenticodeStatus.ChainValid +
                                      " | Timestamp=" + entry.AuthenticodeStatus.HasTimestamp +
                                      " | TimestampValid=" + entry.AuthenticodeStatus.TimestampValid);
                        sb.AppendLine("    Policy Compliant: " + entry.AuthenticodeStatus.PolicyCompliant);
                        if (entry.AuthenticodeStatus.PolicyFailures.Count > 0)
                        {
                            sb.AppendLine("    Policy Failures:");
                            foreach (string failure in entry.AuthenticodeStatus.PolicyFailures)
                            {
                                sb.AppendLine("      - " + Safe(failure));
                            }
                        }
                    }

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
                        if (entry.AuthenticodeResults != null && entry.AuthenticodeResults.Length > 0)
                        {
                            WriteAuthenticodeResults(sb, entry.AuthenticodeResults, "    ");
                        }
                        continue;
                    }

                    foreach (Pkcs7SignerInfo signer in entry.Pkcs7SignerInfos)
                    {
                        WriteSignerInfo(sb, signer, "    ");
                    }

                    if (entry.AuthenticodeResults != null && entry.AuthenticodeResults.Length > 0)
                    {
                        WriteAuthenticodeResults(sb, entry.AuthenticodeResults, "    ");
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
                if (!string.IsNullOrWhiteSpace(pe.DotNetRuntimeHint))
                {
                    sb.AppendLine("  Runtime Hint: " + Safe(pe.DotNetRuntimeHint));
                }
                sb.AppendLine("  Runtime Version: " + pe.ClrMetadata.MajorRuntimeVersion + "." + pe.ClrMetadata.MinorRuntimeVersion);
                sb.AppendLine("  Metadata Version: " + Safe(pe.ClrMetadata.MetadataVersion));
                sb.AppendLine("  Flags: 0x" + pe.ClrMetadata.Flags.ToString("X8", CultureInfo.InvariantCulture));
                sb.AppendLine("  EntryPoint Token: 0x" + pe.ClrMetadata.EntryPointToken.ToString("X8", CultureInfo.InvariantCulture));
                sb.AppendLine("  IL Only: " + pe.ClrMetadata.IlOnly);
                sb.AppendLine("  32-bit Required: " + pe.ClrMetadata.Requires32Bit);
                sb.AppendLine("  32-bit Preferred: " + pe.ClrMetadata.Prefers32Bit);
                sb.AppendLine("  StrongName Signed: " + pe.ClrMetadata.StrongNameSigned);
                sb.AppendLine("  Assembly Name: " + Safe(pe.ClrMetadata.AssemblyName));
                sb.AppendLine("  Assembly Version: " + Safe(pe.ClrMetadata.AssemblyVersion));
                sb.AppendLine("  MVID: " + Safe(pe.ClrMetadata.Mvid));
                sb.AppendLine("  Target Framework: " + Safe(pe.ClrMetadata.TargetFramework));
                sb.AppendLine("  Module Count: " + pe.ClrMetadata.ModuleDefinitionCount.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  TypeDef Count: " + pe.ClrMetadata.TypeDefinitionCount.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  TypeRef Count: " + pe.ClrMetadata.TypeReferenceCount.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  MethodDef Count: " + pe.ClrMetadata.MethodDefinitionCount.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  Field Count: " + pe.ClrMetadata.FieldDefinitionCount.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  Property Count: " + pe.ClrMetadata.PropertyDefinitionCount.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  Event Count: " + pe.ClrMetadata.EventDefinitionCount.ToString(CultureInfo.InvariantCulture));
                if (pe.ClrMetadata.HasDebuggableAttribute || !string.IsNullOrWhiteSpace(pe.ClrMetadata.DebuggableModes))
                {
                    sb.AppendLine("  Debuggable: " + Safe(pe.ClrMetadata.DebuggableModes));
                }
                else
                {
                    sb.AppendLine("  Debuggable: (none)");
                }
                if (pe.ClrMetadata.MetadataTableCounts.Length == 0)
                {
                    sb.AppendLine("  Metadata Tables: (none)");
                }
                else
                {
                    sb.AppendLine("  Metadata Tables:");
                    foreach (MetadataTableCountInfo table in pe.ClrMetadata.MetadataTableCounts.OrderBy(t => t.TableIndex))
                    {
                        sb.AppendLine("    - " + table.TableName + ": " + table.Count.ToString(CultureInfo.InvariantCulture));
                    }
                }
                if (pe.ClrMetadata.AssemblyReferences.Length == 0)
                {
                    sb.AppendLine("  Assembly References (metadata): (none)");
                }
                else
                {
                    sb.AppendLine("  Assembly References (metadata):");
                    foreach (ClrAssemblyReferenceInfo reference in pe.ClrMetadata.AssemblyReferences)
                    {
                        string tokenText = reference.Token != 0
                            ? "0x" + reference.Token.ToString("X8", CultureInfo.InvariantCulture)
                            : string.Empty;
                        sb.AppendLine("    - " + reference.FullName +
                                      (string.IsNullOrWhiteSpace(tokenText) ? string.Empty : " [Token: " + tokenText + "]"));
                    }
                }
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

            sb.AppendLine("Strong Name Signature:");
            if (pe.StrongNameSignature == null)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                sb.AppendLine("  RVA: 0x" + pe.StrongNameSignature.Rva.ToString("X8", CultureInfo.InvariantCulture));
                sb.AppendLine("  Size: " + pe.StrongNameSignature.Size.ToString(CultureInfo.InvariantCulture));
            }
            sb.AppendLine();

            sb.AppendLine("ReadyToRun Header:");
            if (pe.ReadyToRun == null)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                sb.AppendLine("  Signature: " + pe.ReadyToRun.SignatureText + " (0x" + pe.ReadyToRun.Signature.ToString("X8", CultureInfo.InvariantCulture) + ")");
                sb.AppendLine("  Version: " + pe.ReadyToRun.MajorVersion.ToString(CultureInfo.InvariantCulture) + "." + pe.ReadyToRun.MinorVersion.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  Flags: 0x" + pe.ReadyToRun.Flags.ToString("X8", CultureInfo.InvariantCulture));
                sb.AppendLine("  Section Count: " + pe.ReadyToRun.SectionCount.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  EntryPoint Sections: " + pe.ReadyToRun.EntryPointSectionCount.ToString(CultureInfo.InvariantCulture) +
                              " | Total Size: " + pe.ReadyToRun.EntryPointSectionTotalSize.ToString(CultureInfo.InvariantCulture));
                if (pe.ReadyToRun.Sections.Count == 0)
                {
                    sb.AppendLine("  Sections: (none)");
                }
                else
                {
                    sb.AppendLine("  Sections:");
                    foreach (ReadyToRunSectionInfo section in pe.ReadyToRun.Sections)
                    {
                        string name = string.IsNullOrWhiteSpace(section.Name) ? string.Empty : " (" + section.Name + ")";
                        sb.AppendLine("    - Type: 0x" + section.Type.ToString("X8", CultureInfo.InvariantCulture) + name +
                                      " | RVA: 0x" + section.Rva.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Size: " + section.Size.ToString(CultureInfo.InvariantCulture));
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
                        string source = entry.Source == ImportThunkSource.ImportAddressTable ? "IAT" : "INT";
                        if (entry.IsByOrdinal)
                        {
                            sb.AppendLine("    - [" + source + "] Ordinal: " + entry.Ordinal.ToString(CultureInfo.InvariantCulture) +
                                          " | Thunk RVA: 0x" + entry.ThunkRva.ToString("X8", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.AppendLine("    - [" + source + "] Hint: " + entry.Hint.ToString(CultureInfo.InvariantCulture) +
                                          ", Name: " + Safe(entry.Name) +
                                          " | Thunk RVA: 0x" + entry.ThunkRva.ToString("X8", CultureInfo.InvariantCulture));
                        }
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Import Descriptors:");
            if (pe.ImportDescriptors.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ImportDescriptorInfo descriptor in pe.ImportDescriptors.OrderBy(d => d.DllName, StringComparer.OrdinalIgnoreCase))
                {
                    sb.AppendLine("  - " + Safe(descriptor.DllName) +
                                  " | INT: " + descriptor.IntCount.ToString(CultureInfo.InvariantCulture) +
                                  " | IAT: " + descriptor.IatCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Bound: " + descriptor.IsBound +
                                  " | Stale: " + descriptor.IsBoundStale);
                    if (descriptor.IntOnlyFunctions.Count > 0)
                    {
                        sb.AppendLine("    INT-only: " + string.Join(", ", descriptor.IntOnlyFunctions.Take(10)));
                        if (descriptor.IntOnlyFunctions.Count > 10)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }
                    if (descriptor.IatOnlyFunctions.Count > 0)
                    {
                        sb.AppendLine("    IAT-only: " + string.Join(", ", descriptor.IatOnlyFunctions.Take(10)));
                        if (descriptor.IatOnlyFunctions.Count > 10)
                        {
                            sb.AppendLine("    (truncated)");
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
                        string source = entry.Source == ImportThunkSource.ImportAddressTable ? "IAT" : "INT";
                        if (entry.IsByOrdinal)
                        {
                            sb.AppendLine("    - [" + source + "] Ordinal: " + entry.Ordinal.ToString(CultureInfo.InvariantCulture) +
                                          " | Thunk RVA: 0x" + entry.ThunkRva.ToString("X8", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.AppendLine("    - [" + source + "] Hint: " + entry.Hint.ToString(CultureInfo.InvariantCulture) +
                                          ", Name: " + Safe(entry.Name) +
                                          " | Thunk RVA: 0x" + entry.ThunkRva.ToString("X8", CultureInfo.InvariantCulture));
                        }
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Delay Import Descriptors:");
            if (pe.DelayImportDescriptors.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (DelayImportDescriptorInfo descriptor in pe.DelayImportDescriptors)
                {
                    sb.AppendLine("  - Dll: " + Safe(descriptor.DllName) +
                                  " | Uses RVA: " + descriptor.UsesRva +
                                  " | Bound: " + descriptor.IsBound +
                                  " | TimeDateStamp: 0x" + descriptor.TimeDateStamp.ToString("X8", CultureInfo.InvariantCulture));
                    sb.AppendLine("    ModuleHandle RVA: 0x" + descriptor.ModuleHandleRva.ToString("X8", CultureInfo.InvariantCulture));
                    sb.AppendLine("    IAT RVA: 0x" + descriptor.ImportAddressTableRva.ToString("X8", CultureInfo.InvariantCulture));
                    sb.AppendLine("    INT RVA: 0x" + descriptor.ImportNameTableRva.ToString("X8", CultureInfo.InvariantCulture));
                    sb.AppendLine("    Bound IAT RVA: 0x" + descriptor.BoundImportAddressTableRva.ToString("X8", CultureInfo.InvariantCulture));
                    sb.AppendLine("    Unload Info RVA: 0x" + descriptor.UnloadInformationTableRva.ToString("X8", CultureInfo.InvariantCulture));
                }
            }
            sb.AppendLine();

            sb.AppendLine("Bound Imports:");
            if (pe.BoundImports.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (BoundImportEntry bound in pe.BoundImports)
                {
                    sb.AppendLine("  - Dll: " + Safe(bound.DllName) +
                                  " | TimeDateStamp: 0x" + bound.TimeDateStamp.ToString("X8", CultureInfo.InvariantCulture));
                    if (bound.Forwarders.Length == 0)
                    {
                        sb.AppendLine("    Forwarders: (none)");
                    }
                    else
                    {
                        sb.AppendLine("    Forwarders:");
                        foreach (BoundForwarderRef forwarder in bound.Forwarders)
                        {
                            sb.AppendLine("      - " + Safe(forwarder.DllName) +
                                          " | TimeDateStamp: 0x" + forwarder.TimeDateStamp.ToString("X8", CultureInfo.InvariantCulture));
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
                    string line = "  - Ordinal: " + entry.Ordinal.ToString(CultureInfo.InvariantCulture) +
                                  ", Name: " + name +
                                  ", AddressRVA: 0x" + entry.AddressRva.ToString("X8", CultureInfo.InvariantCulture);
                    if (entry.IsForwarder)
                    {
                        line += ", Forwarder: " + Safe(entry.Forwarder);
                        if (entry.ForwarderChain.Count > 0)
                        {
                            line += ", ForwarderTarget: " + Safe(entry.ForwarderTarget);
                        }
                    }
                    sb.AppendLine(line);
                    if (entry.IsForwarder && entry.ForwarderChain.Count > 0)
                    {
                        string chain = string.Join(" -> ", entry.ForwarderChain);
                        if (entry.ForwarderHasCycle)
                        {
                            chain += " (cycle)";
                        }
                        sb.AppendLine("    ForwarderChain: " + chain);
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Exception Directory:");
            if (pe.ExceptionFunctions.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                if (pe.ExceptionSummary != null)
                {
                    sb.AppendLine("  Summary:");
                    sb.AppendLine("    Functions: " + pe.ExceptionSummary.FunctionCount.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("    Invalid Ranges: " + pe.ExceptionSummary.InvalidRangeCount.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("    Out Of Range: " + pe.ExceptionSummary.OutOfRangeCount.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("    Unwind Infos: " + pe.ExceptionSummary.UnwindInfoCount.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("    Unwind Parse Failures: " + pe.ExceptionSummary.UnwindInfoParseFailures.ToString(CultureInfo.InvariantCulture));
                    if (pe.ExceptionSummary.UnwindInfoVersions.Count > 0)
                    {
                        sb.AppendLine("    Unwind Versions:");
                        foreach (UnwindInfoVersionCount version in pe.ExceptionSummary.UnwindInfoVersions)
                        {
                            sb.AppendLine("      - v" + version.Version.ToString(CultureInfo.InvariantCulture) +
                                          ": " + version.Count.ToString(CultureInfo.InvariantCulture));
                        }
                    }
                }

                if (pe.UnwindInfoDetails.Count > 0)
                {
                    sb.AppendLine("  Unwind Details:");
                    foreach (UnwindInfoDetail detail in pe.UnwindInfoDetails.Take(20))
                    {
                        string line = "    - Function: 0x" + detail.FunctionBegin.ToString("X8", CultureInfo.InvariantCulture) +
                                      "-0x" + detail.FunctionEnd.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Unwind: 0x" + detail.UnwindInfoAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Prolog: " + detail.PrologSize.ToString(CultureInfo.InvariantCulture) +
                                      " | Frame: " + detail.FrameRegister.ToString(CultureInfo.InvariantCulture) +
                                      "/" + detail.FrameOffset.ToString(CultureInfo.InvariantCulture);
                        if (detail.PrologSizeExceedsFunction)
                        {
                            line += " (prolog > size)";
                        }
                        sb.AppendLine(line);

                        if (detail.UnwindCodes.Count > 0)
                        {
                            string codes = string.Join(", ",
                                detail.UnwindCodes.Select(c =>
                                    c.CodeOffset.ToString(CultureInfo.InvariantCulture) +
                                    ":" + c.UnwindOp.ToString(CultureInfo.InvariantCulture) +
                                    "/" + c.OpInfo.ToString(CultureInfo.InvariantCulture)));
                            sb.AppendLine("      Codes: " + codes);
                        }
                    }

                    if (pe.UnwindInfoDetails.Count > 20)
                    {
                        sb.AppendLine("    (truncated)");
                    }
                }

                sb.AppendLine("  Functions: " + pe.ExceptionFunctions.Length.ToString(CultureInfo.InvariantCulture));
                foreach (ExceptionFunctionInfo func in pe.ExceptionFunctions.Take(50))
                {
                    sb.AppendLine("  - Begin: 0x" + func.BeginAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                  " | End: 0x" + func.EndAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                  " | Unwind: 0x" + func.UnwindInfoAddress.ToString("X8", CultureInfo.InvariantCulture));
                }
                if (pe.ExceptionFunctions.Length > 50)
                {
                    sb.AppendLine("  (truncated)");
                }
            }
            sb.AppendLine();

            sb.AppendLine("Debug Directory:");
            if (pe.DebugDirectories.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (DebugDirectoryEntry entry in pe.DebugDirectories)
                {
                    sb.AppendLine("  - Type: " + entry.Type +
                                  " | Size: " + entry.SizeOfData.ToString(CultureInfo.InvariantCulture) +
                                  " | Timestamp: 0x" + entry.TimeDateStamp.ToString("X8", CultureInfo.InvariantCulture) +
                                  " | RawPtr: 0x" + entry.PointerToRawData.ToString("X8", CultureInfo.InvariantCulture));
                    if (!string.IsNullOrWhiteSpace(entry.Note))
                    {
                        sb.AppendLine("    Note: " + entry.Note);
                    }
                    if (entry.CodeView != null)
                    {
                        sb.AppendLine("    CodeView: " + entry.CodeView.Signature +
                                      " | Age: " + entry.CodeView.Age.ToString(CultureInfo.InvariantCulture));
                        if (!string.IsNullOrWhiteSpace(entry.CodeView.PdbPath))
                        {
                            sb.AppendLine("    PDB: " + entry.CodeView.PdbPath);
                        }
                        if (entry.CodeView.Guid != Guid.Empty)
                        {
                            sb.AppendLine("    GUID: " + entry.CodeView.Guid.ToString());
                        }
                        if (entry.CodeView.HasPdbTimeDateStamp)
                        {
                            sb.AppendLine("    PDB TimeDateStamp: 0x" + entry.CodeView.PdbTimeDateStamp.ToString("X8", CultureInfo.InvariantCulture));
                            sb.AppendLine("    Timestamp Match: " + entry.CodeView.TimeDateStampMatches);
                        }
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Base Relocations:");
            if (pe.BaseRelocations.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                int totalEntries = pe.BaseRelocations.Sum(b => b.EntryCount);
                sb.AppendLine("  Blocks: " + pe.BaseRelocations.Length.ToString(CultureInfo.InvariantCulture) +
                              " | Entries: " + totalEntries.ToString(CultureInfo.InvariantCulture));
                foreach (BaseRelocationBlockInfo block in pe.BaseRelocations)
                {
                    sb.AppendLine("  - Page RVA: 0x" + block.PageRva.ToString("X8", CultureInfo.InvariantCulture) +
                                  " | Entries: " + block.EntryCount.ToString(CultureInfo.InvariantCulture));
                }
            }
            sb.AppendLine();

            sb.AppendLine("TLS Directory:");
            if (pe.TlsInfo == null)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                sb.AppendLine("  StartRawData: 0x" + pe.TlsInfo.StartAddressOfRawData.ToString("X", CultureInfo.InvariantCulture));
                sb.AppendLine("  EndRawData: 0x" + pe.TlsInfo.EndAddressOfRawData.ToString("X", CultureInfo.InvariantCulture));
                sb.AppendLine("  AddressOfIndex: 0x" + pe.TlsInfo.AddressOfIndex.ToString("X", CultureInfo.InvariantCulture));
                sb.AppendLine("  AddressOfCallbacks: 0x" + pe.TlsInfo.AddressOfCallbacks.ToString("X", CultureInfo.InvariantCulture));
                sb.AppendLine("  SizeOfZeroFill: " + pe.TlsInfo.SizeOfZeroFill.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  Characteristics: 0x" + pe.TlsInfo.Characteristics.ToString("X8", CultureInfo.InvariantCulture));
                if (pe.TlsInfo.CallbackInfos.Count > 0)
                {
                    sb.AppendLine("  Callbacks:");
                    foreach (TlsCallbackInfo callback in pe.TlsInfo.CallbackInfos)
                    {
                        string line = "    - 0x" + callback.Address.ToString("X", CultureInfo.InvariantCulture);
                        if (callback.Rva != 0)
                        {
                            line += " (RVA 0x" + callback.Rva.ToString("X8", CultureInfo.InvariantCulture) + ")";
                        }

                        if (!string.IsNullOrWhiteSpace(callback.SymbolName))
                        {
                            line += " " + callback.SymbolName;
                        }

                        sb.AppendLine(line);
                    }
                }
                else if (pe.TlsInfo.CallbackAddresses.Count == 0)
                {
                    sb.AppendLine("  Callbacks: (none)");
                }
                else
                {
                    sb.AppendLine("  Callbacks:");
                    foreach (ulong callback in pe.TlsInfo.CallbackAddresses)
                    {
                        sb.AppendLine("    - 0x" + callback.ToString("X", CultureInfo.InvariantCulture));
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Load Config:");
            if (pe.LoadConfig == null)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                sb.AppendLine("  Size: " + pe.LoadConfig.Size.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  TimeDateStamp: 0x" + pe.LoadConfig.TimeDateStamp.ToString("X8", CultureInfo.InvariantCulture));
                if (pe.LoadConfig.GlobalFlagsInfo != null)
                {
                    sb.AppendLine("  GlobalFlags: 0x" + pe.LoadConfig.GlobalFlagsInfo.Value.ToString("X8", CultureInfo.InvariantCulture));
                    if (pe.LoadConfig.GlobalFlagsInfo.Flags.Count > 0)
                    {
                        sb.AppendLine("  Global Flags Decoded:");
                        foreach (string flag in pe.LoadConfig.GlobalFlagsInfo.Flags)
                        {
                            sb.AppendLine("    - " + flag);
                        }
                    }
                }

                sb.AppendLine("  SecurityCookie: 0x" + pe.LoadConfig.SecurityCookie.ToString("X", CultureInfo.InvariantCulture));
                sb.AppendLine("  SEHandlerCount: " + pe.LoadConfig.SeHandlerCount.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  GuardFlags: 0x" + pe.LoadConfig.GuardFlags.ToString("X8", CultureInfo.InvariantCulture));
                if (pe.LoadConfig.GuardFlagsInfo != null && pe.LoadConfig.GuardFlagsInfo.Flags.Count > 0)
                {
                    sb.AppendLine("  Guard Flags Decoded:");
                    foreach (string flag in pe.LoadConfig.GuardFlagsInfo.Flags)
                    {
                        sb.AppendLine("    - " + flag);
                    }
                }

                if (pe.LoadConfig.ChpeMetadataPointer != 0)
                {
                    sb.AppendLine("  CHPE Metadata Pointer: 0x" + pe.LoadConfig.ChpeMetadataPointer.ToString("X", CultureInfo.InvariantCulture));
                }

                if (pe.LoadConfig.GuardEhContinuationTable != 0 || pe.LoadConfig.GuardEhContinuationCount != 0)
                {
                    sb.AppendLine("  GuardEH Continuation Table: 0x" + pe.LoadConfig.GuardEhContinuationTable.ToString("X", CultureInfo.InvariantCulture));
                    sb.AppendLine("  GuardEH Continuation Count: " + pe.LoadConfig.GuardEhContinuationCount.ToString(CultureInfo.InvariantCulture));
                }

                if (pe.LoadConfig.GuardXfgCheckFunctionPointer != 0 ||
                    pe.LoadConfig.GuardXfgDispatchFunctionPointer != 0 ||
                    pe.LoadConfig.GuardXfgTableDispatchFunctionPointer != 0)
                {
                    sb.AppendLine("  GuardXFG Check Function: 0x" + pe.LoadConfig.GuardXfgCheckFunctionPointer.ToString("X", CultureInfo.InvariantCulture));
                    sb.AppendLine("  GuardXFG Dispatch Function: 0x" + pe.LoadConfig.GuardXfgDispatchFunctionPointer.ToString("X", CultureInfo.InvariantCulture));
                    sb.AppendLine("  GuardXFG Table Dispatch: 0x" + pe.LoadConfig.GuardXfgTableDispatchFunctionPointer.ToString("X", CultureInfo.InvariantCulture));
                }
            }
            sb.AppendLine();

            sb.AppendLine("Rich Header:");
            if (pe.RichHeader == null || pe.RichHeader.Entries.Count == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                sb.AppendLine("  Key: 0x" + pe.RichHeader.Key.ToString("X8", CultureInfo.InvariantCulture));
                foreach (RichHeaderEntry entry in pe.RichHeader.Entries)
                {
                    sb.AppendLine("  - Product: " + entry.ProductId.ToString(CultureInfo.InvariantCulture) +
                                  " | Build: " + entry.BuildNumber.ToString(CultureInfo.InvariantCulture) +
                                  " | Count: " + entry.Count.ToString(CultureInfo.InvariantCulture));
                }
            }
            sb.AppendLine();

            sb.AppendLine("Version Info Details:");
            if (pe.VersionInfoDetails == null)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                if (pe.VersionInfoDetails.FixedFileInfo != null)
                {
                    sb.AppendLine("  Fixed File Info:");
                    sb.AppendLine("    FileVersion: " + Safe(pe.VersionInfoDetails.FixedFileInfo.FileVersion));
                    sb.AppendLine("    ProductVersion: " + Safe(pe.VersionInfoDetails.FixedFileInfo.ProductVersion));
                    sb.AppendLine("    FileFlags: 0x" + pe.VersionInfoDetails.FixedFileInfo.FileFlags.ToString("X8", CultureInfo.InvariantCulture));
                    sb.AppendLine("    FileOS: 0x" + pe.VersionInfoDetails.FixedFileInfo.FileOs.ToString("X8", CultureInfo.InvariantCulture));
                    sb.AppendLine("    FileType: 0x" + pe.VersionInfoDetails.FixedFileInfo.FileType.ToString("X8", CultureInfo.InvariantCulture));
                }
                sb.AppendLine("  Translation: " + Safe(pe.VersionInfoDetails.TranslationText));
                if (pe.VersionInfoDetails.StringValues.Count > 0)
                {
                    sb.AppendLine("  String Values:");
                    foreach (var pair in pe.VersionInfoDetails.StringValues.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase))
                    {
                        sb.AppendLine("    - " + pair.Key + ": " + pair.Value);
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Icon Groups:");
            if (pe.IconGroups.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (IconGroupInfo group in pe.IconGroups)
                {
                    sb.AppendLine("  - NameId: " + group.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + group.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Entries: " + group.Entries.Count.ToString(CultureInfo.InvariantCulture) +
                                  " | IcoBytes: " + group.IcoData.Length.ToString(CultureInfo.InvariantCulture));
                    if (group.Entries.Count > 0)
                    {
                        foreach (IconEntryInfo entry in group.Entries.Take(10))
                        {
                            string line = "    - " + entry.Width.ToString(CultureInfo.InvariantCulture) +
                                          "x" + entry.Height.ToString(CultureInfo.InvariantCulture) +
                                          " | Bits: " + entry.BitCount.ToString(CultureInfo.InvariantCulture) +
                                          " | ResId: " + entry.ResourceId.ToString(CultureInfo.InvariantCulture);
                            if (entry.IsPng)
                            {
                                line += " | PNG: " + entry.PngWidth.ToString(CultureInfo.InvariantCulture) +
                                        "x" + entry.PngHeight.ToString(CultureInfo.InvariantCulture);
                            }

                            sb.AppendLine(line);
                        }

                        if (group.Entries.Count > 10)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }
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
            sb.AppendLine();

            sb.AppendLine("Resource String Tables:");
            if (pe.ResourceStringTables.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceStringTableInfo table in pe.ResourceStringTables.OrderBy(t => t.BlockId).ThenBy(t => t.LanguageId))
                {
                    sb.AppendLine("  Block: " + table.BlockId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + table.LanguageId.ToString("X4", CultureInfo.InvariantCulture));
                    for (int i = 0; i < table.Strings.Length; i++)
                    {
                        string value = table.Strings[i];
                        if (string.IsNullOrEmpty(value))
                        {
                            continue;
                        }
                        sb.AppendLine("    [" + i.ToString(CultureInfo.InvariantCulture) + "] " + value);
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resource Message Tables:");
            if (pe.ResourceMessageTables.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceMessageTableInfo table in pe.ResourceMessageTables.OrderBy(t => t.NameId).ThenBy(t => t.LanguageId))
                {
                    sb.AppendLine("  NameId: " + table.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + table.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Entries: " + table.Entries.Count.ToString(CultureInfo.InvariantCulture));
                    foreach (MessageTableEntryInfo entry in table.Entries.Take(50))
                    {
                        sb.AppendLine("    - Id: " + entry.Id.ToString(CultureInfo.InvariantCulture) +
                                      " | Unicode: " + entry.IsUnicode +
                                      " | " + entry.Text);
                    }
                    if (table.Entries.Count > 50)
                    {
                        sb.AppendLine("  (truncated)");
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resource Dialogs:");
            if (pe.ResourceDialogs.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceDialogInfo dialog in pe.ResourceDialogs.OrderBy(d => d.NameId).ThenBy(d => d.LanguageId))
                {
                    sb.AppendLine("  NameId: " + dialog.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + dialog.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Controls: " + dialog.ControlCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Title: " + Safe(dialog.Title));
                    sb.AppendLine("    Style: 0x" + dialog.Style.ToString("X8", CultureInfo.InvariantCulture) +
                                  " | ExStyle: 0x" + dialog.ExtendedStyle.ToString("X8", CultureInfo.InvariantCulture) +
                                  " | Rect: " + dialog.X + "," + dialog.Y + " " + dialog.Cx + "x" + dialog.Cy);
                    if (!string.IsNullOrWhiteSpace(dialog.Menu))
                    {
                        sb.AppendLine("    Menu: " + Safe(dialog.Menu));
                    }
                    if (!string.IsNullOrWhiteSpace(dialog.WindowClass))
                    {
                        sb.AppendLine("    Class: " + Safe(dialog.WindowClass));
                    }
                    if (dialog.FontPointSize.HasValue)
                    {
                        sb.AppendLine("    Font: " + dialog.FontPointSize.Value.ToString(CultureInfo.InvariantCulture) +
                                      (string.IsNullOrWhiteSpace(dialog.FontFace) ? string.Empty : " " + dialog.FontFace));
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resource Accelerators:");
            if (pe.ResourceAccelerators.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceAcceleratorTableInfo table in pe.ResourceAccelerators.OrderBy(t => t.NameId).ThenBy(t => t.LanguageId))
                {
                    sb.AppendLine("  NameId: " + table.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + table.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Entries: " + table.Entries.Count.ToString(CultureInfo.InvariantCulture));
                    foreach (ResourceAcceleratorEntryInfo entry in table.Entries)
                    {
                        string flags = entry.FlagNames.Length == 0
                            ? "0x" + entry.Flags.ToString("X2", CultureInfo.InvariantCulture)
                            : string.Join(",", entry.FlagNames);
                        sb.AppendLine("    - Key: 0x" + entry.Key.ToString("X4", CultureInfo.InvariantCulture) +
                                      " | Cmd: 0x" + entry.Command.ToString("X4", CultureInfo.InvariantCulture) +
                                      " | Flags: " + flags +
                                      " | Last: " + entry.IsLast);
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resource Menus:");
            if (pe.ResourceMenus.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceMenuInfo menu in pe.ResourceMenus.OrderBy(m => m.NameId).ThenBy(m => m.LanguageId))
                {
                    sb.AppendLine("  NameId: " + menu.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + menu.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Items: " + menu.ItemCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Extended: " + menu.IsExtended);
                    if (menu.ItemTexts.Count > 0)
                    {
                        foreach (string text in menu.ItemTexts.Take(10))
                        {
                            sb.AppendLine("    - " + Safe(text));
                        }
                        if (menu.ItemTexts.Count > 10)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resource Toolbars:");
            if (pe.ResourceToolbars.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceToolbarInfo toolbar in pe.ResourceToolbars.OrderBy(t => t.NameId).ThenBy(t => t.LanguageId))
                {
                    sb.AppendLine("  NameId: " + toolbar.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + toolbar.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Version: " + toolbar.Version.ToString(CultureInfo.InvariantCulture) +
                                  " | Size: " + toolbar.Width.ToString(CultureInfo.InvariantCulture) + "x" + toolbar.Height.ToString(CultureInfo.InvariantCulture) +
                                  " | Items: " + toolbar.ItemCount.ToString(CultureInfo.InvariantCulture));
                    if (toolbar.ItemIds.Count > 0)
                    {
                        sb.AppendLine("    Ids: " + string.Join(", ", toolbar.ItemIds.Take(12)));
                        if (toolbar.ItemIds.Count > 12)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resource Manifests:");
            if (pe.ResourceManifests.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceManifestInfo manifest in pe.ResourceManifests.OrderBy(m => m.NameId).ThenBy(m => m.LanguageId))
                {
                    string typeLabel = !string.IsNullOrWhiteSpace(manifest.TypeName)
                        ? manifest.TypeName
                        : "Type#" + manifest.TypeId.ToString(CultureInfo.InvariantCulture);
                    if (manifest.IsMui && !string.Equals(typeLabel, "MUI", StringComparison.OrdinalIgnoreCase))
                    {
                        typeLabel = "MUI";
                    }

                    sb.AppendLine("  NameId: " + manifest.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + manifest.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Type: " + typeLabel);
                    if (manifest.Schema != null)
                    {
                        sb.AppendLine("    Schema:");
                        sb.AppendLine("      Root: " + Safe(manifest.Schema.RootElement));
                        sb.AppendLine("      Namespace: " + Safe(manifest.Schema.Namespace));
                        sb.AppendLine("      ManifestVersion: " + Safe(manifest.Schema.ManifestVersion));
                        if (!string.IsNullOrWhiteSpace(manifest.Schema.AssemblyIdentityName))
                        {
                            sb.AppendLine("      AssemblyIdentity: " + Safe(manifest.Schema.AssemblyIdentityName) +
                                          (string.IsNullOrWhiteSpace(manifest.Schema.AssemblyIdentityVersion) ? string.Empty : " " + manifest.Schema.AssemblyIdentityVersion));
                        }
                        if (!string.IsNullOrWhiteSpace(manifest.Schema.AssemblyIdentityArchitecture))
                        {
                            sb.AppendLine("      Architecture: " + Safe(manifest.Schema.AssemblyIdentityArchitecture));
                        }
                        if (!string.IsNullOrWhiteSpace(manifest.Schema.AssemblyIdentityType))
                        {
                            sb.AppendLine("      AssemblyType: " + Safe(manifest.Schema.AssemblyIdentityType));
                        }
                        if (!string.IsNullOrWhiteSpace(manifest.Schema.AssemblyIdentityLanguage))
                        {
                            sb.AppendLine("      AssemblyLanguage: " + Safe(manifest.Schema.AssemblyIdentityLanguage));
                        }
                        if (!string.IsNullOrWhiteSpace(manifest.Schema.RequestedExecutionLevel))
                        {
                            sb.AppendLine("      RequestedExecutionLevel: " + Safe(manifest.Schema.RequestedExecutionLevel));
                        }
                        if (!string.IsNullOrWhiteSpace(manifest.Schema.UiAccess))
                        {
                            sb.AppendLine("      UiAccess: " + Safe(manifest.Schema.UiAccess));
                        }
                        if (!string.IsNullOrWhiteSpace(manifest.Schema.DpiAware))
                        {
                            sb.AppendLine("      DpiAware: " + Safe(manifest.Schema.DpiAware));
                        }
                        if (!string.IsNullOrWhiteSpace(manifest.Schema.DpiAwareness))
                        {
                            sb.AppendLine("      DpiAwareness: " + Safe(manifest.Schema.DpiAwareness));
                        }
                        if (!string.IsNullOrWhiteSpace(manifest.Schema.UiLanguage))
                        {
                            sb.AppendLine("      UiLanguage: " + Safe(manifest.Schema.UiLanguage));
                        }
                    }
                    if (!string.IsNullOrWhiteSpace(manifest.Content))
                    {
                        foreach (string line in manifest.Content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                        {
                            sb.AppendLine("    " + line);
                        }
                    }
                }
            }

            return sb.ToString();
        }

        private static void WriteAuthenticodeResults(StringBuilder sb, AuthenticodeVerificationResult[] results, string indent)
        {
            string prefix = indent ?? string.Empty;
            sb.AppendLine(prefix + "Authenticode:");
            foreach (AuthenticodeVerificationResult result in results)
            {
                sb.AppendLine(prefix + "  - " + Safe(result.EmbeddedDigest.AlgorithmName) +
                              " (" + Safe(result.EmbeddedDigest.AlgorithmOid) + ")");
                sb.AppendLine(prefix + "    Embedded: " + ToHex(result.EmbeddedDigest.Digest));
                sb.AppendLine(prefix + "    Computed: " + Safe(result.ComputedHash));
                sb.AppendLine(prefix + "    Match: " + result.Matches);
            }
        }

        private static void WriteSignerInfo(StringBuilder sb, Pkcs7SignerInfo signer, string indent)
        {
            string prefix = indent ?? string.Empty;
            sb.AppendLine(prefix + "- Subject: " + Safe(signer.Subject));
            sb.AppendLine(prefix + "  Issuer: " + Safe(signer.Issuer));
            sb.AppendLine(prefix + "  Serial: " + Safe(signer.SerialNumber));
            sb.AppendLine(prefix + "  Thumbprint: " + Safe(signer.Thumbprint));
            sb.AppendLine(prefix + "  Digest: " + Safe(signer.DigestAlgorithm));
            sb.AppendLine(prefix + "  Signature: " + Safe(signer.SignatureAlgorithm));
            sb.AppendLine(prefix + "  Signer ID Type: " + Safe(signer.SignerIdentifierType));
            sb.AppendLine(prefix + "  Signing Time: " + (signer.SigningTime?.ToString("u", CultureInfo.InvariantCulture) ?? string.Empty));
            sb.AppendLine(prefix + "  Signature Valid: " + signer.SignatureValid);
            if (!string.IsNullOrWhiteSpace(signer.SignatureError))
            {
                sb.AppendLine(prefix + "  Signature Error: " + signer.SignatureError);
            }
            sb.AppendLine(prefix + "  Chain Valid: " + signer.ChainValid);
            sb.AppendLine(prefix + "  Code Signing EKU: " + signer.HasCodeSigningEku);
            sb.AppendLine(prefix + "  Timestamp EKU: " + signer.HasTimestampEku);
            sb.AppendLine(prefix + "  Within Validity: " + signer.IsWithinValidityPeriod);
            if (signer.NestingLevel > 0)
            {
                sb.AppendLine(prefix + "  Nesting Level: " + signer.NestingLevel.ToString(CultureInfo.InvariantCulture));
            }
            if (signer.ChainStatus != null && signer.ChainStatus.Length > 0)
            {
                sb.AppendLine(prefix + "  Chain Status:");
                foreach (string status in signer.ChainStatus)
                {
                    sb.AppendLine(prefix + "    - " + status);
                }
            }
            if (signer.IsTimestampSigner)
            {
                sb.AppendLine(prefix + "  Timestamp Signer: true");
            }
            if (signer.Rfc3161Timestamps != null && signer.Rfc3161Timestamps.Count > 0)
            {
                sb.AppendLine(prefix + "  RFC3161 Timestamps:");
                foreach (Pkcs7TimestampInfo info in signer.Rfc3161Timestamps)
                {
                    sb.AppendLine(prefix + "    - Policy: " + Safe(info.Policy));
                    if (!string.IsNullOrWhiteSpace(info.SerialNumber))
                    {
                        sb.AppendLine(prefix + "      Serial: " + Safe(info.SerialNumber));
                    }
                    if (!string.IsNullOrWhiteSpace(info.TsaName))
                    {
                        sb.AppendLine(prefix + "      TSA: " + Safe(info.TsaName));
                    }
                    if (info.GeneratedTime.HasValue)
                    {
                        sb.AppendLine(prefix + "      Time: " + info.GeneratedTime.Value.ToString("u", CultureInfo.InvariantCulture));
                    }
                }
            }
            if (signer.CounterSigners != null && signer.CounterSigners.Length > 0)
            {
                sb.AppendLine(prefix + "  Counter Signers:");
                foreach (Pkcs7SignerInfo counter in signer.CounterSigners)
                {
                    WriteSignerInfo(sb, counter, prefix + "    ");
                }
            }
            if (signer.NestedSigners != null && signer.NestedSigners.Length > 0)
            {
                sb.AppendLine(prefix + "  Nested Signatures:");
                foreach (Pkcs7SignerInfo nested in signer.NestedSigners)
                {
                    WriteSignerInfo(sb, nested, prefix + "    ");
                }
            }
        }

        private static string Safe(string? value)
        {
            return value ?? string.Empty;
        }

        private static string ToHex(byte[]? data)
        {
            if (data == null || data.Length == 0)
            {
                return string.Empty;
            }

            StringBuilder sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
            {
                sb.Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
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
