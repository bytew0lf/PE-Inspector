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
            public ReportFilter Filter { get; } = new ReportFilter();
        }

        private sealed class ReportFilter
        {
            public HashSet<string> Include { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> Exclude { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            public bool ShouldInclude(string sectionKey)
            {
                string key = NormalizeSectionKey(sectionKey);
                if (Include.Count > 0 && !Include.Contains(key))
                {
                    return false;
                }

                if (Exclude.Contains(key))
                {
                    return false;
                }

                return true;
            }
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

                string report = BuildReport(options.FilePath, pe, certPaths, pemPaths, options.Filter);
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

        private static string BuildReport(string filePath, PECOFF pe, List<string> certPaths, List<string> pemPaths, ReportFilter filter)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("PE File Inspection Report");
            sb.AppendLine("=========================");
            sb.AppendLine("Generated: " + DateTimeOffset.Now.ToString("u", CultureInfo.InvariantCulture));
            sb.AppendLine();

            if (filter.ShouldInclude("file-info"))
            {
                FileInfo fi = new FileInfo(filePath);
                sb.AppendLine("File Information:");
                sb.AppendLine("  Full Path: " + filePath);
                sb.AppendLine("  File Name: " + fi.Name);
                sb.AppendLine("  Extension: " + fi.Extension);
                sb.AppendLine("  Directory: " + fi.DirectoryName);
                sb.AppendLine("  Size (bytes): " + fi.Length.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  SHA256: " + (pe.Hash ?? string.Empty));
                sb.AppendLine();
            }

            if (filter.ShouldInclude("version-info"))
            {
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
                if (pe.VersionInfoDetails != null)
                {
                    if (pe.VersionInfoDetails.Translations.Count > 0)
                    {
                        sb.AppendLine("  Translations:");
                        foreach (VersionTranslationInfo translation in pe.VersionInfoDetails.Translations)
                        {
                            sb.AppendLine("    - " + translation.DisplayName);
                        }
                    }

                    if (pe.VersionInfoDetails.StringTables.Count > 0)
                    {
                        sb.AppendLine("  String Tables:");
                        foreach (VersionStringTableInfo table in pe.VersionInfoDetails.StringTables)
                        {
                            sb.AppendLine("    - " + table.Key + " (" + table.Values.Count.ToString(CultureInfo.InvariantCulture) + " entries)");
                        }
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("pe-analysis"))
            {
                sb.AppendLine("PE Analysis:");
                sb.AppendLine("  Image Kind: " + Safe(pe.ImageKind));
                sb.AppendLine("  Is .NET File: " + pe.IsDotNetFile);
                sb.AppendLine("  Is Obfuscated: " + pe.IsObfuscated);
                sb.AppendLine("  Obfuscation Percentage: " + pe.ObfuscationPercentage.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  Import Hash: " + Safe(pe.ImportHash));
                if (pe.ApiSetSchema != null)
                {
                    if (pe.ApiSetSchema.Loaded)
                    {
                        sb.AppendLine("  API Set Schema: v" + pe.ApiSetSchema.Version.ToString(CultureInfo.InvariantCulture) +
                                      " (" + Safe(pe.ApiSetSchema.Flavor) + ") " + Safe(pe.ApiSetSchema.SourcePath));
                    }
                    else if (!string.IsNullOrWhiteSpace(pe.ApiSetSchema.SourcePath))
                    {
                        sb.AppendLine("  API Set Schema: not loaded (" + Safe(pe.ApiSetSchema.SourcePath) + ")");
                    }
                }
                sb.AppendLine("  File Alignment: " + pe.FileAlignment.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  Section Alignment: " + pe.SectionAlignment.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  Size Of Headers: " + pe.SizeOfHeaders.ToString(CultureInfo.InvariantCulture));
                if (pe.DosRelocations != null && pe.DosRelocations.DeclaredCount > 0)
                {
                    sb.AppendLine("  DOS Relocations: " + pe.DosRelocations.DeclaredCount.ToString(CultureInfo.InvariantCulture) +
                                  (pe.DosRelocations.IsTruncated ? " (truncated)" : string.Empty));
                    sb.AppendLine("    Table Offset: 0x" + pe.DosRelocations.TableOffset.ToString("X", CultureInfo.InvariantCulture));
                    foreach (DosRelocationEntry entry in pe.DosRelocations.Entries.Take(5))
                    {
                        sb.AppendLine("    - Segment: 0x" + entry.Segment.ToString("X4", CultureInfo.InvariantCulture) +
                                      " Offset: 0x" + entry.Offset.ToString("X4", CultureInfo.InvariantCulture) +
                                      " Linear: 0x" + entry.LinearAddress.ToString("X", CultureInfo.InvariantCulture));
                    }
                }
                if (pe.CoffObject != null)
                {
                    sb.AppendLine("  COFF Object:");
                    sb.AppendLine("    Machine: " + Safe(pe.CoffObject.MachineName) + " (0x" + pe.CoffObject.Machine.ToString("X4", CultureInfo.InvariantCulture) + ")");
                    if (pe.CoffObject.IsBigObj)
                    {
                        sb.AppendLine("    Sections: " + pe.CoffObject.BigObjSectionCount.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    BigObj: true");
                        if (pe.CoffObject.BigObjFlags != 0)
                        {
                            sb.AppendLine("    BigObj Flags: 0x" + pe.CoffObject.BigObjFlags.ToString("X8", CultureInfo.InvariantCulture));
                        }
                        if (pe.CoffObject.BigObjMetaDataSize != 0 || pe.CoffObject.BigObjMetaDataOffset != 0)
                        {
                            sb.AppendLine("    BigObj MetaData: Size=" + pe.CoffObject.BigObjMetaDataSize.ToString(CultureInfo.InvariantCulture) +
                                          " Offset=0x" + pe.CoffObject.BigObjMetaDataOffset.ToString("X", CultureInfo.InvariantCulture));
                        }
                        if (!string.IsNullOrWhiteSpace(pe.CoffObject.BigObjClassId))
                        {
                            sb.AppendLine("    BigObj ClassId: " + Safe(pe.CoffObject.BigObjClassId));
                        }
                    }
                    else
                    {
                        sb.AppendLine("    Sections: " + pe.CoffObject.SectionCount.ToString(CultureInfo.InvariantCulture));
                    }
                    sb.AppendLine("    TimeDateStamp: " + pe.CoffObject.TimeDateStamp.ToString(CultureInfo.InvariantCulture));
                    if (pe.CoffObject.TimeDateStampUtc.HasValue)
                    {
                        sb.AppendLine("    TimeDateStamp (UTC): " + pe.CoffObject.TimeDateStampUtc.Value.ToString("u", CultureInfo.InvariantCulture));
                    }
                    if (pe.CoffObject.CharacteristicsFlags.Count > 0)
                    {
                        sb.AppendLine("    Characteristics: " + string.Join(", ", pe.CoffObject.CharacteristicsFlags));
                    }
                }
                if (pe.CoffArchive != null)
                {
                    sb.AppendLine("  COFF Archive:");
                    sb.AppendLine("    Thin: " + pe.CoffArchive.IsThinArchive.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("    Members: " + pe.CoffArchive.MemberCount.ToString(CultureInfo.InvariantCulture));
                    if (pe.CoffArchive.HasLongNameTable)
                    {
                        sb.AppendLine("    LongNames: " + pe.CoffArchive.LongNameTableSize.ToString(CultureInfo.InvariantCulture));
                    }
                    if (pe.CoffArchive.SymbolTable != null)
                    {
                        sb.AppendLine("    Symbols: " + pe.CoffArchive.SymbolTable.SymbolCount.ToString(CultureInfo.InvariantCulture) +
                                      " | NameTable: " + pe.CoffArchive.SymbolTable.NameTableSize.ToString(CultureInfo.InvariantCulture) +
                                      " | Format: " + (pe.CoffArchive.SymbolTable.Is64Bit ? "SYM64" : "SYM32"));
                    }
                    foreach (CoffArchiveMemberInfo member in pe.CoffArchive.Members.Take(5))
                    {
                        sb.AppendLine("    - " + Safe(member.Name) +
                                      " | Size: " + member.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | Import: " + member.IsImportObject +
                                      " | Stored: " + member.DataInArchive);
                        if (member.ImportObject != null)
                        {
                            sb.AppendLine("      Import: " + Safe(member.ImportObject.SymbolName) +
                                          " from " + Safe(member.ImportObject.DllName) +
                                          " (" + Safe(member.ImportObject.MachineName) + ")");
                            if (member.ImportObject.IsImportByOrdinal && member.ImportObject.Ordinal.HasValue)
                            {
                                sb.AppendLine("      Ordinal: " + member.ImportObject.Ordinal.Value.ToString(CultureInfo.InvariantCulture));
                            }
                            else if (member.ImportObject.Hint.HasValue)
                            {
                                sb.AppendLine("      Hint: " + member.ImportObject.Hint.Value.ToString(CultureInfo.InvariantCulture));
                            }
                        }
                    }
                    if (pe.CoffArchive.Members.Count > 5)
                    {
                        sb.AppendLine("    (truncated)");
                    }
                }
                if (pe.TeImage != null)
                {
                    sb.AppendLine("  TE Image:");
                    sb.AppendLine("    Machine: " + Safe(pe.TeImage.MachineName) + " (0x" + pe.TeImage.Machine.ToString("X4", CultureInfo.InvariantCulture) + ")");
                    sb.AppendLine("    Subsystem: " + Safe(pe.TeImage.SubsystemName) + " (" + pe.TeImage.Subsystem.ToString(CultureInfo.InvariantCulture) + ")");
                    sb.AppendLine("    Sections: " + pe.TeImage.SectionCount.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("    StrippedSize: 0x" + pe.TeImage.StrippedSize.ToString("X4", CultureInfo.InvariantCulture));
                    sb.AppendLine("    HeaderSize: 0x" + pe.TeImage.HeaderSize.ToString("X4", CultureInfo.InvariantCulture));
                    sb.AppendLine("    SectionTable: Offset=0x" + pe.TeImage.SectionTableOffset.ToString("X", CultureInfo.InvariantCulture) +
                                  " Size=" + pe.TeImage.SectionTableSize.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("    ImageBase: 0x" + pe.TeImage.ImageBase.ToString("X", CultureInfo.InvariantCulture));
                    sb.AppendLine("    EntryPoint: 0x" + pe.TeImage.AddressOfEntryPoint.ToString("X", CultureInfo.InvariantCulture));
                    sb.AppendLine("    BaseOfCode: 0x" + pe.TeImage.BaseOfCode.ToString("X", CultureInfo.InvariantCulture));
                    if (pe.TeImage.EntryPointFileOffsetValid)
                    {
                        sb.AppendLine("    EntryPointFileOffset: 0x" + pe.TeImage.EntryPointFileOffset.ToString("X", CultureInfo.InvariantCulture));
                    }
                    if (pe.TeImage.EntryPointMapped)
                    {
                        sb.AppendLine("    EntryPointSection: " + Safe(pe.TeImage.EntryPointSectionName));
                    }
                    if (pe.TeImage.BaseOfCodeFileOffsetValid)
                    {
                        sb.AppendLine("    BaseOfCodeFileOffset: 0x" + pe.TeImage.BaseOfCodeFileOffset.ToString("X", CultureInfo.InvariantCulture));
                    }
                    if (pe.TeImage.BaseOfCodeMapped)
                    {
                        sb.AppendLine("    BaseOfCodeSection: " + Safe(pe.TeImage.BaseOfCodeSectionName));
                    }
                    if (pe.TeImage.DataDirectories.Count > 0)
                    {
                        sb.AppendLine("    Directories:");
                        foreach (TeDataDirectoryInfo dir in pe.TeImage.DataDirectories)
                        {
                            sb.AppendLine("      - " + Safe(dir.Name) + ": RVA=0x" + dir.VirtualAddress.ToString("X", CultureInfo.InvariantCulture) +
                                          " Size=" + dir.Size.ToString(CultureInfo.InvariantCulture));
                        }
                    }
                }
                if (pe.OverlayInfo != null)
                {
                    sb.AppendLine("  Overlay Start: 0x" + pe.OverlayInfo.StartOffset.ToString("X", CultureInfo.InvariantCulture));
                    sb.AppendLine("  Overlay Size: " + pe.OverlayInfo.Size.ToString(CultureInfo.InvariantCulture));
                }
                if (pe.OverlayContainers.Length > 0)
                {
                    sb.AppendLine("  Overlay Containers:");
                    foreach (OverlayContainerInfo container in pe.OverlayContainers)
                    {
                        sb.AppendLine("    - " + Safe(container.Type) +
                                      " " + Safe(container.Version) +
                                      " | Entries: " + container.EntryCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Truncated: " + container.IsTruncated.ToString(CultureInfo.InvariantCulture));
                        if (!string.IsNullOrWhiteSpace(container.Notes))
                        {
                            sb.AppendLine("      Notes: " + Safe(container.Notes));
                        }
                        if (container.Entries.Count > 0)
                        {
                            foreach (OverlayContainerEntry entry in container.Entries.Take(10))
                            {
                                sb.AppendLine("      * " + Safe(entry.Name) +
                                              " | " + entry.CompressionMethod +
                                              " | " + entry.CompressedSize.ToString(CultureInfo.InvariantCulture) +
                                              "/" + entry.UncompressedSize.ToString(CultureInfo.InvariantCulture));
                            }
                        }
                    }
                }
                if (pe.PackingHints.Length > 0)
                {
                    sb.AppendLine("  Packing Hints:");
                    foreach (PackingHintInfo hint in pe.PackingHints)
                    {
                        sb.AppendLine("    - " + hint.Kind + ": " + Safe(hint.Name) + " | " + Safe(hint.Evidence));
                    }
                }
                else
                {
                    sb.AppendLine("  Packing Hints: (none)");
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
            }

            if (filter.ShouldInclude("data-directories"))
            {
                sb.AppendLine("Data Directories:");
                if (pe.DataDirectories.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    foreach (DataDirectoryInfo dir in pe.DataDirectories)
                    {
                        string mapping = dir.IsMapped
                            ? " | Section: " + Safe(dir.SectionName) + " (RVA: 0x" + dir.SectionRva.ToString("X8", CultureInfo.InvariantCulture) +
                              " | Size: " + dir.SectionSize.ToString(CultureInfo.InvariantCulture) + ")"
                            : string.Empty;
                        sb.AppendLine("  - [" + dir.Index.ToString(CultureInfo.InvariantCulture) + "] " + Safe(dir.Name) +
                                      " | RVA: 0x" + dir.VirtualAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Size: " + dir.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | Present: " + dir.IsPresent +
                                      " | Mapped: " + dir.IsMapped +
                                      mapping);
                    }
                }

                if (pe.DataDirectoryValidations.Count > 0)
                {
                    sb.AppendLine("Data Directory Validations:");
                    foreach (DataDirectoryValidationInfo validation in pe.DataDirectoryValidations.OrderBy(info => info.Index))
                    {
                        string sectionInfo = string.IsNullOrWhiteSpace(validation.SectionName)
                            ? string.Empty
                            : " | Section: " + Safe(validation.SectionName) + " (RVA: 0x" + validation.SectionRva.ToString("X8", CultureInfo.InvariantCulture) +
                              " | Size: " + validation.SectionSize.ToString(CultureInfo.InvariantCulture) + ")";
                        string notes = string.IsNullOrWhiteSpace(validation.Notes)
                            ? string.Empty
                            : " | Notes: " + Safe(validation.Notes);
                        sb.AppendLine("  - [" + validation.Index.ToString(CultureInfo.InvariantCulture) + "] " + Safe(validation.Name) +
                                      " | RVA: 0x" + validation.VirtualAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Size: " + validation.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | Present: " + validation.IsPresent +
                                      " | Mapped: " + validation.IsMapped +
                                      " | FullyMapped: " + validation.IsFullyMapped +
                                      " | MinSize: " + validation.MinimumSize.ToString(CultureInfo.InvariantCulture) +
                                      " | EntrySize: " + validation.EntrySize.ToString(CultureInfo.InvariantCulture) +
                                      " | Aligned: " + validation.SizeAligned +
                                      " | Plausible: " + validation.SizePlausible +
                                      " | UsesFileOffset: " + validation.UsesFileOffset +
                                      sectionInfo +
                                      notes);
                    }
                }

                if (filter.ShouldInclude("section-directories"))
                {
                    sb.AppendLine("Section Directory Coverage:");
                    if (pe.SectionDirectoryCoverage.Length == 0)
                    {
                        sb.AppendLine("  (none)");
                    }
                    else
                    {
                        foreach (SectionDirectoryInfo entry in pe.SectionDirectoryCoverage.OrderBy(s => s.SectionName, StringComparer.OrdinalIgnoreCase))
                        {
                            string dirs = entry.Directories.Count > 0 ? string.Join(", ", entry.Directories) : "(none)";
                            sb.AppendLine("  - " + Safe(entry.SectionName) + " | Directories: " + dirs);
                        }
                    }
                    if (pe.UnmappedDataDirectories.Length > 0)
                    {
                        sb.AppendLine("  Unmapped Directories: " + string.Join(", ", pe.UnmappedDataDirectories));
                    }
                }

                if (pe.ArchitectureDirectory != null ||
                    pe.GlobalPtrDirectory != null ||
                    pe.IatDirectory != null)
                {
                    sb.AppendLine("  Special Directories:");
                    if (pe.ArchitectureDirectory != null)
                    {
                        sb.AppendLine("    Architecture: RVA 0x" + pe.ArchitectureDirectory.VirtualAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Size: " + pe.ArchitectureDirectory.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | Mapped: " + pe.ArchitectureDirectory.IsMapped +
                                      " | Section: " + Safe(pe.ArchitectureDirectory.SectionName));
                        if (pe.ArchitectureDirectory.Parsed)
                        {
                            sb.AppendLine("      Magic: 0x" + pe.ArchitectureDirectory.Magic.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | Version: " + pe.ArchitectureDirectory.MajorVersion.ToString(CultureInfo.InvariantCulture) +
                                          "." + pe.ArchitectureDirectory.MinorVersion.ToString(CultureInfo.InvariantCulture) +
                                          " | Entries: " + pe.ArchitectureDirectory.NumberOfEntries.ToString(CultureInfo.InvariantCulture));
                            sb.AppendLine("      FirstEntryRva: 0x" + pe.ArchitectureDirectory.FirstEntryRva.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | SizeOfData: " + pe.ArchitectureDirectory.SizeOfData.ToString(CultureInfo.InvariantCulture));
                            if (pe.ArchitectureDirectory.ParsedEntryCount > 0)
                            {
                                string truncated = pe.ArchitectureDirectory.EntriesTruncated ? " (truncated)" : string.Empty;
                                sb.AppendLine("      ParsedEntries: " + pe.ArchitectureDirectory.ParsedEntryCount.ToString(CultureInfo.InvariantCulture) + truncated);
                                foreach (ArchitectureDirectoryEntryInfo entry in pe.ArchitectureDirectory.Entries.Take(5))
                                {
                                    sb.AppendLine("        FixupRva: 0x" + entry.FixupRva.ToString("X8", CultureInfo.InvariantCulture) +
                                                  " | NewInstruction: 0x" + entry.NewInstruction.ToString("X8", CultureInfo.InvariantCulture) +
                                                  " | Mapped: " + entry.FixupMapped +
                                                  " | Section: " + Safe(entry.FixupSectionName));
                                }
                            }
                        }
                    }
                    if (pe.GlobalPtrDirectory != null)
                    {
                        sb.AppendLine("    GlobalPtr: RVA 0x" + pe.GlobalPtrDirectory.VirtualAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Size: " + pe.GlobalPtrDirectory.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | Mapped: " + pe.GlobalPtrDirectory.IsMapped +
                                      " | Section: " + Safe(pe.GlobalPtrDirectory.SectionName));
                        if (pe.GlobalPtrDirectory.ValueMapped)
                        {
                            sb.AppendLine("      Value: 0x" + pe.GlobalPtrDirectory.Value.ToString("X", CultureInfo.InvariantCulture));
                            if (pe.GlobalPtrDirectory.HasRva)
                            {
                                sb.AppendLine("      RVA: 0x" + pe.GlobalPtrDirectory.Rva.ToString("X8", CultureInfo.InvariantCulture) +
                                              " (" + Safe(pe.GlobalPtrDirectory.RvaKind) + ")" +
                                              " | Mapped: " + pe.GlobalPtrDirectory.RvaMapped +
                                              " | Section: " + Safe(pe.GlobalPtrDirectory.RvaSectionName));
                            }
                        }
                    }
                    if (pe.IatDirectory != null)
                    {
                        sb.AppendLine("    IAT: RVA 0x" + pe.IatDirectory.VirtualAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Size: " + pe.IatDirectory.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | Entries: " + pe.IatDirectory.EntryCount.ToString(CultureInfo.InvariantCulture) +
                                      " | EntrySize: " + pe.IatDirectory.EntrySize.ToString(CultureInfo.InvariantCulture) +
                                      " | Aligned: " + pe.IatDirectory.SizeAligned +
                                      " | Mapped: " + pe.IatDirectory.IsMapped +
                                      " | Section: " + Safe(pe.IatDirectory.SectionName));
                        if (pe.IatDirectory.EntryCount > 0)
                        {
                            sb.AppendLine("      NonZero: " + pe.IatDirectory.NonZeroEntryCount.ToString(CultureInfo.InvariantCulture) +
                                          " | Zero: " + pe.IatDirectory.ZeroEntryCount.ToString(CultureInfo.InvariantCulture));
                            if (pe.IatDirectory.SampleCount > 0)
                            {
                                string truncated = pe.IatDirectory.SamplesTruncated ? " (truncated)" : string.Empty;
                                sb.AppendLine("      Samples: " + pe.IatDirectory.SampleCount.ToString(CultureInfo.InvariantCulture) +
                                              " | Mapped: " + pe.IatDirectory.MappedEntryCount.ToString(CultureInfo.InvariantCulture) + truncated);
                                foreach (IatEntryInfo entry in pe.IatDirectory.Samples.Take(5))
                                {
                                    sb.AppendLine("        [" + entry.Index.ToString(CultureInfo.InvariantCulture) + "] 0x" +
                                                  entry.Value.ToString("X", CultureInfo.InvariantCulture) +
                                                  (entry.HasRva
                                                      ? " | RVA: 0x" + entry.Rva.ToString("X8", CultureInfo.InvariantCulture) +
                                                        " (" + Safe(entry.RvaKind) + ")" +
                                                        " | Mapped: " + entry.Mapped +
                                                        " | Section: " + Safe(entry.SectionName)
                                                      : " | RVA: n/a"));
                                }
                            }
                        }
                    }
                }

                sb.AppendLine();
            }

            if (filter.ShouldInclude("section-entropy"))
            {
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
            }

            if (filter.ShouldInclude("section-details"))
            {
                sb.AppendLine("Section Details:");
                if (pe.SectionHeaders.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    foreach (SectionHeaderInfo info in pe.SectionHeaders.OrderBy(s => s.Index))
                    {
                        string flags = info.Flags.Count > 0 ? string.Join(",", info.Flags) : "(none)";
                        sb.AppendLine("  - [" + info.Index.ToString(CultureInfo.InvariantCulture) + "] " + Safe(info.Name) +
                                      " | RVA: 0x" + info.VirtualAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | VSZ: " + info.VirtualSize.ToString(CultureInfo.InvariantCulture) +
                                      " | Raw: 0x" + info.RawPointer.ToString("X", CultureInfo.InvariantCulture) +
                                      " (" + info.RawSize.ToString(CultureInfo.InvariantCulture) + ")");
                        sb.AppendLine("      Flags: " + flags +
                                      " | R:" + info.IsReadable +
                                      " W:" + info.IsWritable +
                                      " X:" + info.IsExecutable +
                                      " | Discardable: " + info.IsDiscardable +
                                      " | Shared: " + info.IsShared);
                        sb.AppendLine("      Align: VA=" + info.VirtualAddressAligned +
                                      " RawPtr=" + info.RawPointerAligned +
                                      " RawSize=" + info.RawSizeAligned +
                                      " | RawInBounds=" + info.RawDataInFileBounds);
                        if (info.VirtualPadding > 0 || info.RawPadding > 0)
                        {
                            sb.AppendLine("      Padding: Virtual=" + info.VirtualPadding.ToString(CultureInfo.InvariantCulture) +
                                          " | Raw=" + info.RawPadding.ToString(CultureInfo.InvariantCulture));
                        }
                        if (info.RelocationCount > 0 || info.LineNumberCount > 0)
                        {
                            sb.AppendLine("      COFF: Relocs=" + info.RelocationCount.ToString(CultureInfo.InvariantCulture) +
                                          " | Lines=" + info.LineNumberCount.ToString(CultureInfo.InvariantCulture));
                        }
                        if (info.HasSuspiciousPermissions || info.HasMismatch)
                        {
                            sb.AppendLine("      Warnings: RWX=" + info.HasSuspiciousPermissions +
                                          " | Mismatch=" + info.HasMismatch +
                                          " | SizeMismatch=" + info.HasSizeMismatch);
                        }
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("section-permissions"))
            {
                sb.AppendLine("Section Permissions:");
                if (pe.SectionPermissions.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    foreach (SectionPermissionInfo info in pe.SectionPermissions.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        string flags = info.Flags.Count > 0 ? string.Join(",", info.Flags) : "(none)";
                        sb.AppendLine("  - " + Safe(info.Name) +
                                      " | Flags: " + flags +
                                      " | R:" + info.IsReadable +
                                      " W:" + info.IsWritable +
                                      " X:" + info.IsExecutable +
                                      " | Suspicious: " + info.HasSuspiciousPermissions +
                                      " | Mismatch: " + info.HasMismatch);
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("section-padding"))
            {
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
            }

            if (filter.ShouldInclude("certificates"))
            {
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
                        if (entry.DeclaredLength > 0)
                        {
                            sb.AppendLine("    Declared Length: " + entry.DeclaredLength.ToString(CultureInfo.InvariantCulture));
                        }
                        if (entry.Revision != 0)
                        {
                            sb.AppendLine("    Revision: " + CertificateUtilities.GetCertificateRevisionName(entry.Revision));
                        }
                        if (entry.AlignedLength > 0)
                        {
                            sb.AppendLine("    Aligned Length: " + entry.AlignedLength.ToString(CultureInfo.InvariantCulture));
                        }
                        if (entry.AlignmentPadding > 0)
                        {
                            sb.AppendLine("    Alignment Padding: " + entry.AlignmentPadding.ToString(CultureInfo.InvariantCulture));
                        }
                        if (entry.FileOffset >= 0)
                        {
                            sb.AppendLine("    File Offset: 0x" + entry.FileOffset.ToString("X", CultureInfo.InvariantCulture));
                        }
                        sb.AppendLine("    Is Aligned: " + entry.IsAligned);
                        if (entry.AuthenticodeStatus != null)
                        {
                            sb.AppendLine("    Status: Signers=" + entry.AuthenticodeStatus.SignerCount.ToString(CultureInfo.InvariantCulture) +
                                          " | SignatureValid=" + entry.AuthenticodeStatus.SignatureValid +
                                          " | ChainValid=" + entry.AuthenticodeStatus.ChainValid +
                                          " | Timestamp=" + entry.AuthenticodeStatus.HasTimestamp +
                                          " | TimestampValid=" + entry.AuthenticodeStatus.TimestampValid);
                            sb.AppendLine("    Certificate Transparency: " + entry.AuthenticodeStatus.CertificateTransparencySignerCount.ToString(CultureInfo.InvariantCulture) +
                                          " | Required Met=" + entry.AuthenticodeStatus.CertificateTransparencyRequiredMet);
                            if (entry.AuthenticodeStatus.CertificateTransparencyLogIds.Count > 0)
                            {
                                sb.AppendLine("    CT Logs: " + entry.AuthenticodeStatus.CertificateTransparencyLogCount.ToString(CultureInfo.InvariantCulture));
                                foreach (string logId in entry.AuthenticodeStatus.CertificateTransparencyLogIds.Take(5))
                                {
                                    sb.AppendLine("      - " + logId);
                                }
                                if (entry.AuthenticodeStatus.CertificateTransparencyLogIds.Count > 5)
                                {
                                    sb.AppendLine("      (truncated)");
                                }
                            }
                            if (entry.AuthenticodeStatus.WinTrust != null)
                            {
                                sb.AppendLine("    WinTrust: " + entry.AuthenticodeStatus.WinTrust.Status +
                                              " | Code=" + entry.AuthenticodeStatus.WinTrust.StatusCode.ToString(CultureInfo.InvariantCulture));
                                if (!string.IsNullOrWhiteSpace(entry.AuthenticodeStatus.WinTrust.Message))
                                {
                                    sb.AppendLine("      " + Safe(entry.AuthenticodeStatus.WinTrust.Message));
                                }
                            }
                            if (entry.AuthenticodeStatus.TrustStore != null)
                            {
                                sb.AppendLine("    TrustStore: " + entry.AuthenticodeStatus.TrustStore.Platform +
                                              " | Performed=" + entry.AuthenticodeStatus.TrustStore.Performed +
                                              " | Verified=" + entry.AuthenticodeStatus.TrustStore.Verified);
                                if (entry.AuthenticodeStatus.TrustStore.Status.Count > 0)
                                {
                                    sb.AppendLine("      Chain: " + string.Join("; ", entry.AuthenticodeStatus.TrustStore.Status.Take(3)));
                                    if (entry.AuthenticodeStatus.TrustStore.Status.Count > 3)
                                    {
                                        sb.AppendLine("      (truncated)");
                                    }
                                }
                            }
                            if (entry.AuthenticodeStatus.Policy != null)
                            {
                                sb.AppendLine("    Policy: RevocationMode=" + entry.AuthenticodeStatus.Policy.RevocationMode +
                                              " | RevocationFlag=" + entry.AuthenticodeStatus.Policy.RevocationFlag +
                                              " | TrustStore=" + entry.AuthenticodeStatus.Policy.EnableTrustStoreCheck +
                                              " | Offline=" + entry.AuthenticodeStatus.Policy.OfflineChainCheck +
                                              " | RequireCT=" + entry.AuthenticodeStatus.Policy.RequireCertificateTransparency +
                                              " | WinTrust=" + entry.AuthenticodeStatus.Policy.EnableWinTrustCheck);
                            }
                            if (entry.AuthenticodeStatus.PolicyEvaluation != null)
                            {
                                sb.AppendLine("    Policy Eval: RevocationRequested=" + entry.AuthenticodeStatus.PolicyEvaluation.RevocationCheckRequested +
                                              " | RevocationPerformed=" + entry.AuthenticodeStatus.PolicyEvaluation.RevocationCheckPerformed +
                                              " | CodeSigningEkuRequired=" + entry.AuthenticodeStatus.PolicyEvaluation.CodeSigningEkuRequired +
                                              " | CodeSigningEkuOk=" + entry.AuthenticodeStatus.PolicyEvaluation.CodeSigningEkuSatisfied +
                                              " | CTRequired=" + entry.AuthenticodeStatus.PolicyEvaluation.CertificateTransparencyRequired +
                                              " | CTOk=" + entry.AuthenticodeStatus.PolicyEvaluation.CertificateTransparencySatisfied);
                                if (entry.AuthenticodeStatus.PolicyEvaluation.CertificateTransparencyLogIds.Count > 0)
                                {
                                    sb.AppendLine("      CT Logs: " + entry.AuthenticodeStatus.PolicyEvaluation.CertificateTransparencyLogCount.ToString(CultureInfo.InvariantCulture));
                                }
                            }
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

                CatalogSignatureInfo catalogInfo = pe.CatalogSignature;
                if (catalogInfo != null && (catalogInfo.Checked || catalogInfo.Supported))
                {
                    sb.AppendLine("  Catalog Signature:");
                    sb.AppendLine("    Supported: " + catalogInfo.Supported);
                    sb.AppendLine("    Checked: " + catalogInfo.Checked);
                    sb.AppendLine("    Signed: " + catalogInfo.IsSigned);
                    if (!string.IsNullOrWhiteSpace(catalogInfo.CatalogName))
                    {
                        sb.AppendLine("    Catalog: " + Safe(catalogInfo.CatalogName));
                    }
                    if (!string.IsNullOrWhiteSpace(catalogInfo.CatalogPath))
                    {
                        sb.AppendLine("    Catalog Path: " + Safe(catalogInfo.CatalogPath));
                    }
                    if (catalogInfo.TrustCheckPerformed)
                    {
                        sb.AppendLine("    Trust Verified: " + catalogInfo.TrustVerified);
                    }
                    if (catalogInfo.Status != null)
                    {
                        sb.AppendLine("    Status: Signers=" + catalogInfo.Status.SignerCount.ToString(CultureInfo.InvariantCulture) +
                                      " | SignatureValid=" + catalogInfo.Status.SignatureValid +
                                      " | ChainValid=" + catalogInfo.Status.ChainValid +
                                      " | Timestamp=" + catalogInfo.Status.HasTimestamp +
                                      " | TimestampValid=" + catalogInfo.Status.TimestampValid);
                        sb.AppendLine("    Certificate Transparency: " + catalogInfo.Status.CertificateTransparencySignerCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Required Met=" + catalogInfo.Status.CertificateTransparencyRequiredMet);
                        if (catalogInfo.Status.Policy != null)
                        {
                            sb.AppendLine("    Policy: RevocationMode=" + catalogInfo.Status.Policy.RevocationMode +
                                          " | RevocationFlag=" + catalogInfo.Status.Policy.RevocationFlag +
                                          " | TrustStore=" + catalogInfo.Status.Policy.EnableTrustStoreCheck +
                                          " | Offline=" + catalogInfo.Status.Policy.OfflineChainCheck +
                                          " | RequireCT=" + catalogInfo.Status.Policy.RequireCertificateTransparency);
                        }
                        sb.AppendLine("    Policy Compliant: " + catalogInfo.Status.PolicyCompliant);
                        if (catalogInfo.Status.PolicyFailures.Count > 0)
                        {
                            sb.AppendLine("    Policy Failures:");
                            foreach (string failure in catalogInfo.Status.PolicyFailures)
                            {
                                sb.AppendLine("      - " + Safe(failure));
                            }
                        }
                    }
                    if (!string.IsNullOrWhiteSpace(catalogInfo.Error))
                    {
                        sb.AppendLine("    Error: " + Safe(catalogInfo.Error));
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("parse-status"))
            {
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
                    Dictionary<string, int> warningCounts = new Dictionary<string, int>(StringComparer.Ordinal);
                    List<string> warningOrder = new List<string>();
                    foreach (string warning in pe.ParseResult.Warnings)
                    {
                        if (warningCounts.TryGetValue(warning, out int count))
                        {
                            warningCounts[warning] = count + 1;
                        }
                        else
                        {
                            warningCounts[warning] = 1;
                            warningOrder.Add(warning);
                        }
                    }

                    foreach (string warning in warningOrder)
                    {
                        sb.AppendLine("    - " + warning + " [" +
                                      warningCounts[warning].ToString(CultureInfo.InvariantCulture) + "]");
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("findings"))
            {
                sb.AppendLine("Findings:");
                WriteFindings(sb, pe);
                sb.AppendLine();
            }

            if (filter.ShouldInclude("clr"))
            {
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
                if (pe.StrongNameValidation != null)
                {
                    sb.AppendLine("  StrongName Signature Present: " + pe.StrongNameValidation.HasSignature);
                    sb.AppendLine("  StrongName Size Matches: " + pe.StrongNameValidation.SizeMatches);
                    if (pe.StrongNameValidation.Issues.Count > 0)
                    {
                        sb.AppendLine("  StrongName Issues:");
                        foreach (string issue in pe.StrongNameValidation.Issues)
                        {
                            sb.AppendLine("    - " + issue);
                        }
                    }
                }
                sb.AppendLine("  Metadata Valid: " + pe.ClrMetadata.IsValid);
                if (pe.ClrMetadata.ValidationMessages != null && pe.ClrMetadata.ValidationMessages.Length > 0)
                {
                    sb.AppendLine("  Metadata Validation Messages:");
                    foreach (string message in pe.ClrMetadata.ValidationMessages)
                    {
                        sb.AppendLine("    - " + message);
                    }
                }
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
                if (pe.ClrMetadata.MethodBodySummary != null)
                {
                    sb.AppendLine("  Method Bodies: " + pe.ClrMetadata.MethodBodySummary.MethodBodyCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Tiny: " + pe.ClrMetadata.MethodBodySummary.TinyHeaderCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Fat: " + pe.ClrMetadata.MethodBodySummary.FatHeaderCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Invalid: " + pe.ClrMetadata.MethodBodySummary.InvalidHeaderCount.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("  IL Bytes: Total=" + pe.ClrMetadata.MethodBodySummary.TotalIlBytes.ToString(CultureInfo.InvariantCulture) +
                                  " | Max=" + pe.ClrMetadata.MethodBodySummary.MaxIlBytes.ToString(CultureInfo.InvariantCulture) +
                                  " | Avg=" + pe.ClrMetadata.MethodBodySummary.AverageIlBytes.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("  EH Clauses: Total=" + pe.ClrMetadata.MethodBodySummary.ExceptionClauseCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Catch=" + pe.ClrMetadata.MethodBodySummary.ExceptionClauseCatchCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Finally=" + pe.ClrMetadata.MethodBodySummary.ExceptionClauseFinallyCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Fault=" + pe.ClrMetadata.MethodBodySummary.ExceptionClauseFaultCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Filter=" + pe.ClrMetadata.MethodBodySummary.ExceptionClauseFilterCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Invalid=" + pe.ClrMetadata.MethodBodySummary.ExceptionClauseInvalidCount.ToString(CultureInfo.InvariantCulture));
                }
                if (pe.ClrMetadata.SignatureSummary != null)
                {
                    sb.AppendLine("  Signature Decode: Methods=" + pe.ClrMetadata.SignatureSummary.MethodSignatureCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Fields=" + pe.ClrMetadata.SignatureSummary.FieldSignatureCount.ToString(CultureInfo.InvariantCulture) +
                                  " | MemberRefs=" + pe.ClrMetadata.SignatureSummary.MemberReferenceSignatureCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Standalone=" + pe.ClrMetadata.SignatureSummary.StandaloneSignatureCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Failed=" + pe.ClrMetadata.SignatureSummary.FailedSignatureCount.ToString(CultureInfo.InvariantCulture));
                    if (pe.ClrMetadata.SignatureSummary.Samples.Count > 0)
                    {
                        sb.AppendLine("  Signature Samples:");
                        foreach (ClrSignatureSampleInfo sample in pe.ClrMetadata.SignatureSummary.Samples.Take(5))
                        {
                            string prefix = string.IsNullOrWhiteSpace(sample.Name) ? sample.Kind : sample.Kind + " " + sample.Name;
                            sb.AppendLine("    - " + prefix + ": " + Safe(sample.Signature));
                        }
                        if (pe.ClrMetadata.SignatureSummary.Samples.Count > 5)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }
                }
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
                        string tokenRange = table.FirstToken != 0
                            ? " (0x" + table.FirstToken.ToString("X8", CultureInfo.InvariantCulture) +
                              "-0x" + table.LastToken.ToString("X8", CultureInfo.InvariantCulture) + ")"
                            : string.Empty;
                        sb.AppendLine("    - " + table.TableName + ": " + table.Count.ToString(CultureInfo.InvariantCulture) + tokenRange);
                    }
                }
                if (pe.ClrMetadata.TokenReferences.Length > 0)
                {
                    sb.AppendLine("  Token References:");
                    foreach (ClrTokenReferenceInfo info in pe.ClrMetadata.TokenReferences)
                    {
                        if (info.Counts.Count == 0)
                        {
                            continue;
                        }
                        string summary = string.Join(", ", info.Counts.Select(c => c.Target + "=" + c.Count.ToString(CultureInfo.InvariantCulture)));
                        sb.AppendLine("    - " + info.Name + ": " + summary);
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
                        string pktSuffix = string.IsNullOrWhiteSpace(reference.PublicKeyToken) || reference.PublicKeyOrToken == reference.PublicKeyToken
                            ? string.Empty
                            : " [PKT: " + reference.PublicKeyToken + "]";
                        string hintSuffix = string.IsNullOrWhiteSpace(reference.ResolutionHint)
                            ? string.Empty
                            : " [" + reference.ResolutionHint + "]";
                        sb.AppendLine("    - " + reference.FullName +
                                      (string.IsNullOrWhiteSpace(tokenText) ? string.Empty : " [Token: " + tokenText + "]") +
                                      pktSuffix +
                                      hintSuffix);
                    }
                }
                if (pe.ClrMetadata.AssemblyAttributes.Length == 0)
                {
                    sb.AppendLine("  Assembly Attributes: (none)");
                }
                else
                {
                    sb.AppendLine("  Assembly Attributes:");
                    foreach (string attribute in pe.ClrMetadata.AssemblyAttributes)
                    {
                        sb.AppendLine("    - " + attribute);
                    }
                }
                if (pe.ClrMetadata.ModuleAttributes.Length == 0)
                {
                    sb.AppendLine("  Module Attributes: (none)");
                }
                else
                {
                    sb.AppendLine("  Module Attributes:");
                    foreach (string attribute in pe.ClrMetadata.ModuleAttributes)
                    {
                        sb.AppendLine("    - " + attribute);
                    }
                }
                if (pe.ClrMetadata.ModuleReferences.Length == 0)
                {
                    sb.AppendLine("  Module References: (none)");
                }
                else
                {
                    sb.AppendLine("  Module References:");
                    foreach (string moduleRef in pe.ClrMetadata.ModuleReferences)
                    {
                        sb.AppendLine("    - " + moduleRef);
                    }
                }
                if (pe.ClrMetadata.ManagedResources.Length == 0)
                {
                    sb.AppendLine("  Managed Resources: (none)");
                }
                else
                {
                    sb.AppendLine("  Managed Resources:");
                    foreach (ManagedResourceInfo resource in pe.ClrMetadata.ManagedResources)
                    {
                        string visibility = resource.IsPublic ? "public" : "private";
                        string details = string.IsNullOrWhiteSpace(resource.Implementation)
                            ? visibility
                            : visibility + ", " + resource.Implementation;
                        string sizeText = resource.Size > 0
                            ? ", Size: " + resource.Size.ToString(CultureInfo.InvariantCulture)
                            : string.Empty;
                        string hashText = string.IsNullOrWhiteSpace(resource.Sha256)
                            ? string.Empty
                            : ", SHA256: " + resource.Sha256;
                        sb.AppendLine("    - " + resource.Name + " (" + details + ", Offset: " + resource.Offset.ToString(CultureInfo.InvariantCulture) + sizeText + hashText + ")");
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
            }

            if (filter.ShouldInclude("strong-name"))
            {
                sb.AppendLine("Strong Name Signature:");
                if (pe.StrongNameSignature == null)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    sb.AppendLine("  RVA: 0x" + pe.StrongNameSignature.Rva.ToString("X8", CultureInfo.InvariantCulture));
                    sb.AppendLine("  Size: " + pe.StrongNameSignature.Size.ToString(CultureInfo.InvariantCulture));
                    sb.AppendLine("  Data Size: " + pe.StrongNameSignature.Data.Length.ToString(CultureInfo.InvariantCulture));
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("readytorun"))
            {
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
            }

            if (filter.ShouldInclude("assembly-refs"))
            {
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
            }

            if (filter.ShouldInclude("imports"))
            {
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
            }

            if (filter.ShouldInclude("import-details"))
            {
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
            }

            if (filter.ShouldInclude("import-descriptors"))
            {
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
                                      " (Null: " + descriptor.IntNullThunkCount.ToString(CultureInfo.InvariantCulture) +
                                      ", Terminated: " + descriptor.IntTerminated + ")" +
                                      " | IAT: " + descriptor.IatCount.ToString(CultureInfo.InvariantCulture) +
                                      " (Null: " + descriptor.IatNullThunkCount.ToString(CultureInfo.InvariantCulture) +
                                      ", Terminated: " + descriptor.IatTerminated + ")" +
                                      " | Bound: " + descriptor.IsBound +
                                      " | Stale: " + descriptor.IsBoundStale);
                        if (descriptor.ApiSetResolution != null && descriptor.ApiSetResolution.IsApiSet)
                        {
                            string targets = descriptor.ApiSetResolution.Targets.Count > 0
                                ? string.Join(", ", descriptor.ApiSetResolution.Targets)
                                : "(unresolved)";
                            string canonical = descriptor.ApiSetResolution.CanonicalTargets.Count > 0
                                ? string.Join(", ", descriptor.ApiSetResolution.CanonicalTargets)
                                : "(none)";
                            sb.AppendLine("    ApiSet: " + Safe(descriptor.ApiSetResolution.ApiSetName) +
                                          " -> " + targets +
                                          " | Canonical: " + canonical +
                                          " | Source: " + Safe(descriptor.ApiSetResolution.ResolutionSource) +
                                          " | Confidence: " + Safe(descriptor.ApiSetResolution.ResolutionConfidence));
                        }
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
            }

            if (filter.ShouldInclude("delay-import-details"))
            {
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
            }

            if (filter.ShouldInclude("delay-import-descriptors"))
            {
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
                        if (descriptor.ApiSetResolution != null && descriptor.ApiSetResolution.IsApiSet)
                        {
                            string targets = descriptor.ApiSetResolution.Targets.Count > 0
                                ? string.Join(", ", descriptor.ApiSetResolution.Targets)
                                : "(unresolved)";
                            string canonical = descriptor.ApiSetResolution.CanonicalTargets.Count > 0
                                ? string.Join(", ", descriptor.ApiSetResolution.CanonicalTargets)
                                : "(none)";
                            sb.AppendLine("    ApiSet: " + Safe(descriptor.ApiSetResolution.ApiSetName) +
                                          " -> " + targets +
                                          " | Canonical: " + canonical +
                                          " | Source: " + Safe(descriptor.ApiSetResolution.ResolutionSource) +
                                          " | Confidence: " + Safe(descriptor.ApiSetResolution.ResolutionConfidence));
                        }
                        sb.AppendLine("    ModuleHandle RVA: 0x" + descriptor.ModuleHandleRva.ToString("X8", CultureInfo.InvariantCulture));
                        sb.AppendLine("    IAT RVA: 0x" + descriptor.ImportAddressTableRva.ToString("X8", CultureInfo.InvariantCulture));
                        sb.AppendLine("    INT RVA: 0x" + descriptor.ImportNameTableRva.ToString("X8", CultureInfo.InvariantCulture));
                        sb.AppendLine("    Bound IAT RVA: 0x" + descriptor.BoundImportAddressTableRva.ToString("X8", CultureInfo.InvariantCulture));
                        sb.AppendLine("    Unload Info RVA: 0x" + descriptor.UnloadInformationTableRva.ToString("X8", CultureInfo.InvariantCulture));
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("bound-imports"))
            {
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
            }

            if (filter.ShouldInclude("exports"))
            {
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
            }

            if (filter.ShouldInclude("export-anomalies") && pe.ExportAnomalies != null)
            {
                sb.AppendLine("Export Anomalies:");
                sb.AppendLine("  Duplicate Names: " + pe.ExportAnomalies.DuplicateNameCount.ToString(CultureInfo.InvariantCulture) +
                              " | Duplicate Ordinals: " + pe.ExportAnomalies.DuplicateOrdinalCount.ToString(CultureInfo.InvariantCulture) +
                              " | Ordinal OutOfRange: " + pe.ExportAnomalies.OrdinalOutOfRangeCount.ToString(CultureInfo.InvariantCulture) +
                              " | Forwarder Missing Target: " + pe.ExportAnomalies.ForwarderMissingTargetCount.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine();
            }

            if (filter.ShouldInclude("export-details"))
            {
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
                            line += ", ForwarderResolved: " + entry.ForwarderResolved;
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
            }

            if (filter.ShouldInclude("exception"))
            {
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
                        sb.AppendLine("    Directory RVA: 0x" + pe.ExceptionSummary.DirectoryRva.ToString("X8", CultureInfo.InvariantCulture));
                        sb.AppendLine("    Directory Size: " + pe.ExceptionSummary.DirectorySize.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    Directory Section: " + Safe(pe.ExceptionSummary.DirectorySection));
                        sb.AppendLine("    In .pdata: " + pe.ExceptionSummary.DirectoryInPdata);
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

                    if (pe.UnwindInfoDetails.Length > 0)
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

                        if (pe.UnwindInfoDetails.Length > 20)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }

                    if (pe.Arm64UnwindInfoDetails.Length > 0)
                    {
                        sb.AppendLine("  ARM64 Unwind Details:");
                        foreach (Arm64UnwindInfoDetail detail in pe.Arm64UnwindInfoDetails.Take(20))
                        {
                            sb.AppendLine("    - Function: 0x" + detail.FunctionBegin.ToString("X8", CultureInfo.InvariantCulture) +
                                          "-0x" + detail.FunctionEnd.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | Unwind: 0x" + detail.UnwindInfoAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | Len: " + detail.FunctionLengthBytes.ToString(CultureInfo.InvariantCulture) +
                                          " | Ver: " + detail.Version.ToString(CultureInfo.InvariantCulture) +
                                          " | Epilog: " + detail.EpilogCount.ToString(CultureInfo.InvariantCulture) +
                                          " | CodeWords: " + detail.CodeWords.ToString(CultureInfo.InvariantCulture) +
                                          " | X: " + detail.HasXFlag +
                                          " | E: " + detail.HasEpilogFlag);
                            if (detail.EpilogScopes.Count > 0)
                            {
                                sb.AppendLine("      Epilog Scopes:");
                                foreach (Arm64EpilogScopeInfo scope in detail.EpilogScopes.Take(5))
                                {
                                    sb.AppendLine("        - Offset: " + scope.StartOffsetBytes.ToString(CultureInfo.InvariantCulture) +
                                                  " | Index: " + scope.StartIndex.ToString(CultureInfo.InvariantCulture) +
                                                  " | Packed: " + scope.IsPacked);
                                }
                            }
                            if (detail.UnwindCodes.Count > 0)
                            {
                                sb.AppendLine("      Codes:");
                                foreach (Arm64UnwindCodeInfo code in detail.UnwindCodes.Take(8))
                                {
                                    sb.AppendLine("        - [" + code.ByteIndex.ToString(CultureInfo.InvariantCulture) + "] " +
                                                  Safe(code.OpCode) + " " + Safe(code.Details));
                                }
                            }
                            if (!string.IsNullOrWhiteSpace(detail.RawPreview))
                            {
                                sb.AppendLine("      Raw: " + detail.RawPreview);
                            }
                        }

                        if (pe.Arm64UnwindInfoDetails.Length > 20)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }

                    if (pe.Arm32UnwindInfoDetails.Length > 0)
                    {
                        sb.AppendLine("  ARM Unwind Details:");
                        foreach (Arm32UnwindInfoDetail detail in pe.Arm32UnwindInfoDetails.Take(20))
                        {
                            sb.AppendLine("    - Function: 0x" + detail.FunctionBegin.ToString("X8", CultureInfo.InvariantCulture) +
                                          "-0x" + detail.FunctionEnd.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | Unwind: 0x" + detail.UnwindInfoAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | Len: " + detail.FunctionLengthBytes.ToString(CultureInfo.InvariantCulture) +
                                          " | Ver: " + detail.Version.ToString(CultureInfo.InvariantCulture) +
                                          " | E: " + detail.HasEpilogFlag +
                                          " | X: " + detail.HasExceptionData +
                                          " | F: " + detail.IsFragment);
                            if (detail.UnwindCodeWords.Count > 0)
                            {
                                sb.AppendLine("      CodeWords: " + string.Join(", ", detail.UnwindCodeWords.Take(6)
                                    .Select(word => "0x" + word.ToString("X8", CultureInfo.InvariantCulture))));
                            }
                        }

                        if (pe.Arm32UnwindInfoDetails.Length > 20)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }

                    if (pe.Ia64UnwindInfoDetails.Length > 0)
                    {
                        sb.AppendLine("  IA64 Unwind Details:");
                        foreach (Ia64UnwindInfoDetail detail in pe.Ia64UnwindInfoDetails.Take(20))
                        {
                            sb.AppendLine("    - Function: 0x" + detail.FunctionBegin.ToString("X8", CultureInfo.InvariantCulture) +
                                          "-0x" + detail.FunctionEnd.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | Unwind: 0x" + detail.UnwindInfoAddress.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | Header: 0x" + detail.Header.ToString("X8", CultureInfo.InvariantCulture));
                            if (!string.IsNullOrWhiteSpace(detail.RawPreview))
                            {
                                sb.AppendLine("      Raw: " + detail.RawPreview);
                            }
                        }

                        if (pe.Ia64UnwindInfoDetails.Length > 20)
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
            }

            if (filter.ShouldInclude("debug"))
            {
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
                        if (!string.IsNullOrWhiteSpace(entry.CodeView.PdbFileName))
                        {
                            sb.AppendLine("    PDB File: " + entry.CodeView.PdbFileName);
                        }
                        if (!string.IsNullOrWhiteSpace(entry.CodeView.PdbId))
                        {
                            sb.AppendLine("    PDB Id: " + entry.CodeView.PdbId);
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
                        sb.AppendLine("    RSDS: " + entry.CodeView.IsRsds +
                                      " | NB10: " + entry.CodeView.IsNb10 +
                                      " | Valid GUID: " + entry.CodeView.HasValidGuid +
                                      " | Valid Age: " + entry.CodeView.HasValidAge);
                        sb.AppendLine("    PDB Path OK: " + entry.CodeView.PdbPathEndsWithPdb);
                        if (!string.IsNullOrWhiteSpace(entry.CodeView.PdbPathSanitized))
                        {
                            sb.AppendLine("    PDB Path Sanitized: " + entry.CodeView.PdbPathSanitized);
                        }
                        sb.AppendLine("    PDB Path Has Dir: " + entry.CodeView.PdbPathHasDirectory);
                        sb.AppendLine("    Identity Valid: " + entry.CodeView.IdentityLooksValid);
                    }
                    if (entry.Pdb != null)
                    {
                        sb.AppendLine("    PDB Info: " + Safe(entry.Pdb.Format) +
                                      " | Streams: " + entry.Pdb.StreamCount.ToString(CultureInfo.InvariantCulture) +
                                      " | PageSize: " + entry.Pdb.PageSize.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    PDB Signature: 0x" + entry.Pdb.PdbSignature.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Age: " + entry.Pdb.Age.ToString(CultureInfo.InvariantCulture));
                        if (entry.Pdb.Guid != Guid.Empty)
                        {
                            sb.AppendLine("    PDB GUID: " + entry.Pdb.Guid.ToString());
                        }
                        if (entry.Pdb.Dbi != null)
                        {
                            sb.AppendLine("    DBI: Version=" + entry.Pdb.Dbi.Version.ToString(CultureInfo.InvariantCulture) +
                                          " | Age=" + entry.Pdb.Dbi.Age.ToString(CultureInfo.InvariantCulture) +
                                          " | Globals=" + entry.Pdb.Dbi.GlobalStreamIndex.ToString(CultureInfo.InvariantCulture) +
                                          " | Publics=" + entry.Pdb.Dbi.PublicStreamIndex.ToString(CultureInfo.InvariantCulture) +
                                          " | SymRec=" + entry.Pdb.Dbi.SymRecordStreamIndex.ToString(CultureInfo.InvariantCulture) +
                                          " | Machine=0x" + entry.Pdb.Dbi.Machine.ToString("X4", CultureInfo.InvariantCulture));
                        }
                        if (entry.Pdb.Tpi != null)
                        {
                            sb.AppendLine("    TPI: Types=" + entry.Pdb.Tpi.TypeCount.ToString(CultureInfo.InvariantCulture) +
                                          " | Version=0x" + entry.Pdb.Tpi.Version.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | HashBuckets=" + entry.Pdb.Tpi.HashBucketCount.ToString(CultureInfo.InvariantCulture));
                        }
                        if (entry.Pdb.Ipi != null)
                        {
                            sb.AppendLine("    IPI: Types=" + entry.Pdb.Ipi.TypeCount.ToString(CultureInfo.InvariantCulture) +
                                          " | Version=0x" + entry.Pdb.Ipi.Version.ToString("X8", CultureInfo.InvariantCulture));
                        }
                        if (entry.Pdb.Publics != null && entry.Pdb.Publics.NameCount > 0)
                        {
                            sb.AppendLine("    GSI/Publics: " + entry.Pdb.Publics.NameCount.ToString(CultureInfo.InvariantCulture));
                        }
                        if (entry.Pdb.Globals != null && entry.Pdb.Globals.NameCount > 0)
                        {
                            sb.AppendLine("    GSI/Globals: " + entry.Pdb.Globals.NameCount.ToString(CultureInfo.InvariantCulture));
                        }
                        if (entry.Pdb.PublicSymbols.Count > 0)
                        {
                            sb.AppendLine("    Public Symbols: " + entry.Pdb.PublicSymbolCount.ToString(CultureInfo.InvariantCulture));
                            foreach (string name in entry.Pdb.PublicSymbols.Take(10))
                            {
                                sb.AppendLine("      - " + Safe(name));
                            }
                            if (entry.Pdb.PublicSymbols.Count > 10)
                            {
                                sb.AppendLine("      (truncated)");
                            }
                        }
                        if (entry.Pdb.SymbolRecordCount > 0)
                        {
                            int publicCount = entry.Pdb.SymbolRecords.Count(r => r.Kind == "Public");
                            int globalCount = entry.Pdb.SymbolRecords.Count(r => r.Kind == "Global");
                            int procCount = entry.Pdb.SymbolRecords.Count(r => r.Kind == "Proc");
                            int localCount = entry.Pdb.SymbolRecords.Count(r => r.Kind == "Local");
                            sb.AppendLine("    Symbol Records: " + entry.Pdb.SymbolRecordCount.ToString(CultureInfo.InvariantCulture) +
                                          " | Public=" + publicCount.ToString(CultureInfo.InvariantCulture) +
                                          " | Global=" + globalCount.ToString(CultureInfo.InvariantCulture) +
                                          " | Proc=" + procCount.ToString(CultureInfo.InvariantCulture) +
                                          " | Local=" + localCount.ToString(CultureInfo.InvariantCulture));
                            foreach (PdbSymbolRecordInfo record in entry.Pdb.SymbolRecords.Take(10))
                            {
                                string name = string.IsNullOrWhiteSpace(record.Name) ? record.RecordTypeName : record.Name;
                                sb.AppendLine("      - [" + record.Kind + "] " + Safe(name));
                            }
                            if (entry.Pdb.SymbolRecords.Count > 10)
                            {
                                sb.AppendLine("      (truncated)");
                            }
                        }
                        if (!string.IsNullOrWhiteSpace(entry.Pdb.SymbolRecordNotes))
                        {
                            sb.AppendLine("    Symbol Notes: " + Safe(entry.Pdb.SymbolRecordNotes));
                        }
                        if (!string.IsNullOrWhiteSpace(entry.Pdb.Notes))
                        {
                            sb.AppendLine("    PDB Notes: " + Safe(entry.Pdb.Notes));
                        }
                    }
                    if (entry.Coff != null)
                    {
                        sb.AppendLine("    COFF: Symbols=" + entry.Coff.NumberOfSymbols.ToString(CultureInfo.InvariantCulture) +
                                      " | LineNumbers=" + entry.Coff.NumberOfLinenumbers.ToString(CultureInfo.InvariantCulture) +
                                      " | Code RVA: 0x" + entry.Coff.RvaToFirstByteOfCode.ToString("X8", CultureInfo.InvariantCulture) +
                                      "-0x" + entry.Coff.RvaToLastByteOfCode.ToString("X8", CultureInfo.InvariantCulture));
                    }
                    if (entry.Pogo != null)
                    {
                        sb.AppendLine("    POGO: " + Safe(entry.Pogo.Signature) +
                                      " | Entries: " + entry.Pogo.TotalEntryCount.ToString(CultureInfo.InvariantCulture) +
                                      (entry.Pogo.IsTruncated ? " (truncated)" : string.Empty));
                        foreach (DebugPogoEntryInfo pogo in entry.Pogo.Entries.Take(10))
                        {
                            sb.AppendLine("      - RVA: 0x" + pogo.Rva.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | Size: " + pogo.Size.ToString(CultureInfo.InvariantCulture) +
                                          " | " + Safe(pogo.Name));
                        }
                    }
                    if (entry.VcFeature != null)
                    {
                        string flags = entry.VcFeature.FlagNames.Count > 0
                            ? string.Join(", ", entry.VcFeature.FlagNames)
                            : "0x" + entry.VcFeature.Flags.ToString("X8", CultureInfo.InvariantCulture);
                        sb.AppendLine("    VC Feature Flags: " + flags);
                    }
                    if (entry.ExDllCharacteristics != null)
                    {
                        string flags = entry.ExDllCharacteristics.FlagNames.Count > 0
                            ? string.Join(", ", entry.ExDllCharacteristics.FlagNames)
                            : "0x" + entry.ExDllCharacteristics.Characteristics.ToString("X8", CultureInfo.InvariantCulture);
                        sb.AppendLine("    ExDllCharacteristics: " + flags);
                    }
                    if (entry.Fpo != null)
                    {
                        sb.AppendLine("    FPO Entries: " + entry.Fpo.TotalEntryCount.ToString(CultureInfo.InvariantCulture) +
                                      (entry.Fpo.IsTruncated ? " (truncated)" : string.Empty));
                        foreach (DebugFpoEntryInfo fpo in entry.Fpo.Entries.Take(5))
                        {
                            sb.AppendLine("      - Start: 0x" + fpo.StartOffset.ToString("X8", CultureInfo.InvariantCulture) +
                                          " | Size: " + fpo.ProcedureSize.ToString(CultureInfo.InvariantCulture) +
                                          " | Locals: " + fpo.LocalBytes.ToString(CultureInfo.InvariantCulture) +
                                          " | Params: " + fpo.ParameterBytes.ToString(CultureInfo.InvariantCulture) +
                                          " | Prolog: " + fpo.PrologSize.ToString(CultureInfo.InvariantCulture) +
                                          " | Regs: " + fpo.SavedRegisterCount.ToString(CultureInfo.InvariantCulture) +
                                          " | SEH: " + fpo.HasSeh +
                                          " | BP: " + fpo.UsesBasePointer);
                        }
                    }
                    if (entry.Borland != null)
                    {
                        sb.AppendLine("    Borland: Version=" + entry.Borland.Version.ToString(CultureInfo.InvariantCulture) +
                                      " | Flags=0x" + entry.Borland.Flags.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Offsets=" + entry.Borland.Offsets.Count.ToString(CultureInfo.InvariantCulture));
                        foreach (uint offset in entry.Borland.Offsets.Take(5))
                        {
                            sb.AppendLine("      - 0x" + offset.ToString("X8", CultureInfo.InvariantCulture));
                        }
                    }
                    if (entry.Reserved != null)
                    {
                        sb.AppendLine("    Reserved: Version=" + entry.Reserved.Version.ToString(CultureInfo.InvariantCulture) +
                                      " | Flags=0x" + entry.Reserved.Flags.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Offsets=" + entry.Reserved.Offsets.Count.ToString(CultureInfo.InvariantCulture));
                        foreach (uint offset in entry.Reserved.Offsets.Take(5))
                        {
                            sb.AppendLine("      - 0x" + offset.ToString("X8", CultureInfo.InvariantCulture));
                        }
                    }
                    if (entry.Fixup != null)
                    {
                        sb.AppendLine("    Fixup: " + entry.Fixup.DataLength.ToString(CultureInfo.InvariantCulture) +
                                      " bytes | " + entry.Fixup.Sha256);
                        if (!string.IsNullOrWhiteSpace(entry.Fixup.Preview))
                        {
                            sb.AppendLine("      Preview: " + entry.Fixup.Preview);
                        }
                    }
                    if (entry.Misc != null)
                    {
                        sb.AppendLine("    Misc: Type=" + entry.Misc.DataType.ToString(CultureInfo.InvariantCulture) +
                                      " | Unicode=" + entry.Misc.IsUnicode +
                                      " | Length=" + entry.Misc.Length.ToString(CultureInfo.InvariantCulture));
                        if (!string.IsNullOrWhiteSpace(entry.Misc.Data))
                        {
                            sb.AppendLine("      Data: " + entry.Misc.Data);
                        }
                    }
                    if (entry.OmapToSource != null)
                    {
                        sb.AppendLine("    OMAP To Src: " + entry.OmapToSource.TotalEntryCount.ToString(CultureInfo.InvariantCulture) +
                                      (entry.OmapToSource.IsTruncated ? " (truncated)" : string.Empty));
                        foreach (DebugOmapEntryInfo omap in entry.OmapToSource.Entries.Take(5))
                        {
                            sb.AppendLine("      - 0x" + omap.From.ToString("X8", CultureInfo.InvariantCulture) +
                                          " -> 0x" + omap.To.ToString("X8", CultureInfo.InvariantCulture));
                        }
                    }
                    if (entry.OmapFromSource != null)
                    {
                        sb.AppendLine("    OMAP From Src: " + entry.OmapFromSource.TotalEntryCount.ToString(CultureInfo.InvariantCulture) +
                                      (entry.OmapFromSource.IsTruncated ? " (truncated)" : string.Empty));
                        foreach (DebugOmapEntryInfo omap in entry.OmapFromSource.Entries.Take(5))
                        {
                            sb.AppendLine("      - 0x" + omap.From.ToString("X8", CultureInfo.InvariantCulture) +
                                          " -> 0x" + omap.To.ToString("X8", CultureInfo.InvariantCulture));
                        }
                    }
                    if (entry.Repro != null)
                    {
                        sb.AppendLine("    Repro: " + entry.Repro.DataLength.ToString(CultureInfo.InvariantCulture) +
                                      " bytes | " + entry.Repro.Hash);
                    }
                    if (entry.EmbeddedPortablePdb != null)
                    {
                        sb.AppendLine("    Embedded PDB: " + Safe(entry.EmbeddedPortablePdb.Signature) +
                                      " | Uncompressed: " + entry.EmbeddedPortablePdb.UncompressedSize.ToString(CultureInfo.InvariantCulture) +
                                      " | Compressed: " + entry.EmbeddedPortablePdb.CompressedSize.ToString(CultureInfo.InvariantCulture));
                        if (!string.IsNullOrWhiteSpace(entry.EmbeddedPortablePdb.PayloadHash))
                        {
                            sb.AppendLine("      Hash: " + entry.EmbeddedPortablePdb.PayloadHash);
                        }
                        if (!string.IsNullOrWhiteSpace(entry.EmbeddedPortablePdb.Notes))
                        {
                            sb.AppendLine("      Notes: " + Safe(entry.EmbeddedPortablePdb.Notes));
                        }
                    }
                    if (entry.Spgo != null)
                    {
                        sb.AppendLine("    SPGO: " + entry.Spgo.DataLength.ToString(CultureInfo.InvariantCulture) +
                                      " bytes | " + entry.Spgo.Hash);
                        if (!string.IsNullOrWhiteSpace(entry.Spgo.Preview))
                        {
                            sb.AppendLine("      Preview: " + entry.Spgo.Preview);
                        }
                    }
                    if (entry.PdbHash != null)
                    {
                        sb.AppendLine("    PDB Hash: " + Safe(entry.PdbHash.AlgorithmName) +
                                      " | " + entry.PdbHash.Hash);
                    }
                    if (entry.Iltcg != null)
                    {
                        sb.AppendLine("    ILTCG: " + entry.Iltcg.DataLength.ToString(CultureInfo.InvariantCulture) +
                                      " bytes | " + entry.Iltcg.Sha256);
                        if (!string.IsNullOrWhiteSpace(entry.Iltcg.Preview))
                        {
                            sb.AppendLine("      Preview: " + entry.Iltcg.Preview);
                        }
                    }
                    if (entry.Mpx != null)
                    {
                        sb.AppendLine("    MPX: " + entry.Mpx.DataLength.ToString(CultureInfo.InvariantCulture) +
                                      " bytes | " + entry.Mpx.Sha256);
                        if (!string.IsNullOrWhiteSpace(entry.Mpx.Preview))
                        {
                            sb.AppendLine("      Preview: " + entry.Mpx.Preview);
                        }
                    }
                    if (entry.Clsid != null)
                    {
                        sb.AppendLine("    CLSID: " + entry.Clsid.ClassId.ToString());
                    }
                    if (entry.Exception != null)
                    {
                        sb.AppendLine("    Exception: Entries=" + entry.Exception.EntryCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Aligned=" + entry.Exception.IsAligned.ToString(CultureInfo.InvariantCulture));
                        if (entry.Exception.SampleRvas.Count > 0)
                        {
                            sb.AppendLine("      Sample: " + string.Join(", ", entry.Exception.SampleRvas.Take(8)
                                .Select(value => "0x" + value.ToString("X8", CultureInfo.InvariantCulture))));
                        }
                    }
                    if (entry.Other != null)
                    {
                        sb.AppendLine("    Raw: " + entry.Other.DataLength.ToString(CultureInfo.InvariantCulture) +
                                      " bytes | " + entry.Other.Sha256);
                        if (!string.IsNullOrWhiteSpace(entry.Other.Preview))
                        {
                            sb.AppendLine("      Preview: " + entry.Other.Preview);
                        }
                    }
                }
            }
            sb.AppendLine();
            }

            if (filter.ShouldInclude("coff-symbols"))
            {
                sb.AppendLine("COFF Symbols:");
                if (pe.CoffSymbols.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    sb.AppendLine("  Count: " + pe.CoffSymbols.Length.ToString(CultureInfo.InvariantCulture));
                    foreach (CoffSymbolInfo symbol in pe.CoffSymbols.Take(100))
                    {
                        sb.AppendLine("  - [" + symbol.Index.ToString(CultureInfo.InvariantCulture) + "] " + Safe(symbol.Name) +
                                      " | Value: 0x" + symbol.Value.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Section: " + Safe(symbol.SectionName) +
                                      " (" + symbol.SectionNumber.ToString(CultureInfo.InvariantCulture) + ")" +
                                      " | Type: 0x" + symbol.Type.ToString("X4", CultureInfo.InvariantCulture) +
                                      (string.IsNullOrWhiteSpace(symbol.TypeName) ? string.Empty : " (" + Safe(symbol.TypeName) + ")") +
                                      " | StorageClass: " + symbol.StorageClass.ToString(CultureInfo.InvariantCulture) +
                                      (string.IsNullOrWhiteSpace(symbol.StorageClassName) ? string.Empty : " (" + Safe(symbol.StorageClassName) + ")") +
                                      " | Scope: " + Safe(symbol.ScopeName) +
                                      " | Aux: " + symbol.AuxSymbolCount.ToString(CultureInfo.InvariantCulture));
                    }
                    if (pe.CoffSymbols.Length > 100)
                    {
                        sb.AppendLine("  (truncated)");
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("coff-string-table"))
            {
                sb.AppendLine("COFF String Table:");
                if (pe.CoffStringTable.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    sb.AppendLine("  Count: " + pe.CoffStringTable.Length.ToString(CultureInfo.InvariantCulture));
                    foreach (CoffStringTableEntry entry in pe.CoffStringTable.Take(100))
                    {
                        sb.AppendLine("  - Offset: 0x" + entry.Offset.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | Value: " + Safe(entry.Value));
                    }
                    if (pe.CoffStringTable.Length > 100)
                    {
                        sb.AppendLine("  (truncated)");
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("coff-line-numbers"))
            {
                sb.AppendLine("COFF Line Numbers:");
                if (pe.CoffLineNumbers.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    sb.AppendLine("  Count: " + pe.CoffLineNumbers.Length.ToString(CultureInfo.InvariantCulture));
                    foreach (CoffLineNumberInfo entry in pe.CoffLineNumbers.Take(100))
                    {
                        string kind = entry.IsFunction ? "Function" : "Line";
                        string address = entry.IsFunction
                            ? "SymbolIndex: " + entry.SymbolIndex.ToString(CultureInfo.InvariantCulture)
                            : "Address: 0x" + entry.VirtualAddress.ToString("X8", CultureInfo.InvariantCulture);
                        sb.AppendLine("  - " + Safe(entry.SectionName) +
                                      " (" + entry.SectionIndex.ToString(CultureInfo.InvariantCulture) + ")" +
                                      " | " + kind +
                                      " | Line: " + entry.LineNumber.ToString(CultureInfo.InvariantCulture) +
                                      " | " + address +
                                      " | FileOffset: 0x" + entry.FileOffset.ToString("X8", CultureInfo.InvariantCulture));
                    }
                    if (pe.CoffLineNumbers.Length > 100)
                    {
                        sb.AppendLine("  (truncated)");
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("relocations"))
            {
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
                                  " | Entries: " + block.EntryCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Reserved: " + block.ReservedTypeCount.ToString(CultureInfo.InvariantCulture) +
                                  " | OutOfRange: " + block.OutOfRangeCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Unmapped: " + block.UnmappedCount.ToString(CultureInfo.InvariantCulture) +
                                  " | PageAligned: " + block.IsPageAligned);
                }

                if (pe.BaseRelocationSections.Length > 0)
                {
                    sb.AppendLine("  By Section:");
                    foreach (BaseRelocationSectionSummary summary in pe.BaseRelocationSections.OrderBy(s => s.SectionName, StringComparer.OrdinalIgnoreCase))
                    {
                        sb.AppendLine("    - " + Safe(summary.SectionName) +
                                      " | Blocks: " + summary.BlockCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Entries: " + summary.EntryCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Reserved: " + summary.ReservedTypeCount.ToString(CultureInfo.InvariantCulture) +
                                      " | OutOfRange: " + summary.OutOfRangeCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Unmapped: " + summary.UnmappedCount.ToString(CultureInfo.InvariantCulture));
                        if (summary.TopTypes.Count > 0)
                        {
                            string topTypes = string.Join(", ", summary.TopTypes.Select(t => t.Name + "=" + t.Count.ToString(CultureInfo.InvariantCulture)));
                            sb.AppendLine("      Top Types: " + topTypes);
                        }
                        if (summary.Samples.Count > 0)
                        {
                            string samples = string.Join(", ", summary.Samples.Select(s => "0x" + s.Rva.ToString("X8", CultureInfo.InvariantCulture) + ":" + s.TypeName));
                            sb.AppendLine("      Samples: " + samples);
                        }
                    }
                }

                if (pe.RelocationAnomalies != null)
                {
                    sb.AppendLine("  Anomalies: ZeroSized=" + pe.RelocationAnomalies.ZeroSizedBlockCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Empty=" + pe.RelocationAnomalies.EmptyBlockCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Invalid=" + pe.RelocationAnomalies.InvalidBlockCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Orphaned=" + pe.RelocationAnomalies.OrphanedBlockCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Discardable=" + pe.RelocationAnomalies.DiscardableBlockCount.ToString(CultureInfo.InvariantCulture) +
                                  " | ReservedEntries=" + pe.RelocationAnomalies.ReservedTypeCount.ToString(CultureInfo.InvariantCulture) +
                                  " | OutOfRangeEntries=" + pe.RelocationAnomalies.OutOfRangeEntryCount.ToString(CultureInfo.InvariantCulture) +
                                  " | UnmappedEntries=" + pe.RelocationAnomalies.UnmappedEntryCount.ToString(CultureInfo.InvariantCulture));
                }
            }
            sb.AppendLine();
            }

            if (filter.ShouldInclude("tls"))
            {
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
                if (pe.TlsInfo.IndexInfo != null)
                {
                    string section = string.IsNullOrWhiteSpace(pe.TlsInfo.IndexInfo.SectionName)
                        ? string.Empty
                        : " | Section: " + Safe(pe.TlsInfo.IndexInfo.SectionName) +
                          " (RVA: 0x" + pe.TlsInfo.IndexInfo.SectionRva.ToString("X8", CultureInfo.InvariantCulture) +
                          " | Offset: 0x" + pe.TlsInfo.IndexInfo.SectionOffset.ToString("X8", CultureInfo.InvariantCulture) + ")";
                    string value = pe.TlsInfo.IndexInfo.HasValue
                        ? " | Value: " + pe.TlsInfo.IndexInfo.Value.ToString(CultureInfo.InvariantCulture)
                        : string.Empty;
                    string notes = string.IsNullOrWhiteSpace(pe.TlsInfo.IndexInfo.Notes)
                        ? string.Empty
                        : " | Notes: " + Safe(pe.TlsInfo.IndexInfo.Notes);
                    sb.AppendLine("  Index: RVA 0x" + pe.TlsInfo.IndexInfo.Rva.ToString("X8", CultureInfo.InvariantCulture) +
                                  " | Mapped: " + pe.TlsInfo.IndexInfo.IsMapped +
                                  value +
                                  section +
                                  notes);
                }
                sb.AppendLine("  AddressOfCallbacks: 0x" + pe.TlsInfo.AddressOfCallbacks.ToString("X", CultureInfo.InvariantCulture));
                sb.AppendLine("  SizeOfZeroFill: " + pe.TlsInfo.SizeOfZeroFill.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  Characteristics: 0x" + pe.TlsInfo.Characteristics.ToString("X8", CultureInfo.InvariantCulture));
                sb.AppendLine("  RawDataSize: " + pe.TlsInfo.RawDataSize.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("  RawDataRva: 0x" + pe.TlsInfo.RawDataRva.ToString("X8", CultureInfo.InvariantCulture));
                sb.AppendLine("  RawDataMapped: " + pe.TlsInfo.RawDataMapped.ToString(CultureInfo.InvariantCulture));
                if (!string.IsNullOrWhiteSpace(pe.TlsInfo.RawDataSectionName))
                {
                    sb.AppendLine("  RawDataSection: " + Safe(pe.TlsInfo.RawDataSectionName));
                }
                if (!string.IsNullOrWhiteSpace(pe.TlsInfo.RawDataSha256))
                {
                    sb.AppendLine("  RawDataSha256: " + Safe(pe.TlsInfo.RawDataSha256));
                }
                if (!string.IsNullOrWhiteSpace(pe.TlsInfo.RawDataPreview))
                {
                    sb.AppendLine("  RawDataPreview: " + pe.TlsInfo.RawDataPreview);
                }
                if (pe.TlsInfo.Template != null)
                {
                    sb.AppendLine("  TemplateRawSize: " + pe.TlsInfo.Template.RawDataSize.ToString(CultureInfo.InvariantCulture) +
                                  " | ZeroFill: " + pe.TlsInfo.Template.ZeroFillSize.ToString(CultureInfo.InvariantCulture) +
                                  " | Total: " + pe.TlsInfo.Template.TotalSize.ToString(CultureInfo.InvariantCulture));
                    if (pe.TlsInfo.Template.RangeValid)
                    {
                        sb.AppendLine("  TemplateRange: " + pe.TlsInfo.Template.RangeSize.ToString(CultureInfo.InvariantCulture) +
                                      " | MatchesRaw: " + pe.TlsInfo.Template.SizeMatchesRange.ToString(CultureInfo.InvariantCulture) +
                                      " | Aligned: " + pe.TlsInfo.Template.IsAligned.ToString(CultureInfo.InvariantCulture));
                    }
                    if (!string.IsNullOrWhiteSpace(pe.TlsInfo.Template.Notes))
                    {
                        sb.AppendLine("  TemplateNotes: " + Safe(pe.TlsInfo.Template.Notes));
                    }
                }
                if (pe.TlsInfo.AlignmentBytes > 0)
                {
                    sb.AppendLine("  AlignmentBytes: " + pe.TlsInfo.AlignmentBytes.ToString(CultureInfo.InvariantCulture));
                }
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

                        if (!string.IsNullOrWhiteSpace(callback.SectionName))
                        {
                            line += " | Section: " + callback.SectionName;
                            if (callback.SectionOffset != 0)
                            {
                                line += "+0x" + callback.SectionOffset.ToString("X", CultureInfo.InvariantCulture);
                            }
                        }

                        if (!string.IsNullOrWhiteSpace(callback.ResolutionSource))
                        {
                            line += " | Resolved: " + callback.ResolutionSource;
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
            }

            if (filter.ShouldInclude("load-config"))
            {
                sb.AppendLine("Load Config:");
                if (pe.LoadConfig == null)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    sb.AppendLine("  Size: " + pe.LoadConfig.Size.ToString(CultureInfo.InvariantCulture));
                    if (pe.LoadConfig.VersionInfo != null)
                    {
                        sb.AppendLine("  Layout: " + Safe(pe.LoadConfig.VersionInfo.VersionHint) +
                                      " | Parsed: " + pe.LoadConfig.VersionInfo.ParsedBytes.ToString(CultureInfo.InvariantCulture) +
                                      " | Trailing: " + pe.LoadConfig.VersionInfo.TrailingBytes.ToString(CultureInfo.InvariantCulture) +
                                      " | Truncated: " + pe.LoadConfig.VersionInfo.IsTruncated.ToString(CultureInfo.InvariantCulture));
                        if (pe.LoadConfig.VersionInfo.FieldGroups.Count > 0)
                        {
                            sb.AppendLine("  Field Groups: " + string.Join(", ", pe.LoadConfig.VersionInfo.FieldGroups));
                        }
                        if (pe.LoadConfig.VersionInfo.TrailingBytes > 0)
                        {
                            sb.AppendLine("  Trailing Preview: " + pe.LoadConfig.VersionInfo.TrailingPreview);
                        }
                    }
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
                    if (pe.LoadConfig.CodeIntegrity != null)
                    {
                        sb.AppendLine("  Code Integrity:");
                        sb.AppendLine("    Flags: 0x" + pe.LoadConfig.CodeIntegrity.Flags.ToString("X4", CultureInfo.InvariantCulture));
                        if (pe.LoadConfig.CodeIntegrity.FlagNames.Count > 0)
                        {
                            sb.AppendLine("    Flag Names: " + string.Join(", ", pe.LoadConfig.CodeIntegrity.FlagNames));
                        }
                        sb.AppendLine("    Catalog: " + pe.LoadConfig.CodeIntegrity.Catalog.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    CatalogOffset: 0x" + pe.LoadConfig.CodeIntegrity.CatalogOffset.ToString("X8", CultureInfo.InvariantCulture));
                    }

                    sb.AppendLine("  SecurityCookie: 0x" + pe.LoadConfig.SecurityCookie.ToString("X", CultureInfo.InvariantCulture));
                    sb.AppendLine("  SEHandlerCount: " + pe.LoadConfig.SeHandlerCount.ToString(CultureInfo.InvariantCulture));
                    if (pe.LoadConfig.SehHandlerTable != null)
                    {
                        sb.AppendLine("  SEH Handler Table: 0x" + pe.LoadConfig.SehHandlerTable.TableAddress.ToString("X", CultureInfo.InvariantCulture) +
                                      " | Entries: " + pe.LoadConfig.SehHandlerTable.HandlerCount.ToString(CultureInfo.InvariantCulture));
                        if (!string.IsNullOrWhiteSpace(pe.LoadConfig.SehHandlerTable.SectionName))
                        {
                            sb.AppendLine("    Section: " + Safe(pe.LoadConfig.SehHandlerTable.SectionName));
                        }
                        if (pe.LoadConfig.SehHandlerTable.HandlerRvas.Count > 0)
                        {
                            sb.AppendLine("    Sample: " + string.Join(", ", pe.LoadConfig.SehHandlerTable.HandlerRvas.Take(10)
                                .Select(rva => "0x" + rva.ToString("X8", CultureInfo.InvariantCulture))));
                        }
                        if (pe.LoadConfig.SehHandlerTable.Entries.Count > 0)
                        {
                            sb.AppendLine("    Entries:");
                            foreach (SehHandlerEntryInfo entry in pe.LoadConfig.SehHandlerTable.Entries.Take(10))
                            {
                                string line = "      - 0x" + entry.Rva.ToString("X8", CultureInfo.InvariantCulture);
                                if (!string.IsNullOrWhiteSpace(entry.SectionName))
                                {
                                    line += " | Section: " + Safe(entry.SectionName);
                                }
                                if (!string.IsNullOrWhiteSpace(entry.SymbolName))
                                {
                                    line += " | Symbol: " + Safe(entry.SymbolName);
                                }
                                if (!string.IsNullOrWhiteSpace(entry.ResolutionSource))
                                {
                                    line += " | Resolved: " + Safe(entry.ResolutionSource);
                                }
                                sb.AppendLine(line);
                            }
                        }
                    }
                    sb.AppendLine("  GuardFlags: 0x" + pe.LoadConfig.GuardFlags.ToString("X8", CultureInfo.InvariantCulture));
                    if (pe.LoadConfig.GuardFlagsInfo != null && pe.LoadConfig.GuardFlagsInfo.Flags.Count > 0)
                    {
                        sb.AppendLine("  Guard Flags Decoded:");
                        foreach (string flag in pe.LoadConfig.GuardFlagsInfo.Flags)
                        {
                            sb.AppendLine("    - " + flag);
                        }
                    }

                    AppendGuardRvaTableInfo(sb, pe.LoadConfig.GuardCfFunctionTableInfo, "  Guard CF Function Table:");
                    AppendGuardRvaTableInfo(sb, pe.LoadConfig.GuardAddressTakenIatTable, "  Guard Address Taken IAT Table:");
                    AppendGuardRvaTableInfo(sb, pe.LoadConfig.GuardLongJumpTargetTable, "  Guard Long Jump Target Table:");

                    if (pe.LoadConfig.ChpeMetadataPointer != 0)
                    {
                        sb.AppendLine("  CHPE Metadata Pointer: 0x" + pe.LoadConfig.ChpeMetadataPointer.ToString("X", CultureInfo.InvariantCulture));
                    }

                    if (pe.LoadConfig.DynamicValueRelocTable != 0)
                    {
                        sb.AppendLine("  Dynamic Value Reloc Table: 0x" + pe.LoadConfig.DynamicValueRelocTable.ToString("X", CultureInfo.InvariantCulture));
                        if (pe.LoadConfig.DynamicValueRelocTableOffset != 0 || pe.LoadConfig.DynamicValueRelocTableSection != 0)
                        {
                            sb.AppendLine("  Dynamic Value Reloc Offset: 0x" + pe.LoadConfig.DynamicValueRelocTableOffset.ToString("X", CultureInfo.InvariantCulture) +
                                          " | Section Index: " + pe.LoadConfig.DynamicValueRelocTableSection.ToString(CultureInfo.InvariantCulture));
                        }
                    }

                    if (pe.LoadConfig.GuardRFFailureRoutine != 0 || pe.LoadConfig.GuardRFFailureRoutineFunctionPointer != 0)
                    {
                        sb.AppendLine("  GuardRF Failure Routine: 0x" + pe.LoadConfig.GuardRFFailureRoutine.ToString("X", CultureInfo.InvariantCulture));
                        sb.AppendLine("  GuardRF Failure Routine FP: 0x" + pe.LoadConfig.GuardRFFailureRoutineFunctionPointer.ToString("X", CultureInfo.InvariantCulture));
                    }

                    if (pe.LoadConfig.GuardRFVerifyStackPointerFunctionPointer != 0)
                    {
                        sb.AppendLine("  GuardRF Verify Stack Pointer FP: 0x" + pe.LoadConfig.GuardRFVerifyStackPointerFunctionPointer.ToString("X", CultureInfo.InvariantCulture));
                    }

                    if (pe.LoadConfig.HotPatchTableOffset != 0)
                    {
                        sb.AppendLine("  HotPatch Table Offset: 0x" + pe.LoadConfig.HotPatchTableOffset.ToString("X", CultureInfo.InvariantCulture));
                    }

                    if (pe.LoadConfig.EnclaveConfigurationPointer != 0)
                    {
                        sb.AppendLine("  Enclave Configuration Pointer: 0x" + pe.LoadConfig.EnclaveConfigurationPointer.ToString("X", CultureInfo.InvariantCulture));
                    }
                    if (pe.LoadConfig.EnclaveConfiguration != null)
                    {
                        EnclaveConfigurationInfo enclave = pe.LoadConfig.EnclaveConfiguration;
                        sb.AppendLine("  Enclave Configuration:");
                        sb.AppendLine("    Size: " + enclave.Size.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    MinRequiredSize: " + enclave.MinimumRequiredConfigSize.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    PolicyFlags: 0x" + enclave.PolicyFlags.ToString("X8", CultureInfo.InvariantCulture));
                        if (enclave.PolicyFlagNames.Count > 0)
                        {
                            sb.AppendLine("    Policy Flags: " + string.Join(", ", enclave.PolicyFlagNames));
                        }
                        sb.AppendLine("    Imports: " + enclave.NumberOfImports.ToString(CultureInfo.InvariantCulture) +
                                      " | ImportListRVA: 0x" + enclave.ImportListRva.ToString("X8", CultureInfo.InvariantCulture) +
                                      " | EntrySize: " + enclave.ImportEntrySize.ToString(CultureInfo.InvariantCulture));
                        if (enclave.Imports.Count > 0)
                        {
                            sb.AppendLine("    Import Entries:");
                            foreach (EnclaveImportInfo import in enclave.Imports.Take(10))
                            {
                                sb.AppendLine("      - [" + import.Index.ToString(CultureInfo.InvariantCulture) + "] " +
                                              Safe(import.MatchTypeName) +
                                              " | MinSV: " + import.MinimumSecurityVersion.ToString(CultureInfo.InvariantCulture) +
                                              " | Name: " + Safe(import.ImportName));
                                if (!string.IsNullOrWhiteSpace(import.UniqueOrAuthorId))
                                {
                                    sb.AppendLine("        Unique/Author: " + import.UniqueOrAuthorId);
                                }
                                if (!string.IsNullOrWhiteSpace(import.FamilyId))
                                {
                                    sb.AppendLine("        FamilyId: " + import.FamilyId);
                                }
                                if (!string.IsNullOrWhiteSpace(import.ImageId))
                                {
                                    sb.AppendLine("        ImageId: " + import.ImageId);
                                }
                            }

                            if (enclave.Imports.Count > 10)
                            {
                                sb.AppendLine("      (truncated)");
                            }
                        }
                        if (!string.IsNullOrWhiteSpace(enclave.FamilyId))
                        {
                            sb.AppendLine("    FamilyId: " + enclave.FamilyId);
                        }
                        if (!string.IsNullOrWhiteSpace(enclave.ImageId))
                        {
                            sb.AppendLine("    ImageId: " + enclave.ImageId);
                        }
                        sb.AppendLine("    ImageVersion: " + enclave.ImageVersion.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    SecurityVersion: " + enclave.SecurityVersion.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    EnclaveSize: " + enclave.EnclaveSize.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    Threads: " + enclave.NumberOfThreads.ToString(CultureInfo.InvariantCulture));
                        sb.AppendLine("    EnclaveFlags: 0x" + enclave.EnclaveFlags.ToString("X8", CultureInfo.InvariantCulture));
                        if (enclave.EnclaveFlagNames.Count > 0)
                        {
                            sb.AppendLine("    Enclave Flags: " + string.Join(", ", enclave.EnclaveFlagNames));
                        }
                        if (!string.IsNullOrWhiteSpace(enclave.SectionName))
                        {
                            sb.AppendLine("    Section: " + enclave.SectionName);
                        }
                    }

                    if (pe.LoadConfig.VolatileMetadataPointer != 0)
                    {
                        sb.AppendLine("  Volatile Metadata Pointer: 0x" + pe.LoadConfig.VolatileMetadataPointer.ToString("X", CultureInfo.InvariantCulture));
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

                    if (pe.LoadConfig.GuardFeatureMatrix != null && pe.LoadConfig.GuardFeatureMatrix.Count > 0)
                    {
                        sb.AppendLine("  Guard Feature Matrix:");
                        foreach (GuardFeatureInfo feature in pe.LoadConfig.GuardFeatureMatrix)
                        {
                            sb.AppendLine("    - " + Safe(feature.Feature) +
                                          " | Enabled: " + feature.Enabled +
                                          " | Table: " + feature.HasTable +
                                          " | Pointer: " + feature.HasPointer +
                                          (string.IsNullOrWhiteSpace(feature.Notes) ? string.Empty : " | " + Safe(feature.Notes)));
                        }
                    }

                    if (pe.LoadConfig.GuardTableSanity != null && pe.LoadConfig.GuardTableSanity.Count > 0)
                    {
                        sb.AppendLine("  Guard Table Sanity:");
                        foreach (GuardTableSanityInfo info in pe.LoadConfig.GuardTableSanity)
                        {
                            sb.AppendLine("    - " + Safe(info.Name) +
                                          " | Pointer: " + info.PointerPresent +
                                          " | Count: " + info.CountPresent +
                                          " | Mapped: " + info.MappedToSection +
                                          " | SizeFits: " + info.SizeFits);
                            if (!string.IsNullOrWhiteSpace(info.SectionName))
                            {
                                sb.AppendLine("      Section: " + Safe(info.SectionName) +
                                              " (RVA 0x" + info.SectionRva.ToString("X8", CultureInfo.InvariantCulture) +
                                              ", Size " + info.SectionSize.ToString(CultureInfo.InvariantCulture) + ")");
                            }
                            if (info.EstimatedSize > 0)
                            {
                                sb.AppendLine("      Estimated Size: " + info.EstimatedSize.ToString(CultureInfo.InvariantCulture));
                            }
                            if (!string.IsNullOrWhiteSpace(info.Notes))
                            {
                                sb.AppendLine("      Notes: " + Safe(info.Notes));
                            }
                        }
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("rich-header"))
            {
                sb.AppendLine("Rich Header:");
                if (pe.RichHeader == null || pe.RichHeader.Entries.Count == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    sb.AppendLine("  Key: 0x" + pe.RichHeader.Key.ToString("X8", CultureInfo.InvariantCulture));
                    if (pe.RichHeader.Toolchains.Count > 0)
                    {
                        sb.AppendLine("  Toolchains:");
                        foreach (RichToolchainInfo toolchain in pe.RichHeader.Toolchains)
                        {
                            sb.AppendLine("    - " + Safe(toolchain.Name) +
                                          " | Version: " + Safe(toolchain.Version) +
                                          " | Count: " + toolchain.TotalCount.ToString(CultureInfo.InvariantCulture));
                            if (toolchain.Tools.Count > 0)
                            {
                                sb.AppendLine("      Tools: " + string.Join(", ", toolchain.Tools));
                            }
                        }
                    }
                    foreach (RichHeaderEntry entry in pe.RichHeader.Entries)
                    {
                        sb.AppendLine("  - Product: " + entry.ProductId.ToString(CultureInfo.InvariantCulture) +
                                      " (" + Safe(entry.ProductName) + ")" +
                                      " | Build: " + entry.BuildNumber.ToString(CultureInfo.InvariantCulture) +
                                      " | Toolchain: " + Safe(entry.ToolchainVersion) +
                                      " | Count: " + entry.Count.ToString(CultureInfo.InvariantCulture));
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("version-info-details"))
            {
                sb.AppendLine("Version Info Details:");
                if (pe.VersionInfoDetails == null)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    sb.AppendLine("  FixedFileInfo Signature: 0x" + pe.VersionInfoDetails.FixedFileInfoSignature.ToString("X8", CultureInfo.InvariantCulture));
                    sb.AppendLine("  Signature Valid: " + pe.VersionInfoDetails.FixedFileInfoSignatureValid);
                    if (pe.VersionInfoDetails.ResourceLength > 0)
                    {
                        sb.AppendLine("  Resource Header: Length=" + pe.VersionInfoDetails.ResourceLength.ToString(CultureInfo.InvariantCulture) +
                                      " | ValueLength=" + pe.VersionInfoDetails.ResourceValueLength.ToString(CultureInfo.InvariantCulture) +
                                      " | Type=" + pe.VersionInfoDetails.ResourceType.ToString(CultureInfo.InvariantCulture) +
                                      " | Key=" + Safe(pe.VersionInfoDetails.ResourceKey));
                        if (pe.VersionInfoDetails.ExtraDataBytes > 0)
                        {
                            sb.AppendLine("  Resource Extra: " + pe.VersionInfoDetails.ExtraDataBytes.ToString(CultureInfo.InvariantCulture) +
                                          " | Preview=" + pe.VersionInfoDetails.ExtraDataPreview);
                        }
                    }
                    if (pe.VersionInfoDetails.FixedFileInfo != null)
                    {
                        sb.AppendLine("  Fixed File Info:");
                        sb.AppendLine("    FileVersion: " + Safe(pe.VersionInfoDetails.FixedFileInfo.FileVersion));
                        sb.AppendLine("    ProductVersion: " + Safe(pe.VersionInfoDetails.FixedFileInfo.ProductVersion));
                        sb.AppendLine("    FileFlags: 0x" + pe.VersionInfoDetails.FixedFileInfo.FileFlags.ToString("X8", CultureInfo.InvariantCulture));
                        if (pe.VersionInfoDetails.FixedFileInfo.FileFlagNames.Count > 0)
                        {
                            sb.AppendLine("    FileFlags Names: " + string.Join(", ", pe.VersionInfoDetails.FixedFileInfo.FileFlagNames));
                        }
                        sb.AppendLine("    FileOS: 0x" + pe.VersionInfoDetails.FixedFileInfo.FileOs.ToString("X8", CultureInfo.InvariantCulture));
                        if (!string.IsNullOrWhiteSpace(pe.VersionInfoDetails.FixedFileInfo.FileOsName))
                        {
                            sb.AppendLine("    FileOS Name: " + pe.VersionInfoDetails.FixedFileInfo.FileOsName);
                        }
                        sb.AppendLine("    FileType: 0x" + pe.VersionInfoDetails.FixedFileInfo.FileType.ToString("X8", CultureInfo.InvariantCulture));
                        if (!string.IsNullOrWhiteSpace(pe.VersionInfoDetails.FixedFileInfo.FileTypeName))
                        {
                            sb.AppendLine("    FileType Name: " + pe.VersionInfoDetails.FixedFileInfo.FileTypeName);
                        }
                        if (!string.IsNullOrWhiteSpace(pe.VersionInfoDetails.FixedFileInfo.FileSubtypeName))
                        {
                            sb.AppendLine("    FileSubtype Name: " + pe.VersionInfoDetails.FixedFileInfo.FileSubtypeName);
                        }
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
            }

            if (filter.ShouldInclude("icon-groups"))
            {
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
                                  " | Type: " + group.HeaderType.ToString(CultureInfo.InvariantCulture) +
                                  " | Reserved: " + group.HeaderReserved.ToString(CultureInfo.InvariantCulture) +
                                  " | Entries: " + group.Entries.Count.ToString(CultureInfo.InvariantCulture) +
                                  " | IcoBytes: " + group.IcoData.Length.ToString(CultureInfo.InvariantCulture));
                    if (group.EntrySize != 14 || !group.HeaderValid || group.EntriesTruncated)
                    {
                        sb.AppendLine("    Header: EntrySize=" + group.EntrySize.ToString(CultureInfo.InvariantCulture) +
                                      " | Declared: " + group.DeclaredEntryCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Valid: " + group.HeaderValid +
                                      " | Truncated: " + group.EntriesTruncated);
                    }
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
            }

            if (filter.ShouldInclude("resource-icons"))
            {
            sb.AppendLine("Resource Icons:");
            if (pe.ResourceIcons.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceIconInfo icon in pe.ResourceIcons.OrderBy(i => i.NameId).ThenBy(i => i.LanguageId))
                {
                    string line = "  - Id#" + icon.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + icon.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Size: " + icon.Width.ToString(CultureInfo.InvariantCulture) +
                                  "x" + icon.Height.ToString(CultureInfo.InvariantCulture) +
                                  " | Bits: " + icon.BitCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Bytes: " + icon.Size.ToString(CultureInfo.InvariantCulture);
                    if (icon.IsPng)
                    {
                        line += " | PNG: " + icon.PngWidth.ToString(CultureInfo.InvariantCulture) +
                                "x" + icon.PngHeight.ToString(CultureInfo.InvariantCulture);
                    }
                    sb.AppendLine(line);
                }
            }
            sb.AppendLine();
            }

            if (filter.ShouldInclude("cursor-groups"))
            {
            sb.AppendLine("Cursor Groups:");
            if (pe.ResourceCursorGroups.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceCursorGroupInfo group in pe.ResourceCursorGroups.OrderBy(g => g.NameId).ThenBy(g => g.LanguageId))
                {
                    sb.AppendLine("  Group: Id#" + group.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + group.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Type: " + group.HeaderType.ToString(CultureInfo.InvariantCulture) +
                                  " | Reserved: " + group.HeaderReserved.ToString(CultureInfo.InvariantCulture) +
                                  " | Entries: " + group.Entries.Count.ToString(CultureInfo.InvariantCulture));
                    if (group.EntrySize != 14 || !group.HeaderValid || group.EntriesTruncated)
                    {
                        sb.AppendLine("    Header: EntrySize=" + group.EntrySize.ToString(CultureInfo.InvariantCulture) +
                                      " | Declared: " + group.DeclaredEntryCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Valid: " + group.HeaderValid +
                                      " | Truncated: " + group.EntriesTruncated);
                    }
                    foreach (ResourceCursorEntryInfo entry in group.Entries.Take(10))
                    {
                        string line = "    - " + entry.Width.ToString(CultureInfo.InvariantCulture) +
                                      "x" + entry.Height.ToString(CultureInfo.InvariantCulture) +
                                      " | Hotspot: " + entry.HotspotX.ToString(CultureInfo.InvariantCulture) +
                                      "," + entry.HotspotY.ToString(CultureInfo.InvariantCulture) +
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
            sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-cursors"))
            {
            sb.AppendLine("Resource Cursors:");
            if (pe.ResourceCursors.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceCursorInfo cursor in pe.ResourceCursors.OrderBy(c => c.NameId).ThenBy(c => c.LanguageId))
                {
                    string line = "  - Id#" + cursor.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + cursor.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Hotspot: " + cursor.HotspotX.ToString(CultureInfo.InvariantCulture) +
                                  "," + cursor.HotspotY.ToString(CultureInfo.InvariantCulture) +
                                  " | Size: " + cursor.Width.ToString(CultureInfo.InvariantCulture) +
                                  "x" + cursor.Height.ToString(CultureInfo.InvariantCulture) +
                                  " | Bits: " + cursor.BitCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Bytes: " + cursor.Size.ToString(CultureInfo.InvariantCulture);
                    if (cursor.IsPng)
                    {
                        line += " | PNG: " + cursor.PngWidth.ToString(CultureInfo.InvariantCulture) +
                                "x" + cursor.PngHeight.ToString(CultureInfo.InvariantCulture);
                    }
                    sb.AppendLine(line);
                }
            }
            sb.AppendLine();
            }

            if (filter.ShouldInclude("bitmaps"))
            {
            sb.AppendLine("Bitmaps:");
            if (pe.ResourceBitmaps.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceBitmapInfo bitmap in pe.ResourceBitmaps.OrderBy(b => b.NameId).ThenBy(b => b.LanguageId))
                {
                    sb.AppendLine("  - Id#" + bitmap.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + bitmap.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Size: " + bitmap.Width.ToString(CultureInfo.InvariantCulture) +
                                  "x" + bitmap.Height.ToString(CultureInfo.InvariantCulture) +
                                  " | Bits: " + bitmap.BitCount.ToString(CultureInfo.InvariantCulture) +
                                  " | Compression: " + bitmap.CompressionName);
                }
            }
            sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-fonts"))
            {
                sb.AppendLine("Resource Fonts:");
                if (pe.ResourceFonts.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    foreach (ResourceFontInfo font in pe.ResourceFonts.OrderBy(f => f.NameId).ThenBy(f => f.LanguageId))
                    {
                        sb.AppendLine("  - Id#" + font.NameId.ToString(CultureInfo.InvariantCulture) +
                                      " | Lang: 0x" + font.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                      " | Size: " + font.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | Format: " + Safe(font.Format) +
                                      (string.IsNullOrWhiteSpace(font.FaceName) ? string.Empty : " | Face: " + font.FaceName));
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-fontdirs"))
            {
                sb.AppendLine("Resource Font Directories:");
                if (pe.ResourceFontDirectories.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    foreach (ResourceFontDirInfo dir in pe.ResourceFontDirectories.OrderBy(d => d.NameId).ThenBy(d => d.LanguageId))
                    {
                        sb.AppendLine("  - Id#" + dir.NameId.ToString(CultureInfo.InvariantCulture) +
                                      " | Lang: 0x" + dir.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                      " | Fonts: " + dir.FontCount.ToString(CultureInfo.InvariantCulture));
                        foreach (ResourceFontDirEntryInfo entry in dir.Entries.Take(10))
                        {
                            sb.AppendLine("    - Ordinal: " + entry.Ordinal.ToString(CultureInfo.InvariantCulture) +
                                          (string.IsNullOrWhiteSpace(entry.FaceName) ? string.Empty : " | Face: " + entry.FaceName));
                        }
                        if (dir.Entries.Count > 10)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-dlginit"))
            {
                sb.AppendLine("Resource DlgInit:");
                if (pe.ResourceDlgInit.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    foreach (ResourceDlgInitInfo init in pe.ResourceDlgInit.OrderBy(d => d.NameId).ThenBy(d => d.LanguageId))
                    {
                        sb.AppendLine("  - Id#" + init.NameId.ToString(CultureInfo.InvariantCulture) +
                                      " | Lang: 0x" + init.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                      " | Entries: " + init.Entries.Count.ToString(CultureInfo.InvariantCulture));
                        foreach (ResourceDlgInitEntryInfo entry in init.Entries.Take(10))
                        {
                            sb.AppendLine("    - Control: " + entry.ControlId.ToString(CultureInfo.InvariantCulture) +
                                          " | Msg: 0x" + entry.Message.ToString("X4", CultureInfo.InvariantCulture) +
                                          " | Len: " + entry.DataLength.ToString(CultureInfo.InvariantCulture) +
                                          (string.IsNullOrWhiteSpace(entry.DataPreview) ? string.Empty : " | " + entry.DataPreview));
                        }
                        if (init.Entries.Count > 10)
                        {
                            sb.AppendLine("    (truncated)");
                        }
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-animated-cursors"))
            {
                sb.AppendLine("Resource Animated Cursors:");
                if (pe.ResourceAnimatedCursors.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    foreach (ResourceAnimatedInfo info in pe.ResourceAnimatedCursors.OrderBy(i => i.NameId).ThenBy(i => i.LanguageId))
                    {
                        sb.AppendLine("  - Id#" + info.NameId.ToString(CultureInfo.InvariantCulture) +
                                      " | Lang: 0x" + info.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                      " | Frames: " + info.FrameCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Steps: " + info.StepCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Size: " + info.Width.ToString(CultureInfo.InvariantCulture) + "x" + info.Height.ToString(CultureInfo.InvariantCulture) +
                                      " | Bits: " + info.BitCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Planes: " + info.Planes.ToString(CultureInfo.InvariantCulture));
                        if (info.ChunkTypes.Count > 0)
                        {
                            sb.AppendLine("    Chunks: " + string.Join(", ", info.ChunkTypes));
                        }
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-animated-icons"))
            {
                sb.AppendLine("Resource Animated Icons:");
                if (pe.ResourceAnimatedIcons.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    foreach (ResourceAnimatedInfo info in pe.ResourceAnimatedIcons.OrderBy(i => i.NameId).ThenBy(i => i.LanguageId))
                    {
                        sb.AppendLine("  - Id#" + info.NameId.ToString(CultureInfo.InvariantCulture) +
                                      " | Lang: 0x" + info.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                      " | Frames: " + info.FrameCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Steps: " + info.StepCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Size: " + info.Width.ToString(CultureInfo.InvariantCulture) + "x" + info.Height.ToString(CultureInfo.InvariantCulture));
                        if (info.ChunkTypes.Count > 0)
                        {
                            sb.AppendLine("    Chunks: " + string.Join(", ", info.ChunkTypes));
                        }
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-rcdata"))
            {
            sb.AppendLine("Resource RCDATA:");
            if (pe.ResourceRcData.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
                else
                {
                    foreach (ResourceRcDataInfo info in pe.ResourceRcData.OrderBy(r => r.NameId).ThenBy(r => r.LanguageId))
                    {
                        sb.AppendLine("  - Id#" + info.NameId.ToString(CultureInfo.InvariantCulture) +
                                      " | Lang: 0x" + info.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                      " | Size: " + info.Size.ToString(CultureInfo.InvariantCulture) +
                                      " | Text: " + info.IsText +
                                      " | Format: " + Safe(info.Format) +
                                      " | Entropy: " + info.Entropy.ToString("F3", CultureInfo.InvariantCulture));
                        if (!string.IsNullOrWhiteSpace(info.FormatDetails))
                        {
                            sb.AppendLine("    Format Details: " + Safe(info.FormatDetails));
                        }
                        if (!string.IsNullOrWhiteSpace(info.TextPreview))
                        {
                            sb.AppendLine("    Preview: " + info.TextPreview);
                        }
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("resources"))
            {
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

            sb.AppendLine("Resource HTML:");
            if (pe.ResourceHtml.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceRawInfo info in pe.ResourceHtml.Take(10))
                {
                    sb.AppendLine("  - Id#" + info.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + info.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Size: " + info.Size.ToString(CultureInfo.InvariantCulture) +
                                  " | Text: " + info.IsText);
                    if (!string.IsNullOrWhiteSpace(info.Preview))
                    {
                        sb.AppendLine("    Preview: " + info.Preview);
                    }
                }
                if (pe.ResourceHtml.Length > 10)
                {
                    sb.AppendLine("  (truncated)");
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resource DLGINCLUDE:");
            if (pe.ResourceDlgInclude.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceRawInfo info in pe.ResourceDlgInclude.Take(10))
                {
                    sb.AppendLine("  - Id#" + info.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + info.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Size: " + info.Size.ToString(CultureInfo.InvariantCulture) +
                                  " | Text: " + info.IsText);
                    if (!string.IsNullOrWhiteSpace(info.Preview))
                    {
                        sb.AppendLine("    Preview: " + info.Preview);
                    }
                }
                if (pe.ResourceDlgInclude.Length > 10)
                {
                    sb.AppendLine("  (truncated)");
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resource PLUGPLAY:");
            if (pe.ResourcePlugAndPlay.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceRawInfo info in pe.ResourcePlugAndPlay.Take(10))
                {
                    sb.AppendLine("  - Id#" + info.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + info.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Size: " + info.Size.ToString(CultureInfo.InvariantCulture) +
                                  " | Text: " + info.IsText);
                    if (!string.IsNullOrWhiteSpace(info.Preview))
                    {
                        sb.AppendLine("    Preview: " + info.Preview);
                    }
                }
                if (pe.ResourcePlugAndPlay.Length > 10)
                {
                    sb.AppendLine("  (truncated)");
                }
            }
            sb.AppendLine();

            sb.AppendLine("Resource VXD:");
            if (pe.ResourceVxd.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceRawInfo info in pe.ResourceVxd.Take(10))
                {
                    sb.AppendLine("  - Id#" + info.NameId.ToString(CultureInfo.InvariantCulture) +
                                  " | Lang: 0x" + info.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                  " | Size: " + info.Size.ToString(CultureInfo.InvariantCulture) +
                                  " | Text: " + info.IsText);
                    if (!string.IsNullOrWhiteSpace(info.Preview))
                    {
                        sb.AppendLine("    Preview: " + info.Preview);
                    }
                }
                if (pe.ResourceVxd.Length > 10)
                {
                    sb.AppendLine("  (truncated)");
                }
            }
            sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-string-tables"))
            {
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
            }

            if (filter.ShouldInclude("resource-string-coverage"))
            {
                sb.AppendLine("Resource String Coverage:");
                if (pe.ResourceStringCoverage.Length == 0)
                {
                    sb.AppendLine("  (none)");
                }
                else
                {
                    foreach (ResourceStringCoverageInfo coverage in pe.ResourceStringCoverage.OrderBy(c => c.LanguageId))
                    {
                        sb.AppendLine("  - Lang: 0x" + coverage.LanguageId.ToString("X4", CultureInfo.InvariantCulture) +
                                      " (" + Safe(coverage.CultureName) + ")" +
                                      " | Blocks: " + coverage.BlockCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Strings: " + coverage.StringCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Missing: " + coverage.MissingBlockCount.ToString(CultureInfo.InvariantCulture) +
                                      " | Range: " + coverage.MinBlockId.ToString(CultureInfo.InvariantCulture) +
                                      "-" + coverage.MaxBlockId.ToString(CultureInfo.InvariantCulture) +
                                      " | Best: " + coverage.IsBestMatch);
                        if (coverage.MissingBlocks.Count > 0)
                        {
                            string missingBlocks = string.Join(", ", coverage.MissingBlocks.Select(id => "0x" + id.ToString("X4", CultureInfo.InvariantCulture)));
                            sb.AppendLine("    Missing Blocks: " + missingBlocks);
                        }
                    }
                }
                sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-message-tables"))
            {
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
                                      " | Entries: " + table.Entries.Count.ToString(CultureInfo.InvariantCulture) +
                                      " | Range: " + table.MinId.ToString(CultureInfo.InvariantCulture) +
                                      "-" + table.MaxId.ToString(CultureInfo.InvariantCulture));
                        foreach (MessageTableEntryInfo entry in table.Entries.Take(50))
                        {
                            sb.AppendLine("    - Id: " + entry.Id.ToString(CultureInfo.InvariantCulture) +
                                          " | Unicode: " + entry.IsUnicode +
                                          " | Len: " + entry.Length.ToString(CultureInfo.InvariantCulture) +
                                          " | Flags: 0x" + entry.Flags.ToString("X4", CultureInfo.InvariantCulture) +
                                          " | " + entry.Text);
                        }
                    if (table.Entries.Count > 50)
                    {
                        sb.AppendLine("  (truncated)");
                    }
                }
            }
            sb.AppendLine();
            }

            if (filter.ShouldInclude("resource-dialogs"))
            {
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
            }

            if (filter.ShouldInclude("resource-accelerators"))
            {
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
            }

            if (filter.ShouldInclude("resource-menus"))
            {
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
            }

            if (filter.ShouldInclude("resource-toolbars"))
            {
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
            }

            if (filter.ShouldInclude("resource-manifests"))
            {
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
                        sb.AppendLine("      SchemaValid: " + manifest.Schema.IsValid);
                        if (manifest.Schema.ValidationMessages != null && manifest.Schema.ValidationMessages.Count > 0)
                        {
                            sb.AppendLine("      Validation:");
                            foreach (string message in manifest.Schema.ValidationMessages)
                            {
                                sb.AppendLine("        - " + message);
                            }
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

            sb.AppendLine();
            }
            if (filter.ShouldInclude("resource-locale-coverage"))
            {
            sb.AppendLine("Resource Locale Coverage:");
            if (pe.ResourceLocaleCoverage.Length == 0)
            {
                sb.AppendLine("  (none)");
            }
            else
            {
                foreach (ResourceLocaleCoverageInfo coverage in pe.ResourceLocaleCoverage.OrderBy(c => c.ResourceKind, StringComparer.OrdinalIgnoreCase))
                {
                    string langs = coverage.LanguageIds.Count > 0
                        ? string.Join(", ", coverage.LanguageIds.Select(id => "0x" + id.ToString("X4", CultureInfo.InvariantCulture)))
                        : "(none)";
                    sb.AppendLine("  - " + Safe(coverage.ResourceKind) +
                                  " | Langs: " + langs +
                                  " | Neutral: " + coverage.HasNeutralLanguage +
                                  " | Localized: " + coverage.HasLocalizedLanguage +
                                  " | MissingNeutral: " + coverage.MissingNeutralFallback);
                }
            }
            sb.AppendLine();
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
            if (signer.CertificateTransparencyCount > 0)
            {
                sb.AppendLine(prefix + "  Certificate Transparency: " + signer.CertificateTransparencyCount.ToString(CultureInfo.InvariantCulture));
            }
            if (signer.CertificateTransparencyLogIds != null && signer.CertificateTransparencyLogIds.Count > 0)
            {
                sb.AppendLine(prefix + "  CT Logs: " + signer.CertificateTransparencyLogIds.Count.ToString(CultureInfo.InvariantCulture));
                foreach (string logId in signer.CertificateTransparencyLogIds.Take(5))
                {
                    sb.AppendLine(prefix + "    - " + logId);
                }
                if (signer.CertificateTransparencyLogIds.Count > 5)
                {
                    sb.AppendLine(prefix + "    (truncated)");
                }
            }
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
            if (signer.ChainElements != null && signer.ChainElements.Count > 0)
            {
                sb.AppendLine(prefix + "  Chain Elements:");
                foreach (Pkcs7ChainElementInfo element in signer.ChainElements)
                {
                    sb.AppendLine(prefix + "    - " + Safe(element.Subject));
                    if (!string.IsNullOrWhiteSpace(element.Thumbprint))
                    {
                        sb.AppendLine(prefix + "      Thumbprint: " + Safe(element.Thumbprint));
                    }
                    if (element.IsSelfSigned)
                    {
                        sb.AppendLine(prefix + "      SelfSigned: true");
                    }
                    if (element.Status != null && element.Status.Length > 0)
                    {
                        sb.AppendLine(prefix + "      Status:");
                        foreach (string status in element.Status)
                        {
                            sb.AppendLine(prefix + "        - " + status);
                        }
                    }
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

        private static void WriteFindings(StringBuilder sb, PECOFF pe)
        {
            if (pe.ParseResult == null || pe.ParseResult.Issues == null || pe.ParseResult.Issues.Count == 0)
            {
                sb.AppendLine("  (none)");
                return;
            }

            ParseIssueSeverity[] severities = new[] { ParseIssueSeverity.Error, ParseIssueSeverity.Warning };
            foreach (ParseIssueSeverity severity in severities)
            {
                var grouped = pe.ParseResult.Issues
                    .Where(issue => issue.Severity == severity)
                    .GroupBy(issue => issue.Category)
                    .OrderBy(group => group.Key.ToString(), StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                if (grouped.Length == 0)
                {
                    continue;
                }

                sb.AppendLine("  " + severity + ":");
                foreach (var group in grouped)
                {
                    sb.AppendLine("    " + group.Key + " (" + group.Count().ToString(CultureInfo.InvariantCulture) + "):");
                    Dictionary<string, int> messageCounts = new Dictionary<string, int>(StringComparer.Ordinal);
                    List<string> messageOrder = new List<string>();
                    foreach (ParseIssue issue in group)
                    {
                        if (messageCounts.TryGetValue(issue.Message, out int count))
                        {
                            messageCounts[issue.Message] = count + 1;
                        }
                        else
                        {
                            messageCounts[issue.Message] = 1;
                            messageOrder.Add(issue.Message);
                        }
                    }

                    foreach (string message in messageOrder)
                    {
                        sb.AppendLine("      - " + message + " [" +
                                      messageCounts[message].ToString(CultureInfo.InvariantCulture) + "]");
                    }
                }
            }
        }

        private static string Safe(string? value)
        {
            return value ?? string.Empty;
        }

        private static void AppendGuardRvaTableInfo(StringBuilder sb, GuardRvaTableInfo info, string label)
        {
            if (sb == null || info == null)
            {
                return;
            }

            sb.AppendLine(label);
            sb.AppendLine("    Pointer: 0x" + info.Pointer.ToString("X", CultureInfo.InvariantCulture) +
                          " | Count: " + info.Count.ToString(CultureInfo.InvariantCulture) +
                          " | EntrySize: " + info.EntrySize.ToString(CultureInfo.InvariantCulture));
            if (!string.IsNullOrWhiteSpace(info.SectionName))
            {
                sb.AppendLine("    Section: " + Safe(info.SectionName));
            }
            sb.AppendLine("    Mapped: " + info.IsMapped +
                          " | SizeFits: " + info.SizeFits +
                          " | Truncated: " + info.IsTruncated);
            if (info.Entries.Count > 0)
            {
                sb.AppendLine("    Sample: " + string.Join(", ", info.Entries.Take(10)
                    .Select(rva => "0x" + rva.ToString("X8", CultureInfo.InvariantCulture))));
            }
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

        private static string NormalizeSectionKey(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : value.Trim().ToLowerInvariant();
        }

        private static HashSet<string> ParseSectionList(string value)
        {
            HashSet<string> sections = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(value))
            {
                return sections;
            }

            string[] parts = value.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string part in parts)
            {
                string key = NormalizeSectionKey(part);
                if (!string.IsNullOrWhiteSpace(key))
                {
                    sections.Add(key);
                }
            }

            return sections;
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

            if (values.TryGetValue("sections", out string? includeValue))
            {
                HashSet<string> include = ParseSectionList(includeValue);
                if (!include.Contains("all") && !include.Contains("*"))
                {
                    options.Filter.Include.UnionWith(include);
                }
            }

            if (values.TryGetValue("exclude-sections", out string? excludeValue))
            {
                options.Filter.Exclude.UnionWith(ParseSectionList(excludeValue));
            }

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
            Console.WriteLine("  PE-FileInspector --output report.txt --output-dir <output-path> --file <file-to-analyze> [--suppress-cssm <true|false>] [--sections <list>] [--exclude-sections <list>]");
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
