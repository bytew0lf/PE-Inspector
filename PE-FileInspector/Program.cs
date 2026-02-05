using System;
using System.Collections.Generic;
using SysFileVersionInfo = System.Diagnostics.FileVersionInfo;
using System.Globalization;
using System.IO;
using System.Text;
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
        }

        private static int Main(string[] args)
        {
            if (!TryParseArgs(args, out Options? options) || options == null)
            {
                PrintUsage();
                return 1;
            }

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
            SysFileVersionInfo versionInfo = SysFileVersionInfo.GetVersionInfo(options.FilePath);

            List<string> certPaths = new List<string>();
            if (pe.Certificates.Length > 0)
            {
                string baseName = Path.GetFileNameWithoutExtension(options.FilePath);
                if (string.IsNullOrWhiteSpace(baseName))
                {
                    baseName = "certificate";
                }

                for (int i = 0; i < pe.Certificates.Length; i++)
                {
                    string suffix = i == 0 ? string.Empty : "-" + (i + 1).ToString(CultureInfo.InvariantCulture);
                    string certFileName = baseName + suffix + ".crt";
                    string certPath = GetUniqueFilePath(options.OutputDir, certFileName);
                    File.WriteAllBytes(certPath, pe.Certificates[i]);
                    certPaths.Add(certPath);
                }
            }

            string report = BuildReport(options.FilePath, pe, versionInfo, certPaths);
            File.WriteAllText(reportPath, report, Encoding.UTF8);

            Console.WriteLine("Report written to: {0}", reportPath);
            if (certPaths.Count > 0)
            {
                foreach (string path in certPaths)
                {
                    Console.WriteLine("Certificate written to: {0}", path);
                }
            }

            return 0;
        }

        private static string BuildReport(string filePath, PECOFF pe, SysFileVersionInfo versionInfo, List<string> certPaths)
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
            sb.AppendLine("  Product Version: " + Safe(versionInfo.ProductVersion));
            sb.AppendLine("  File Version: " + Safe(versionInfo.FileVersion));
            sb.AppendLine("  Company Name: " + Safe(versionInfo.CompanyName));
            sb.AppendLine("  File Description: " + Safe(versionInfo.FileDescription));
            sb.AppendLine("  Internal Name: " + Safe(versionInfo.InternalName));
            sb.AppendLine("  Original Filename: " + Safe(versionInfo.OriginalFilename));
            sb.AppendLine("  Product Name: " + Safe(versionInfo.ProductName));
            sb.AppendLine("  Copyright: " + Safe(versionInfo.LegalCopyright));
            sb.AppendLine("  Trademarks: " + Safe(versionInfo.LegalTrademarks));
            sb.AppendLine("  Language: " + Safe(versionInfo.Language));
            sb.AppendLine("  Comments: " + Safe(versionInfo.Comments));
            sb.AppendLine("  Private Build: " + Safe(versionInfo.PrivateBuild));
            sb.AppendLine("  Special Build: " + Safe(versionInfo.SpecialBuild));
            sb.AppendLine();

            sb.AppendLine("PE Analysis:");
            sb.AppendLine("  Is .NET File: " + pe.IsDotNetFile);
            sb.AppendLine("  Is Obfuscated: " + pe.IsObfuscated);
            sb.AppendLine("  Obfuscation Percentage: " + pe.ObfuscationPercentage.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("  Has Certificate: " + pe.HasCertificate);
            sb.AppendLine("  Certificate Count: " + certPaths.Count.ToString(CultureInfo.InvariantCulture));
            if (certPaths.Count == 0)
            {
                sb.AppendLine("  Certificate Paths: (none)");
            }
            else
            {
                sb.AppendLine("  Certificate Paths:");
                foreach (string path in certPaths)
                {
                    sb.AppendLine("    - " + path);
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

            options = new Options
            {
                OutputFileName = output,
                OutputDir = outputDir,
                FilePath = file
            };

            return true;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  PE-FileInspector --output report.txt --output-dir <output-path> --file <file-to-analyze>");
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
    }
}
