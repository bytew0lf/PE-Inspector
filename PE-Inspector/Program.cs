using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

using PECoff;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace PE_Inspector
{
    class Program
    {
        private static IDisposable _cssmSuppressor;

        [ModuleInitializer]
        internal static void InitializeCssmFilter()
        {
            Environment.SetEnvironmentVariable("OS_ACTIVITY_MODE", "disable");
            bool suppressCssm = CssmStderrFilter.GetDefaultSuppressSetting();
            _cssmSuppressor = CssmStderrFilter.TryStart(suppressCssm);
        }

        static void Main(string[] args)
        {
            String filename = "";
            String dirname = string.Empty;
            if (args.Length != 2)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("<EXE> <FileName>.csv <PathToInspect>");
                Console.WriteLine("\nExample: <EXE> test.csv c:\\Windows");
                return;
            }

            filename = args[0];
            dirname = args[1];

            string[] ignore = null;
            string ignorelist = "Ignorelist.txt";
            if (File.Exists(ignorelist))
            {
                Console.WriteLine("Loading ignorelist...");
                ignore = File.ReadAllLines(ignorelist);
            }

            using (TextWriter tw = new StreamWriter(Path.Combine(Directory.GetCurrentDirectory(), filename)))
            {
                tw.WriteLine("Filename;Extension;Path;Product Version;File Version;IsDotNetFile;IsObfuscated;Obfuscationpercentage;SHA256 HASH;HasCertificate;Comments;CompanyName;FileDescription;InternalName;IsDebug;IsPatched;IsPreRelease;IsPrivateBuild;IsSpecialBuild;Language;Copyright;Trademarks;OriginalFilename;PrivateBuild;ProductName;SpecialBuild;ParseErrors;ParseWarnings");
                string[] ListOfFiles = Directory.GetFiles(dirname, "*.*", SearchOption.AllDirectories); ;

                ApplyIgnoreList(ignore, ref ListOfFiles);

                foreach (string fname in ListOfFiles)
                {
                    Console.Write("Inspecting {0}...\r", fname);
                    PECOFFOptions options = new PECOFFOptions
                    {
                        ParseCertificateSigners = false,
                        ComputeAuthenticode = false
                    };
                    PECOFF f = new PECOFF(fname, options);
                    System.Diagnostics.FileVersionInfo versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(fname);
                    string parseErrors = f.ParseResult.Errors.Count > 0 ? string.Join(" | ", f.ParseResult.Errors) : "";
                    string parseWarnings = f.ParseResult.Warnings.Count > 0 ? string.Join(" | ", f.ParseResult.Warnings) : "";
                    tw.Write("{0};", Path.GetFileName(fname));
                    tw.Write("{0};", Path.GetExtension(fname));
                    tw.Write("{0};", Path.GetDirectoryName(fname));
                    tw.Write("{0};", versionInfo.ProductVersion != null ? versionInfo.ProductVersion.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.FileVersion != null ? versionInfo.FileVersion.Replace("\r", "").Replace("\n", " ").Replace(";", "").Trim() : " ");
                    tw.Write("{0};", f.IsDotNetFile);
                    tw.Write("{0};", f.IsObfuscated);
                    tw.Write(string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0};", f.ObfuscationPercentage));
                    tw.Write("{0};", f.Hash);
                    tw.Write("{0};", f.HasCertificate);
                    tw.Write("{0};", versionInfo.Comments != null ? versionInfo.Comments.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.CompanyName != null ? versionInfo.CompanyName.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.FileDescription != null ? versionInfo.FileDescription.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.InternalName != null ? versionInfo.InternalName.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.IsDebug);
                    tw.Write("{0};", versionInfo.IsPatched);
                    tw.Write("{0};", versionInfo.IsPreRelease);
                    tw.Write("{0};", versionInfo.IsPrivateBuild);
                    tw.Write("{0};", versionInfo.IsSpecialBuild);
                    tw.Write("{0};", versionInfo.Language != null ? versionInfo.Language.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.LegalCopyright != null ? versionInfo.LegalCopyright.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.LegalTrademarks != null ? versionInfo.LegalTrademarks.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.OriginalFilename != null ? versionInfo.OriginalFilename.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.PrivateBuild != null ? versionInfo.PrivateBuild.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.ProductName != null ? versionInfo.ProductName.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", versionInfo.SpecialBuild != null ? versionInfo.SpecialBuild.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                    tw.Write("{0};", Sanitize(parseErrors));
                    tw.Write("{0}\n", Sanitize(parseWarnings));
                }
            }
        }

        static string Sanitize(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "";
            }

            return value.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim();
        }

        static void ApplyIgnoreList(string[] ignorelist, ref string[] Filelist)
        {
            if (ignorelist == null) { return; } // Nothing to do

            List<string> files = new List<string>();
            files.AddRange(Filelist);
            int remcnt = 0;

            List<string> ignoreset = new List<string>();
            ignoreset.AddRange(ignorelist);
            ignoreset = ignoreset.Distinct().ToList();

            foreach (string item in ignoreset)
            {
                if (item.StartsWith(";") || item.StartsWith("#") || string.IsNullOrEmpty(item))
                {
                    // Support for Comments and empty lines
                    continue;
                }

                if (item.StartsWith("*"))
                {
                    // Wildcard possible an extension                    
                    remcnt = files.RemoveAll(x => x.ToLowerInvariant().EndsWith(item.Remove(0, 1)));
                }
                else
                {
                    // specific filename
                    remcnt = files.RemoveAll(x => x.ToLowerInvariant().Contains(item.ToLowerInvariant()));
                }
            }

            Filelist = files.ToArray();
        }

        private static class CssmStderrFilter
        {
            private const string MessageToken = "CSSM_ModuleLoad()";

            public static bool GetDefaultSuppressSetting()
            {
                string suppress = Environment.GetEnvironmentVariable("PE_INSPECTOR_SUPPRESS_CSSM");
                if (string.Equals(suppress, "0", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                return true;
            }

            public static IDisposable TryStart(bool suppress)
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    return null;
                }

                if (!suppress)
                {
                    return null;
                }

                return PipeFilter.TryCreate(2, MessageToken);
            }

            private sealed class PipeFilter : IDisposable
            {
                private readonly int _targetFd;
                private readonly int _savedFd;
                private readonly int _pipeRead;
                private readonly Thread _thread;
                private bool _disposed;

                private PipeFilter(int targetFd, int savedFd, int pipeRead, Thread thread)
                {
                    _targetFd = targetFd;
                    _savedFd = savedFd;
                    _pipeRead = pipeRead;
                    _thread = thread;
                }

                public static PipeFilter TryCreate(int targetFd, string filterToken)
                {
                    int[] fds = new int[2];
                    if (pipe(fds) != 0)
                    {
                        return null;
                    }

                    int pipeRead = fds[0];
                    int pipeWrite = fds[1];

                    int saved = dup(targetFd);
                    if (saved == -1)
                    {
                        close(pipeRead);
                        close(pipeWrite);
                        return null;
                    }

                    if (dup2(pipeWrite, targetFd) == -1)
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

                    return new PipeFilter(targetFd, saved, pipeRead, thread);
                }

                public void Dispose()
                {
                    if (_disposed)
                    {
                        return;
                    }

                    _disposed = true;
                    dup2(_savedFd, _targetFd);
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
                            if (ch == '\n' || ch == '\r')
                            {
                                WriteLineIfAllowed(writeFd, lineBuffer, filterToken, ch);
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
                        WriteLineIfAllowed(writeFd, lineBuffer, filterToken, null);
                    }
                }

                private static void WriteLineIfAllowed(int writeFd, StringBuilder line, string filterToken, char? delimiter)
                {
                    string text = line.ToString();
                    if (text.Contains(filterToken, StringComparison.Ordinal))
                    {
                        return;
                    }

                    string suffix = delimiter.HasValue ? delimiter.Value.ToString() : string.Empty;
                    byte[] data = Encoding.UTF8.GetBytes(text + suffix);
                    write_bytes(writeFd, data, data.Length);
                }
            }

            [DllImport("libc")]
            private static extern int pipe(int[] fds);

            [DllImport("libc")]
            private static extern int dup(int fd);

            [DllImport("libc")]
            private static extern int dup2(int fd, int fd2);

            [DllImport("libc")]
            private static extern int close(int fd);

            [DllImport("libc", EntryPoint = "read")]
            private static extern int read_bytes(int fd, byte[] buffer, int count);

            [DllImport("libc", EntryPoint = "write")]
            private static extern int write_bytes(int fd, byte[] buffer, int count);
        }
    }
}
