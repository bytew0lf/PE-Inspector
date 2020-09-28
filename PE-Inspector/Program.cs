using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

using PECoff;
using System.Runtime.InteropServices;

namespace PE_Inspector
{
    class Program
    {
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
                tw.WriteLine("Filename;Extension;Path;Product Version;File Version;IsDotNetFile;IsObfuscated;Obfuscationpercentage;SHA256 HASH;HasCertificate;Comments;CompanyName;FileDescription;InternalName;IsDebug;IsPatched;IsPreRelease;IsPrivateBuild;IsSpecialBuild;Language;Copyright;Trademarks;OriginalFilename;PrivateBuild;ProductName;SpecialBuild");
                string[] ListOfFiles = Directory.GetFiles(dirname, "*.*", SearchOption.AllDirectories); ;

                ApplyIgnoreList(ignore, ref ListOfFiles);

                foreach (string fname in ListOfFiles)
                {
                    Console.Write("Inspecting {0}...\r", fname);
                    PECOFF f = new PECOFF(fname);
                    System.Diagnostics.FileVersionInfo versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(fname);
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
                    tw.Write("{0}\n", versionInfo.SpecialBuild != null ? versionInfo.SpecialBuild.Replace("\r", " ").Replace("\n", " ").Replace(";", "").Trim() : "");
                }
            }
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
    }
}
