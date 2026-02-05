using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace PECoff
{
    public sealed class PECOFFOptions
    {
        public bool StrictMode { get; init; }
        public bool EnableAssemblyAnalysis { get; init; } = true;
        public bool ComputeHash { get; init; } = true;
        public bool ComputeChecksum { get; init; } = true;
        public bool ParseCertificateSigners { get; init; } = true;
    }

    public sealed class PECOFFParseException : Exception
    {
        public PECOFFParseException(string message)
            : base(message)
        {
        }
    }

    public sealed class ParseResultSnapshot
    {
        public IReadOnlyList<string> Errors { get; }
        public IReadOnlyList<string> Warnings { get; }
        public bool IsSuccess => Errors.Count == 0;

        public ParseResultSnapshot(IReadOnlyList<string> errors, IReadOnlyList<string> warnings)
        {
            Errors = errors ?? Array.Empty<string>();
            Warnings = warnings ?? Array.Empty<string>();
        }
    }

    public sealed class PECOFFResult
    {
        public string FilePath { get; }
        public ParseResultSnapshot ParseResult { get; }
        public string Hash { get; }
        public bool IsDotNetFile { get; }
        public bool IsObfuscated { get; }
        public double ObfuscationPercentage { get; }
        public string FileVersion { get; }
        public string ProductVersion { get; }
        public string CompanyName { get; }
        public string FileDescription { get; }
        public string InternalName { get; }
        public string OriginalFilename { get; }
        public string ProductName { get; }
        public string Comments { get; }
        public string LegalCopyright { get; }
        public string LegalTrademarks { get; }
        public string PrivateBuild { get; }
        public string SpecialBuild { get; }
        public string Language { get; }
        public uint FileAlignment { get; }
        public uint SectionAlignment { get; }
        public uint SizeOfHeaders { get; }
        public uint OptionalHeaderChecksum { get; }
        public uint ComputedChecksum { get; }
        public bool IsChecksumValid { get; }
        public uint TimeDateStamp { get; }
        public DateTimeOffset? TimeDateStampUtc { get; }
        public bool HasCertificate { get; }
        public byte[] Certificate { get; }
        public IReadOnlyList<byte[]> Certificates { get; }
        public IReadOnlyList<CertificateEntry> CertificateEntries { get; }
        public IReadOnlyList<ResourceEntry> Resources { get; }
        public ClrMetadataInfo ClrMetadata { get; }
        public IReadOnlyList<string> Imports { get; }
        public IReadOnlyList<ImportEntry> ImportEntries { get; }
        public IReadOnlyList<ImportEntry> DelayImportEntries { get; }
        public IReadOnlyList<string> Exports { get; }
        public IReadOnlyList<ExportEntry> ExportEntries { get; }
        public IReadOnlyList<string> AssemblyReferences { get; }
        public IReadOnlyList<AssemblyReferenceInfo> AssemblyReferenceInfos { get; }

        internal PECOFFResult(
            string filePath,
            ParseResultSnapshot parseResult,
            string hash,
            bool isDotNetFile,
            bool isObfuscated,
            double obfuscationPercentage,
            string fileVersion,
            string productVersion,
            string companyName,
            string fileDescription,
            string internalName,
            string originalFilename,
            string productName,
            string comments,
            string legalCopyright,
            string legalTrademarks,
            string privateBuild,
            string specialBuild,
            string language,
            uint fileAlignment,
            uint sectionAlignment,
            uint sizeOfHeaders,
            uint optionalHeaderChecksum,
            uint computedChecksum,
            bool isChecksumValid,
            uint timeDateStamp,
            DateTimeOffset? timeDateStampUtc,
            bool hasCertificate,
            byte[] certificate,
            byte[][] certificates,
            CertificateEntry[] certificateEntries,
            ResourceEntry[] resources,
            ClrMetadataInfo clrMetadata,
            string[] imports,
            ImportEntry[] importEntries,
            ImportEntry[] delayImportEntries,
            string[] exports,
            ExportEntry[] exportEntries,
            string[] assemblyReferences,
            AssemblyReferenceInfo[] assemblyReferenceInfos)
        {
            FilePath = filePath ?? string.Empty;
            ParseResult = parseResult ?? new ParseResultSnapshot(Array.Empty<string>(), Array.Empty<string>());
            Hash = hash ?? string.Empty;
            IsDotNetFile = isDotNetFile;
            IsObfuscated = isObfuscated;
            ObfuscationPercentage = obfuscationPercentage;
            FileVersion = fileVersion ?? string.Empty;
            ProductVersion = productVersion ?? string.Empty;
            CompanyName = companyName ?? string.Empty;
            FileDescription = fileDescription ?? string.Empty;
            InternalName = internalName ?? string.Empty;
            OriginalFilename = originalFilename ?? string.Empty;
            ProductName = productName ?? string.Empty;
            Comments = comments ?? string.Empty;
            LegalCopyright = legalCopyright ?? string.Empty;
            LegalTrademarks = legalTrademarks ?? string.Empty;
            PrivateBuild = privateBuild ?? string.Empty;
            SpecialBuild = specialBuild ?? string.Empty;
            Language = language ?? string.Empty;
            FileAlignment = fileAlignment;
            SectionAlignment = sectionAlignment;
            SizeOfHeaders = sizeOfHeaders;
            OptionalHeaderChecksum = optionalHeaderChecksum;
            ComputedChecksum = computedChecksum;
            IsChecksumValid = isChecksumValid;
            TimeDateStamp = timeDateStamp;
            TimeDateStampUtc = timeDateStampUtc;
            HasCertificate = hasCertificate;
            Certificate = certificate ?? Array.Empty<byte>();
            Certificates = Array.AsReadOnly(certificates ?? Array.Empty<byte[]>());
            CertificateEntries = Array.AsReadOnly(certificateEntries ?? Array.Empty<CertificateEntry>());
            Resources = Array.AsReadOnly(resources ?? Array.Empty<ResourceEntry>());
            ClrMetadata = clrMetadata;
            Imports = Array.AsReadOnly(imports ?? Array.Empty<string>());
            ImportEntries = Array.AsReadOnly(importEntries ?? Array.Empty<ImportEntry>());
            DelayImportEntries = Array.AsReadOnly(delayImportEntries ?? Array.Empty<ImportEntry>());
            Exports = Array.AsReadOnly(exports ?? Array.Empty<string>());
            ExportEntries = Array.AsReadOnly(exportEntries ?? Array.Empty<ExportEntry>());
            AssemblyReferences = Array.AsReadOnly(assemblyReferences ?? Array.Empty<string>());
            AssemblyReferenceInfos = Array.AsReadOnly(assemblyReferenceInfos ?? Array.Empty<AssemblyReferenceInfo>());
        }
    }
}
