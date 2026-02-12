using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;

using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.IO.MemoryMappedFiles;
using System.Xml.Linq;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PECoff
{
    public sealed class ParseResult
    {
        private readonly List<string> _errors = new List<string>();
        private readonly List<string> _warnings = new List<string>();
        private readonly List<ParseIssue> _issues = new List<ParseIssue>();

        public IReadOnlyList<string> Errors => _errors;
        public IReadOnlyList<string> Warnings => _warnings;
        public IReadOnlyList<ParseIssue> Issues => _issues;
        public bool IsSuccess => _errors.Count == 0;

        internal void Clear()
        {
            _errors.Clear();
            _warnings.Clear();
            _issues.Clear();
        }

        internal void AddError(string message)
        {
            if (!string.IsNullOrWhiteSpace(message))
            {
                _errors.Add(message);
            }
        }

        internal void AddWarning(string message)
        {
            if (!string.IsNullOrWhiteSpace(message))
            {
                _warnings.Add(message);
            }
        }

        internal void AddIssue(ParseIssueCategory category, ParseIssueSeverity severity, string message)
        {
            if (string.IsNullOrWhiteSpace(message) || severity == ParseIssueSeverity.Ignore)
            {
                return;
            }

            _issues.Add(new ParseIssue(category, severity, message));
            if (severity == ParseIssueSeverity.Error)
            {
                _errors.Add(message);
            }
            else if (severity == ParseIssueSeverity.Warning)
            {
                _warnings.Add(message);
            }
        }

        public ParseResultSnapshot Snapshot()
        {
            return new ParseResultSnapshot(_errors.ToArray(), _warnings.ToArray(), _issues.ToArray());
        }
    }

    public sealed class AssemblyReferenceInfo
    {
        public string Name { get; }
        public string Version { get; }

        public AssemblyReferenceInfo(string name, string version)
        {
            Name = name ?? string.Empty;
            Version = version ?? string.Empty;
        }
    }

    public enum CertificateTypeKind : ushort
    {
        Unknown = 0x0000,
        X509 = 0x0001,
        PkcsSignedData = 0x0002,
        Reserved1 = 0x0003,
        TsStackSigned = 0x0004
    }

    public sealed class CertificateTypeMetadataInfo
    {
        public string Kind { get; }
        public bool Parsed { get; }
        public string Notes { get; }
        public string Subject { get; }
        public string Issuer { get; }
        public string Thumbprint { get; }
        public string Sha256 { get; }
        public string Preview { get; }

        public CertificateTypeMetadataInfo(
            string kind,
            bool parsed,
            string notes,
            string subject,
            string issuer,
            string thumbprint,
            string sha256,
            string preview)
        {
            Kind = kind ?? string.Empty;
            Parsed = parsed;
            Notes = notes ?? string.Empty;
            Subject = subject ?? string.Empty;
            Issuer = issuer ?? string.Empty;
            Thumbprint = thumbprint ?? string.Empty;
            Sha256 = sha256 ?? string.Empty;
            Preview = preview ?? string.Empty;
        }
    }

    public sealed class CertificateEntry
    {
        public CertificateTypeKind Type { get; }
        public byte[] Data { get; }
        public uint DeclaredLength { get; }
        public ushort Revision { get; }
        public int AlignedLength { get; }
        public int AlignmentPadding { get; }
        public long FileOffset { get; }
        public bool IsAligned => AlignmentPadding == 0;
        public Pkcs7SignerInfo[] Pkcs7SignerInfos { get; }
        public string Pkcs7Error { get; }
        public AuthenticodeVerificationResult[] AuthenticodeResults { get; }
        public AuthenticodeStatusInfo AuthenticodeStatus { get; }
        public CertificateTypeMetadataInfo TypeMetadata { get; }

        public CertificateEntry(CertificateTypeKind type, byte[] data)
            : this(
                type,
                data,
                0,
                0,
                0,
                0,
                -1,
                Array.Empty<Pkcs7SignerInfo>(),
                string.Empty,
                Array.Empty<AuthenticodeVerificationResult>(),
                null,
                null)
        {
        }

        public CertificateEntry(
            CertificateTypeKind type,
            byte[] data,
            uint declaredLength,
            ushort revision,
            int alignedLength,
            int alignmentPadding,
            long fileOffset,
            Pkcs7SignerInfo[] pkcs7SignerInfos,
            string pkcs7Error,
            AuthenticodeVerificationResult[] authenticodeResults,
            AuthenticodeStatusInfo authenticodeStatus)
            : this(
                type,
                data,
                declaredLength,
                revision,
                alignedLength,
                alignmentPadding,
                fileOffset,
                pkcs7SignerInfos,
                pkcs7Error,
                authenticodeResults,
                authenticodeStatus,
                null)
        {
        }

        public CertificateEntry(
            CertificateTypeKind type,
            byte[] data,
            uint declaredLength,
            ushort revision,
            int alignedLength,
            int alignmentPadding,
            long fileOffset,
            Pkcs7SignerInfo[] pkcs7SignerInfos,
            string pkcs7Error,
            AuthenticodeVerificationResult[] authenticodeResults,
            AuthenticodeStatusInfo authenticodeStatus,
            CertificateTypeMetadataInfo typeMetadata)
        {
            Type = type;
            Data = data ?? Array.Empty<byte>();
            DeclaredLength = declaredLength;
            Revision = revision;
            AlignedLength = alignedLength < 0 ? 0 : alignedLength;
            AlignmentPadding = alignmentPadding < 0 ? 0 : alignmentPadding;
            FileOffset = fileOffset;
            Pkcs7SignerInfos = pkcs7SignerInfos ?? Array.Empty<Pkcs7SignerInfo>();
            Pkcs7Error = pkcs7Error ?? string.Empty;
            AuthenticodeResults = authenticodeResults ?? Array.Empty<AuthenticodeVerificationResult>();
            AuthenticodeStatus = authenticodeStatus ?? CertificateUtilities.BuildAuthenticodeStatus(Pkcs7SignerInfos);
            TypeMetadata = typeMetadata ?? BuildDefaultCertificateTypeMetadata(type, Data);
        }

        private static CertificateTypeMetadataInfo BuildDefaultCertificateTypeMetadata(CertificateTypeKind type, byte[] data)
        {
            return new CertificateTypeMetadataInfo(
                type.ToString(),
                false,
                "Metadata not decoded.",
                string.Empty,
                string.Empty,
                string.Empty,
                data == null || data.Length == 0 ? string.Empty : BytesToHex(SHA256.HashData(data)),
                BuildPreview(data ?? Array.Empty<byte>(), 32));
        }

        private static string BytesToHex(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return string.Empty;
            }

            StringBuilder sb = new StringBuilder(data.Length * 2);
            for (int i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString("X2", CultureInfo.InvariantCulture));
            }

            return sb.ToString();
        }

        private static string BuildPreview(byte[] data, int maxBytes)
        {
            if (data == null || data.Length == 0 || maxBytes <= 0)
            {
                return string.Empty;
            }

            int count = Math.Min(maxBytes, data.Length);
            byte[] slice = new byte[count];
            Array.Copy(data, 0, slice, 0, count);
            return BytesToHex(slice);
        }
    }

    public sealed class ResourceEntry
    {
        public uint TypeId { get; }
        public string TypeName { get; }
        public uint NameId { get; }
        public string Name { get; }
        public ushort LanguageId { get; }
        public uint CodePage { get; }
        public uint DataRva { get; }
        public uint Size { get; }
        public long FileOffset { get; }

        public ResourceEntry(
            uint typeId,
            string typeName,
            uint nameId,
            string name,
            ushort languageId,
            uint codePage,
            uint dataRva,
            uint size,
            long fileOffset)
        {
            TypeId = typeId;
            TypeName = typeName ?? string.Empty;
            NameId = nameId;
            Name = name ?? string.Empty;
            LanguageId = languageId;
            CodePage = codePage;
            DataRva = dataRva;
            Size = size;
            FileOffset = fileOffset;
        }
    }

    public sealed class ExportEntry
    {
        public string Name { get; }
        public uint Ordinal { get; }
        public uint AddressRva { get; }
        public bool IsForwarder { get; }
        public string Forwarder { get; }
        public string ForwarderTarget { get; }
        public IReadOnlyList<string> ForwarderChain { get; }
        public bool ForwarderHasCycle { get; }
        public bool ForwarderResolved { get; }

        public ExportEntry(
            string name,
            uint ordinal,
            uint addressRva,
            bool isForwarder,
            string forwarder,
            string forwarderTarget = "",
            string[] forwarderChain = null,
            bool forwarderHasCycle = false,
            bool forwarderResolved = false)
        {
            Name = name ?? string.Empty;
            Ordinal = ordinal;
            AddressRva = addressRva;
            IsForwarder = isForwarder;
            Forwarder = forwarder ?? string.Empty;
            ForwarderTarget = forwarderTarget ?? string.Empty;
            ForwarderChain = Array.AsReadOnly(forwarderChain ?? Array.Empty<string>());
            ForwarderHasCycle = forwarderHasCycle;
            ForwarderResolved = forwarderResolved;
        }
    }

    internal sealed class SectionRange
    {
        public string Name { get; }
        public uint VirtualAddress { get; }
        public uint VirtualSize { get; }
        public uint RawPointer { get; }
        public uint RawSize { get; }

        public SectionRange(string name, uint virtualAddress, uint virtualSize, uint rawPointer, uint rawSize)
        {
            Name = name ?? string.Empty;
            VirtualAddress = virtualAddress;
            VirtualSize = virtualSize;
            RawPointer = rawPointer;
            RawSize = rawSize;
        }
    }

    public enum ImportThunkSource
    {
        ImportNameTable = 0,
        ImportAddressTable = 1
    }

    public sealed class ImportEntry
    {
        public string DllName { get; }
        public string Name { get; }
        public ushort Hint { get; }
        public ushort Ordinal { get; }
        public bool IsByOrdinal { get; }
        public ImportThunkSource Source { get; }
        public uint ThunkRva { get; }

        public ImportEntry(string dllName, string name, ushort hint, ushort ordinal, bool isByOrdinal, ImportThunkSource source, uint thunkRva)
        {
            DllName = dllName ?? string.Empty;
            Name = name ?? string.Empty;
            Hint = hint;
            Ordinal = ordinal;
            IsByOrdinal = isByOrdinal;
            Source = source;
            ThunkRva = thunkRva;
        }
    }

    public sealed class DelayImportDescriptorInfo
    {
        public string DllName { get; }
        public uint Attributes { get; }
        public bool UsesRva { get; }
        public bool IsBound { get; }
        public uint TimeDateStamp { get; }
        public uint ModuleHandleRva { get; }
        public uint ImportAddressTableRva { get; }
        public uint ImportNameTableRva { get; }
        public uint BoundImportAddressTableRva { get; }
        public uint UnloadInformationTableRva { get; }
        public ApiSetResolutionInfo ApiSetResolution { get; }

        public DelayImportDescriptorInfo(
            string dllName,
            uint attributes,
            bool usesRva,
            bool isBound,
            uint timeDateStamp,
            uint moduleHandleRva,
            uint importAddressTableRva,
            uint importNameTableRva,
            uint boundImportAddressTableRva,
            uint unloadInformationTableRva,
            ApiSetResolutionInfo apiSetResolution)
        {
            DllName = dllName ?? string.Empty;
            Attributes = attributes;
            UsesRva = usesRva;
            IsBound = isBound;
            TimeDateStamp = timeDateStamp;
            ModuleHandleRva = moduleHandleRva;
            ImportAddressTableRva = importAddressTableRva;
            ImportNameTableRva = importNameTableRva;
            BoundImportAddressTableRva = boundImportAddressTableRva;
            UnloadInformationTableRva = unloadInformationTableRva;
            ApiSetResolution = apiSetResolution
                ?? new ApiSetResolutionInfo(
                    false,
                    false,
                    false,
                    string.Empty,
                    string.Empty,
                    string.Empty,
                    Array.Empty<string>(),
                    Array.Empty<string>());
        }
    }

    public sealed class BoundForwarderRef
    {
        public string DllName { get; }
        public uint TimeDateStamp { get; }

        public BoundForwarderRef(string dllName, uint timeDateStamp)
        {
            DllName = dllName ?? string.Empty;
            TimeDateStamp = timeDateStamp;
        }
    }

    public sealed class BoundImportEntry
    {
        public string DllName { get; }
        public uint TimeDateStamp { get; }
        public BoundForwarderRef[] Forwarders { get; }

        public BoundImportEntry(string dllName, uint timeDateStamp, BoundForwarderRef[] forwarders)
        {
            DllName = dllName ?? string.Empty;
            TimeDateStamp = timeDateStamp;
            Forwarders = forwarders ?? Array.Empty<BoundForwarderRef>();
        }
    }

    public sealed class ClrStreamInfo
    {
        public string Name { get; }
        public uint Offset { get; }
        public uint Size { get; }

        public ClrStreamInfo(string name, uint offset, uint size)
        {
            Name = name ?? string.Empty;
            Offset = offset;
            Size = size;
        }
    }

    public sealed class ManagedResourceInfo
    {
        public string Name { get; }
        public uint Offset { get; }
        public uint Size { get; }
        public bool IsPublic { get; }
        public string Implementation { get; }
        public string Sha256 { get; }

        public ManagedResourceInfo(string name, uint offset, uint size, bool isPublic, string implementation, string sha256)
        {
            Name = name ?? string.Empty;
            Offset = offset;
            Size = size;
            IsPublic = isPublic;
            Implementation = implementation ?? string.Empty;
            Sha256 = sha256 ?? string.Empty;
        }
    }

    public sealed class ClrMetadataInfo
    {
        public ushort MajorRuntimeVersion { get; }
        public ushort MinorRuntimeVersion { get; }
        public uint Flags { get; }
        public uint EntryPointToken { get; }
        public string MetadataVersion { get; }
        public ClrStreamInfo[] Streams { get; }
        public string AssemblyName { get; }
        public string AssemblyVersion { get; }
        public string Mvid { get; }
        public string TargetFramework { get; }
        public ClrAssemblyReferenceInfo[] AssemblyReferences { get; }
        public string[] ModuleReferences { get; }
        public ManagedResourceInfo[] ManagedResources { get; }
        public string[] AssemblyAttributes { get; }
        public string[] ModuleAttributes { get; }
        public MetadataTableCountInfo[] MetadataTableCounts { get; }
        public ClrTokenReferenceInfo[] TokenReferences { get; }
        public ClrMethodBodySummaryInfo MethodBodySummary { get; }
        public ClrSignatureDecodeSummaryInfo SignatureSummary { get; }
        public bool IlOnly { get; }
        public bool Requires32Bit { get; }
        public bool Prefers32Bit { get; }
        public bool StrongNameSigned { get; }
        public int ModuleDefinitionCount { get; }
        public int TypeDefinitionCount { get; }
        public int TypeReferenceCount { get; }
        public int MethodDefinitionCount { get; }
        public int FieldDefinitionCount { get; }
        public int PropertyDefinitionCount { get; }
        public int EventDefinitionCount { get; }
        public bool HasDebuggableAttribute { get; }
        public string DebuggableModes { get; }
        public bool IsValid { get; }
        public string[] ValidationMessages { get; }

        public ClrMetadataInfo(
            ushort majorRuntimeVersion,
            ushort minorRuntimeVersion,
            uint flags,
            uint entryPointToken,
            string metadataVersion,
            ClrStreamInfo[] streams,
            string assemblyName,
            string assemblyVersion,
            string mvid,
            string targetFramework,
            ClrAssemblyReferenceInfo[] assemblyReferences,
            string[] moduleReferences,
            ManagedResourceInfo[] managedResources,
            string[] assemblyAttributes,
            string[] moduleAttributes,
            MetadataTableCountInfo[] metadataTableCounts,
            ClrTokenReferenceInfo[] tokenReferences,
            ClrMethodBodySummaryInfo methodBodySummary,
            ClrSignatureDecodeSummaryInfo signatureSummary,
            bool ilOnly,
            bool requires32Bit,
            bool prefers32Bit,
            bool strongNameSigned,
            int moduleDefinitionCount,
            int typeDefinitionCount,
            int typeReferenceCount,
            int methodDefinitionCount,
            int fieldDefinitionCount,
            int propertyDefinitionCount,
            int eventDefinitionCount,
            bool hasDebuggableAttribute,
            string debuggableModes,
            bool isValid,
            string[] validationMessages)
        {
            MajorRuntimeVersion = majorRuntimeVersion;
            MinorRuntimeVersion = minorRuntimeVersion;
            Flags = flags;
            EntryPointToken = entryPointToken;
            MetadataVersion = metadataVersion ?? string.Empty;
            Streams = streams ?? Array.Empty<ClrStreamInfo>();
            AssemblyName = assemblyName ?? string.Empty;
            AssemblyVersion = assemblyVersion ?? string.Empty;
            Mvid = mvid ?? string.Empty;
            TargetFramework = targetFramework ?? string.Empty;
            AssemblyReferences = assemblyReferences ?? Array.Empty<ClrAssemblyReferenceInfo>();
            ModuleReferences = moduleReferences ?? Array.Empty<string>();
            ManagedResources = managedResources ?? Array.Empty<ManagedResourceInfo>();
            AssemblyAttributes = assemblyAttributes ?? Array.Empty<string>();
            ModuleAttributes = moduleAttributes ?? Array.Empty<string>();
            MetadataTableCounts = metadataTableCounts ?? Array.Empty<MetadataTableCountInfo>();
            TokenReferences = tokenReferences ?? Array.Empty<ClrTokenReferenceInfo>();
            MethodBodySummary = methodBodySummary;
            SignatureSummary = signatureSummary;
            IlOnly = ilOnly;
            Requires32Bit = requires32Bit;
            Prefers32Bit = prefers32Bit;
            StrongNameSigned = strongNameSigned;
            ModuleDefinitionCount = moduleDefinitionCount;
            TypeDefinitionCount = typeDefinitionCount;
            TypeReferenceCount = typeReferenceCount;
            MethodDefinitionCount = methodDefinitionCount;
            FieldDefinitionCount = fieldDefinitionCount;
            PropertyDefinitionCount = propertyDefinitionCount;
            EventDefinitionCount = eventDefinitionCount;
            HasDebuggableAttribute = hasDebuggableAttribute;
            DebuggableModes = debuggableModes ?? string.Empty;
            IsValid = isValid;
            ValidationMessages = validationMessages ?? Array.Empty<string>();
        }
    }

    // Based on https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
    // https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Section_Table
    // https://tech-zealots.com/malware-analysis/understanding-concepts-of-va-rva-and-offset/
    // http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm
    // https://stackoverflow.com/questions/9955744/getting-offset-in-file-from-rva
    public class PECOFF
    {
        private BinaryReader PEFile;
        private Stream PEFileStream;
        private MemoryMappedFile _memoryMappedFile;
        private MemoryMappedViewStream _memoryMappedStream;
        private MemoryMappedViewAccessor _memoryMappedAccessor;
        private readonly ParseResult _parseResult = new ParseResult();
        private readonly PECOFFOptions _options;
        private readonly string _filePath;
        private ApiSetSchemaData _apiSetSchema;
        private bool _apiSetSchemaLoaded;
        private ApiSetSchemaInfo _apiSetSchemaInfo;
        private IMAGE_DATA_DIRECTORY[] _dataDirectories = Array.Empty<IMAGE_DATA_DIRECTORY>();
        private List<IMAGE_SECTION_HEADER> _sections = new List<IMAGE_SECTION_HEADER>();
        private bool _hasResourceDirectory;
        private bool _hasDebugDirectory;
        private bool _hasRelocationDirectory;
        private bool _hasExceptionDirectory;
        private bool _hasLoadConfigDirectory;
        private bool _hasClrDirectory;
        private bool _resourcesParsed;
        private bool _debugParsed;
        private bool _relocationsParsed;
        private bool _exceptionParsed;
        private bool _loadConfigParsed;
        private bool _clrParsed;
        private bool _peHeaderIsPe32Plus;
        private string _imageKind = "Unknown";
        private CoffObjectInfo _coffObjectInfo;
        private CoffArchiveInfo _coffArchiveInfo;
        private TeImageInfo _teImageInfo;
        private CatalogSignatureInfo _catalogSignatureInfo;
        private DosRelocationInfo _dosRelocationInfo;
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private static readonly Dictionary<ushort, string> RichProductNameMap = new Dictionary<ushort, string>
        {
            { 0x00C1, "Import (5.10)" },
            { 0x00C2, "Linker (5.10)" },
            { 0x00C3, "Cvtomf (5.10)" },
            { 0x00C4, "Cvtres (5.10)" },
            { 0x00C5, "Cvtpgd (5.10)" },
            { 0x00C6, "Linker (5.20)" },
            { 0x00C7, "Cvtomf (5.20)" },
            { 0x00C8, "Cvtres (5.20)" },
            { 0x00C9, "Cvtpgd (5.20)" },
            { 0x00CA, "Linker (6.00)" },
            { 0x00CB, "Cvtomf (6.00)" },
            { 0x00CC, "Cvtres (6.00)" },
            { 0x00CD, "Cvtpgd (6.00)" },
            { 0x00CE, "Linker (6.10)" },
            { 0x00CF, "Cvtomf (6.10)" },
            { 0x00D0, "Cvtres (6.10)" },
            { 0x00D1, "Cvtpgd (6.10)" },
            { 0x00D2, "Linker (7.00)" },
            { 0x00D3, "Cvtomf (7.00)" },
            { 0x00D4, "Cvtres (7.00)" },
            { 0x00D5, "Cvtpgd (7.00)" },
            { 0x00D6, "Linker (7.01)" },
            { 0x00D7, "Cvtomf (7.01)" },
            { 0x00D8, "Cvtres (7.01)" },
            { 0x00D9, "Cvtpgd (7.01)" },
            { 0x00DA, "Linker (7.10)" },
            { 0x00DB, "Cvtomf (7.10)" },
            { 0x00DC, "Cvtres (7.10)" },
            { 0x00DD, "Cvtpgd (7.10)" },
            { 0x00DE, "Linker (8.00)" },
            { 0x00DF, "Cvtomf (8.00)" },
            { 0x00E0, "Cvtres (8.00)" },
            { 0x00E1, "Cvtpgd (8.00)" },
            { 0x00E2, "Linker (9.00)" },
            { 0x00E3, "Cvtomf (9.00)" },
            { 0x00E4, "Cvtres (9.00)" },
            { 0x00E5, "Cvtpgd (9.00)" },
            { 0x00E6, "Linker (10.00)" },
            { 0x00E7, "Cvtomf (10.00)" },
            { 0x00E8, "Cvtres (10.00)" },
            { 0x00E9, "Cvtpgd (10.00)" },
            { 0x00EA, "Linker (11.00)" },
            { 0x00EB, "Cvtomf (11.00)" },
            { 0x00EC, "Cvtres (11.00)" },
            { 0x00ED, "Cvtpgd (11.00)" },
            { 0x00EE, "Linker (12.00)" },
            { 0x00EF, "Cvtomf (12.00)" },
            { 0x00F0, "Cvtres (12.00)" },
            { 0x00F1, "Cvtpgd (12.00)" },
            { 0x00F2, "Linker (13.00)" },
            { 0x00F3, "Cvtomf (13.00)" },
            { 0x00F4, "Cvtres (13.00)" },
            { 0x00F5, "Cvtpgd (13.00)" },
            { 0x00F6, "Linker (14.00)" },
            { 0x00F7, "Cvtomf (14.00)" },
            { 0x00F8, "Cvtres (14.00)" },
            { 0x00F9, "Cvtpgd (14.00)" },
            { 0x00FA, "Linker (15.00)" },
            { 0x00FB, "Cvtomf (15.00)" },
            { 0x00FC, "Cvtres (15.00)" },
            { 0x00FD, "Cvtpgd (15.00)" }
        };

        private static readonly byte[] Msf70Signature = Encoding.ASCII.GetBytes("Microsoft C/C++ MSF 7.00\r\n\u001ADS\0\0\0");
        private static readonly byte[] Msf20Signature = Encoding.ASCII.GetBytes("Microsoft C/C++ MSF 2.00\r\n\u001ADS\0\0\0");

        private static readonly string[] DataDirectoryNames =
        {
            "Export",
            "Import",
            "Resource",
            "Exception",
            "Certificate",
            "BaseRelocation",
            "Debug",
            "Architecture",
            "GlobalPtr",
            "TLS",
            "LoadConfig",
            "BoundImport",
            "IAT",
            "DelayImport",
            "CLR",
            "Reserved"
        };

        private const int CoffSymbolSize = 18;
        private const int CoffLineNumberSize = 6;
        private const int CoffRelocationSize = 10;

        private sealed class ImportDescriptorInternal
        {
            public string DllName { get; }
            public uint TimeDateStamp { get; }
            public uint ImportNameTableRva { get; }
            public uint ImportAddressTableRva { get; }
            public int IntNullThunkCount { get; }
            public int IatNullThunkCount { get; }
            public bool IntTerminated { get; }
            public bool IatTerminated { get; }

            public ImportDescriptorInternal(
                string dllName,
                uint timeDateStamp,
                uint importNameTableRva,
                uint importAddressTableRva,
                int intNullThunkCount,
                int iatNullThunkCount,
                bool intTerminated,
                bool iatTerminated)
            {
                DllName = dllName ?? string.Empty;
                TimeDateStamp = timeDateStamp;
                ImportNameTableRva = importNameTableRva;
                ImportAddressTableRva = importAddressTableRva;
                IntNullThunkCount = intNullThunkCount;
                IatNullThunkCount = iatNullThunkCount;
                IntTerminated = intTerminated;
                IatTerminated = iatTerminated;
            }
        }

        private readonly struct ImportThunkParseStats
        {
            public int EntryCount { get; }
            public int NullThunkCount { get; }
            public bool Terminated { get; }

            public ImportThunkParseStats(int entryCount, int nullThunkCount, bool terminated)
            {
                EntryCount = entryCount;
                NullThunkCount = nullThunkCount;
                Terminated = terminated;
            }
        }

        #region Constructor / Destructor
        public PECOFF(string FileName)
            : this(FileName, null)
        {
        }

        public PECOFF(string FileName, PECOFFOptions options)
        {
            // For Debug
            //();

            // Constructor
            _options = options ?? new PECOFFOptions();
            _filePath = FileName ?? string.Empty;
            _apiSetSchemaInfo = new ApiSetSchemaInfo(false, 0, string.Empty, string.Empty);

            if (!string.IsNullOrWhiteSpace(FileName) && File.Exists(FileName))
            {
                if (_options.UseMemoryMappedFile)
                {
                    _memoryMappedFile = MemoryMappedFile.CreateFromFile(FileName, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
                    _memoryMappedStream = _memoryMappedFile.CreateViewStream(0, 0, MemoryMappedFileAccess.Read);
                    _memoryMappedAccessor = _memoryMappedFile.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
                    PEFileStream = _memoryMappedStream;
                }
                else
                {
                    PEFileStream = new FileStream(FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                }

                PEFile = new BinaryReader(PEFileStream, Encoding.UTF8, leaveOpen: true);

                ReadPE();
            }
            else
            {
                PEFile = null;
                PEFileStream = null;
                Fail(ParseIssueCategory.File, "File does not exist.");
                if (_options.StrictMode)
                {
                    throw new PECOFFParseException("File does not exist.");
                }
            }
        }

        public static PECOFFResult Parse(string fileName, PECOFFOptions options = null)
        {
            PECOFF parser = new PECOFF(fileName, options);
            return parser.ToResult();
        }
        
        ~PECOFF()
        { 
            // Destructor
            if (PEFile != null)
            {
                PEFile.Dispose();
            }

            if (PEFileStream != null && !ReferenceEquals(PEFileStream, _memoryMappedStream))
            {
                PEFileStream.Dispose();
            }

            if (_memoryMappedStream != null)
            {
                _memoryMappedStream.Dispose();
            }

            if (_memoryMappedAccessor != null)
            {
                _memoryMappedAccessor.Dispose();
            }

            if (_memoryMappedFile != null)
            {
                _memoryMappedFile.Dispose();
            }
        }
        #endregion

        #region Enums
        private enum MachineTypes : ushort
        {
            IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
            IMAGE_FILE_MACHINE_TARGET_HOST = 0x0001,

            IMAGE_FILE_MACHINE_AM33 = 0x1d3,
            
            IMAGE_FILE_MACHINE_AMD64 = 0x8664, // x64

            IMAGE_FILE_MACHINE_ARM = 0x1c0,
            IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
            IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
            IMAGE_FILE_MACHINE_ARM64EC = 0xA641,
            IMAGE_FILE_MACHINE_ARM64X = 0xA64E,
            
            IMAGE_FILE_MACHINE_EBC = 0xebc, // EFI Byte Code

            IMAGE_FILE_MACHINE_I386 = 0x14c, // x86
            IMAGE_FILE_MACHINE_IA64 = 0x200, // IA64
            IMAGE_FILE_MACHINE_I860 = 0x14d, // Intel i860

            IMAGE_FILE_MACHINE_ALPHA_AXP_old = 0x183,
            IMAGE_FILE_MACHINE_ALPHA_AXP = 0x184,
            IMAGE_FILE_MACHINE_ALPHA_AXP64 = 0x284,

            IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
            IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,

            IMAGE_FILE_MACHINE_M32R = 0x9041,
            IMAGE_FILE_MACHINE_MIPS16 = 0x266,
            IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
            IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,

            IMAGE_FILE_MACHINE_MOTOROLA_68000 = 0x268,
            IMAGE_FILE_MACHINE_TRICORE = 0x520,
            IMAGE_FILE_MACHINE_CEF = 0x0CEF,

            IMAGE_FILE_MACHINE_R3000BE = 0x160,
            IMAGE_FILE_MACHINE_R3000 = 0x162,
            IMAGE_FILE_MACHINE_R4000 = 0x166,
            IMAGE_FILE_MACHINE_R10000 = 0x168,
            IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,
            
            IMAGE_FILE_MACHINE_SH3 = 0x1a2,
            IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
            IMAGE_FILE_MACHINE_SH3E = 0x1a4,
            IMAGE_FILE_MACHINE_SH4 = 0x1a6,
            IMAGE_FILE_MACHINE_SH5 = 0x1a8,
            IMAGE_FILE_MACHINE_THUMB = 0x1c2,
            IMAGE_FILE_MACHINE_CHPE_X86 = 0x3A64,

            IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232,
            IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264,

            IMAGE_FILE_MACHINE_RISCV32 = 0x5032,
            IMAGE_FILE_MACHINE_RISCV64 = 0x5064,
            IMAGE_FILE_MACHINE_RISCV128 = 0x5128,
            

            IMAGE_FILE_MACHINE_PURE_MSIL = 0xc0ee
        }

        [Flags]
        private enum Characteristics : ushort
        {
            IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
            IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
            IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
            IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
            IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010,
            IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
            IMAGE_FILE_FUTURE_USE = 0x0040,
            IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
            IMAGE_FILE_32BIT_MACHINE = 0x0100,
            IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
            IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
            IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
            IMAGE_FILE_SYSTEM = 0x1000,
            IMAGE_FILE_DLL = 0x2000,
            IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
            IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
        }

        private enum PEFormat : ushort
        {
            PE32 = 0x10b,
            PE32plus = 0x20b,
            //ROM = 0x107            
        }

        private enum MagicByteSignature : ushort
        {
            IMAGE_DOS_SIGNATURE = 0x5a4d,       //MZ
            IMAGE_OS2_SIGNATURE = 0x454E,       //NE
            IMAGE_OS2_SIGNATURE_LE = 0x454C,    //LE
            //IMAGE_NT_SIGNATURE = 0x00004550,     //PE00
            IMAGE_UNKNOWN = 0x0000
        }

        private const UInt32 IMAGE_NT_SIGNATURE = 0x00004550;
        private const ushort EFI_TE_SIGNATURE = 0x5A56; // "VZ"

        private enum Subsystem : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14,
            IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
        }

        [Flags]
        private enum DllCharacteristics : ushort
        {
            IMAGE_DLL_CHARACTERISTICS_RESERVED_00 = 0x0001,
            IMAGE_DLL_CHARACTERISTICS_RESERVED_01 = 0x0002,
            IMAGE_DLL_CHARACTERISTICS_RESERVED_02 = 0x0004,
            IMAGE_DLL_CHARACTERISTICS_RESERVED_03 = 0x0008,
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [Flags]
        private enum GuardFlags : uint
        {
            IMAGE_GUARD_CF_INSTRUMENTED = 0x00000100,
            IMAGE_GUARD_CFW_INSTRUMENTED = 0x00000200,
            IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400,
            IMAGE_GUARD_SECURITY_COOKIE_UNUSED = 0x00000800,
            IMAGE_GUARD_PROTECT_DELAYLOAD_IAT = 0x00001000,
            IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x00002000,
            IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00004000,
            IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 0x00008000,
            IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT = 0x00010000,
            IMAGE_GUARD_RF_INSTRUMENTED = 0x00020000,
            IMAGE_GUARD_RF_ENABLE = 0x00040000,
            IMAGE_GUARD_RF_STRICT = 0x00080000,
            IMAGE_GUARD_RETPOLINE_PRESENT = 0x00100000,
            IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT = 0x00400000,
            IMAGE_GUARD_XFG_ENABLED = 0x00800000,
            IMAGE_GUARD_XFG_TABLE_PRESENT = 0x01000000
        }

        [Flags]
        private enum GlobalFlags : uint
        {
            FLG_STOP_ON_EXCEPTION = 0x00000001,
            FLG_SHOW_LDR_SNAPS = 0x00000002,
            FLG_DEBUG_INITIAL_COMMAND = 0x00000004,
            FLG_STOP_ON_HUNG_GUI = 0x00000008,
            FLG_HEAP_ENABLE_TAIL_CHECK = 0x00000010,
            FLG_HEAP_ENABLE_FREE_CHECK = 0x00000020,
            FLG_HEAP_VALIDATE_PARAMETERS = 0x00000040,
            FLG_HEAP_VALIDATE_ALL = 0x00000080,
            FLG_APPLICATION_VERIFIER = 0x00000100,
            FLG_POOL_ENABLE_TAGGING = 0x00000400,
            FLG_HEAP_ENABLE_TAGGING = 0x00000800,
            FLG_USER_STACK_TRACE_DB = 0x00001000,
            FLG_KERNEL_STACK_TRACE_DB = 0x00002000,
            FLG_MAINTAIN_OBJECT_TYPELIST = 0x00004000,
            FLG_HEAP_ENABLE_TAGGING_BY_DLL = 0x00008000,
            FLG_DISABLE_STACK_EXTENSION = 0x00010000,
            FLG_ENABLE_CSRDEBUG = 0x00020000,
            FLG_ENABLE_KDEBUG_SYMBOL_LOAD = 0x00040000,
            FLG_DISABLE_PAGE_KERNEL_STACKS = 0x00080000
        }

        [Flags]
        private enum SectionCharacteristics : uint
        {
            IMAGE_SCN_RESERVED_00 = 0x00000000,
            IMAGE_SCN_RESERVED_01 = 0x00000001,
            IMAGE_SCN_RESERVED_02 = 0x00000002,
            IMAGE_SCN_RESERVED_03 = 0x00000004,
            IMAGE_SCN_TYPE_NO_PAD = 0x00000008,
            IMAGE_SCN_RESERVED_04 = 0x00000010,
            IMAGE_SCN_CNT_CODE = 0x00000020,
            IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
            IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
            IMAGE_SCN_LNK_OTHER = 0x00000100,
            IMAGE_SCN_LNK_INFO = 0x00000200,
            IMAGE_SCN_RESERVED_05 = 0x00000400,
            IMAGE_SCN_LNK_REMOVE = 0x00000800,
            IMAGE_SCN_LNK_COMDAT = 0x00001000,
            IMAGE_SCN_GPREL = 0x00008000,
            IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
            IMAGE_SCN_MEM_16BIT = 0x00020000,
            IMAGE_SCN_MEM_LOCKED = 0x00040000,
            IMAGE_SCN_MEM_PRELOAD = 0x00080000,
            IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
            IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
            IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
            IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
            IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
            IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
            IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
            IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
            IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
            IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
            IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
            IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
            IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
            IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
            IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
            IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
            IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
            IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
            IMAGE_SCN_MEM_SHARED = 0x10000000,
            IMAGE_SCN_MEM_EXECUTE = 0x20000000,
            IMAGE_SCN_MEM_READ = 0x40000000,
            IMAGE_SCN_MEM_WRITE = 0x80000000
        }

        private enum CertificateRevision : ushort
        {
            WIN_CERT_REVISION_1_0 = 0x0100, // Version 1, legacy version of the Win_Certificate structure. It is supported only for purposes of verifying legacy Authenticode signatures
            WIN_CERT_REVISION_2_0 = 0x0200 // Version 2 is the current version of the Win_Certificate structure. 
        }

        private enum CertificateType : ushort
        {
            WIN_CERT_TYPE_X509 = 0x0001,                // bCertificate contains an X.509 Certificate -> Not Supported
            WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002,    // bCertificate contains a PKCS#7 SignedData structure
            WIN_CERT_TYPE_RESERVED_1 = 0x0003,          // Reserved
            WIN_CERT_TYPE_TS_STACK_SIGNED = 0x0004      // Terminal Server Protocol Stack Certificate signing -> Not Supported
        }

        private enum ResourceType : uint
        {
            Cursor = 1,
            Bitmap = 2,
            Icon = 3,
            Menu = 4,
            Dialog = 5,
            String = 6,
            FontDirectory = 7,
            Font = 8,
            Accelerator = 9,
            RcData = 10,
            MessageTable = 11,
            GroupCursor = 12,
            Version = 16,
            GroupIcon = 14,
            DlgInclude = 17,
            DlgInit = 240,
            PlugAndPlay = 19,
            VXD = 20,
            AnimatedCursor = 21,
            AnimatedIcon = 22,
            HTML = 23,
            Manifest = 24,
            Toolbar = 241
        }

        #endregion

        #region Structures
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_DOS_HEADER    // DOS .EXE header
        {
            public MagicByteSignature e_magic;         // Magic number
            public ushort e_cblp;          // Bytes on last page of file
            public ushort e_cp;            // Pages in file
            public ushort e_crlc;          // Relocations
            public ushort e_cparhdr;       // Size of header in paragraphs
            public ushort e_minalloc;      // Minimum extra paragraphs needed
            public ushort e_maxalloc;      // Maximum extra paragraphs needed
            public ushort e_ss;            // Initial (relative) SS value
            public ushort e_sp;            // Initial SP value
            public ushort e_csum;          // Checksum
            public ushort e_ip;            // Initial IP value
            public ushort e_cs;            // Initial (relative) CS value
            public ushort e_lfarlc;        // File address of relocation table
            public ushort e_ovno;          // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res;  // Reserved words
            public ushort e_oemid;         // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;       // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;// Reserved words
            public UInt32 e_lfanew;        // File address of new exe header
            
            public IMAGE_DOS_HEADER(BinaryReader reader)
            {
                IMAGE_DOS_HEADER hdr = new IMAGE_DOS_HEADER();
                this = hdr;

                byte[] buffer = ReadBytesExact(reader, Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)));
                hdr = buffer.ToStructure<IMAGE_DOS_HEADER>();
                
                this = hdr;
            } 
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_NT_HEADERS
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public PEFormat Magic;
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
            public uint SectionAlignment;
            public uint FileAlignment;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public Subsystem Subsystem;
            public DllCharacteristics DllCharacteristics;
            public uint SizeOfImage;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint Win32VersionValue;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public ulong ImageBase;

            public IMAGE_NT_HEADERS(BinaryReader reader)
            {
                IMAGE_NT_HEADERS hdr = new IMAGE_NT_HEADERS
                {
                    DataDirectory = Array.Empty<IMAGE_DATA_DIRECTORY>(),
                    SectionAlignment = 0,
                    FileAlignment = 0,
                    SizeOfHeaders = 0,
                    CheckSum = 0,
                    Subsystem = 0,
                    DllCharacteristics = 0,
                    SizeOfImage = 0,
                    SizeOfCode = 0,
                    SizeOfInitializedData = 0,
                    Win32VersionValue = 0,
                    LoaderFlags = 0,
                    NumberOfRvaAndSizes = 0,
                    ImageBase = 0
                };
                this = hdr;

                hdr.Signature = reader.ReadUInt32();

                byte[] fileHeaderBuffer = ReadBytesExact(reader, Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)));
                hdr.FileHeader = fileHeaderBuffer.ToStructure<IMAGE_FILE_HEADER>();

                if (hdr.FileHeader.SizeOfOptionalHeader < sizeof(ushort))
                {
                    this = hdr;
                    return;
                }

                byte[] optionalHeaderBuffer = ReadBytesExact(reader, hdr.FileHeader.SizeOfOptionalHeader);
                hdr.Magic = (PEFormat)BitConverter.ToUInt16(optionalHeaderBuffer, 0);

                if (hdr.Magic == PEFormat.PE32 &&
                    optionalHeaderBuffer.Length >= Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER32)))
                {
                    IMAGE_OPTIONAL_HEADER32 opt32 = optionalHeaderBuffer.ToStructure<IMAGE_OPTIONAL_HEADER32>();
                    hdr.DataDirectory = opt32.DataDirectory ?? Array.Empty<IMAGE_DATA_DIRECTORY>();
                    hdr.SectionAlignment = opt32.SectionAlignment;
                    hdr.FileAlignment = opt32.FileAlignment;
                    hdr.SizeOfHeaders = opt32.SizeOfHeaders;
                    hdr.CheckSum = opt32.CheckSum;
                    hdr.Subsystem = opt32.Subsystem;
                    hdr.DllCharacteristics = opt32.DllCharacteristics;
                    hdr.SizeOfImage = opt32.SizeOfImage;
                    hdr.SizeOfCode = opt32.SizeOfCode;
                    hdr.SizeOfInitializedData = opt32.SizeOfInitializedData;
                    hdr.Win32VersionValue = opt32.Win32VersionValue;
                    hdr.LoaderFlags = opt32.LoaderFlags;
                    hdr.NumberOfRvaAndSizes = opt32.NumberOfRvaAndSizes;
                    hdr.ImageBase = opt32.ImageBase;
                }
                else if (hdr.Magic == PEFormat.PE32plus &&
                         optionalHeaderBuffer.Length >= Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64)))
                {
                    IMAGE_OPTIONAL_HEADER64 opt64 = optionalHeaderBuffer.ToStructure<IMAGE_OPTIONAL_HEADER64>();
                    hdr.DataDirectory = opt64.DataDirectory ?? Array.Empty<IMAGE_DATA_DIRECTORY>();
                    hdr.SectionAlignment = opt64.SectionAlignment;
                    hdr.FileAlignment = opt64.FileAlignment;
                    hdr.SizeOfHeaders = opt64.SizeOfHeaders;
                    hdr.CheckSum = opt64.CheckSum;
                    hdr.Subsystem = opt64.Subsystem;
                    hdr.DllCharacteristics = opt64.DllCharacteristics;
                    hdr.SizeOfImage = opt64.SizeOfImage;
                    hdr.SizeOfCode = opt64.SizeOfCode;
                    hdr.SizeOfInitializedData = opt64.SizeOfInitializedData;
                    hdr.Win32VersionValue = opt64.Win32VersionValue;
                    hdr.LoaderFlags = opt64.LoaderFlags;
                    hdr.NumberOfRvaAndSizes = opt64.NumberOfRvaAndSizes;
                    hdr.ImageBase = opt64.ImageBase;
                }
                else
                {
                    hdr.DataDirectory = Array.Empty<IMAGE_DATA_DIRECTORY>();
                }

                this = hdr;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_FILE_HEADER
        {
            public MachineTypes Machine;
            public ushort NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public Characteristics Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct ANON_OBJECT_HEADER_BIGOBJ
        {
            public ushort Sig1;
            public ushort Sig2;
            public ushort Version;
            public ushort Machine;
            public uint TimeDateStamp;
            public Guid ClassID;
            public uint SizeOfData;
            public uint Flags;
            public uint MetaDataSize;
            public uint MetaDataOffset;
            public uint NumberOfSections;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct EFI_TE_IMAGE_HEADER
        {
            public ushort Signature;
            public ushort Machine;
            public byte NumberOfSections;
            public byte Subsystem;
            public ushort StrippedSize;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY DebugTable;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_OPTIONAL_HEADER32
        {
            // Standard fields
            public PEFormat Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;

            // Optional Windows specific fields
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public Subsystem Subsystem;
            public DllCharacteristics DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;            
        }
                       
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_OPTIONAL_HEADER64
        {
            // Standard fields
            public PEFormat Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;

            // Optional Windows specific fields
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public Subsystem Subsystem;
            public DllCharacteristics DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_COR20_HEADER
        {
            public UInt32 cb;
            public UInt16 MajorRuntimeVersion;
            public UInt16 MinorRuntimeVersion;
            public IMAGE_DATA_DIRECTORY MetaData;
            public UInt32 Flags;
            public UInt32 EntryPointToken;
            public IMAGE_DATA_DIRECTORY Resources;
            public IMAGE_DATA_DIRECTORY StrongNameSignature;
            public IMAGE_DATA_DIRECTORY CodeManagerTable;
            public IMAGE_DATA_DIRECTORY VTableFixups;
            public IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
            public IMAGE_DATA_DIRECTORY ManagedNativeHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMPORT_DIRECTORY_TABLE
        {
            public UInt32 LookupTableVirtualAddress;
            public UInt32 TimeDateStamp; // Set to Zero until Bound
            public UInt32 FowarderChain;
            public UInt32 NameRVA;
            public UInt32 ImportAddressTableRVA;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_DELAY_IMPORT_DESCRIPTOR
        {
            public UInt32 Attributes;
            public UInt32 NameRVA;
            public UInt32 ModuleHandleRVA;
            public UInt32 ImportAddressTableRVA;
            public UInt32 ImportNameTableRVA;
            public UInt32 BoundImportAddressTableRVA;
            public UInt32 UnloadInformationTableRVA;
            public UInt32 TimeDateStamp;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_BOUND_IMPORT_DESCRIPTOR
        {
            public UInt32 TimeDateStamp;
            public UInt16 OffsetModuleName;
            public UInt16 NumberOfModuleForwarderRefs;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_BOUND_FORWARDER_REF
        {
            public UInt32 TimeDateStamp;
            public UInt16 OffsetModuleName;
            public UInt16 Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct EXPORT_DIRECTORY_TABLE
        {
            public UInt32 ExportFlags; // should be 0
            public UInt32 TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public UInt32 NameRVA;
            public UInt32 OrdinalBase;
            public UInt32 AddressTableEntries;
            public UInt32 NumberOfNamePointers;
            public UInt32 ExportAddressTableRVA;
            public UInt32 NamePointerRVA;
            public UInt32 OrdinalTableRVA;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_DEBUG_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public UInt32 Type;
            public UInt32 SizeOfData;
            public UInt32 AddressOfRawData;
            public UInt32 PointerToRawData;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_BASE_RELOCATION
        {
            public UInt32 VirtualAddress;
            public UInt32 SizeOfBlock;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_TLS_DIRECTORY32
        {
            public UInt32 StartAddressOfRawData;
            public UInt32 EndAddressOfRawData;
            public UInt32 AddressOfIndex;
            public UInt32 AddressOfCallbacks;
            public UInt32 SizeOfZeroFill;
            public UInt32 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_TLS_DIRECTORY64
        {
            public UInt64 StartAddressOfRawData;
            public UInt64 EndAddressOfRawData;
            public UInt64 AddressOfIndex;
            public UInt64 AddressOfCallbacks;
            public UInt32 SizeOfZeroFill;
            public UInt32 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public UInt32 VirtualSize;
            public UInt32 VirtualAddress;
            public UInt32 SizeOfRawData;
            public UInt32 PointerToRawData;
            public UInt32 PointerToRelocations;
            public UInt32 PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public SectionCharacteristics Characteristics;

            public IMAGE_SECTION_HEADER(BinaryReader reader)
            {
                IMAGE_SECTION_HEADER section = new IMAGE_SECTION_HEADER();
                this = section;

                byte[] buffer = ReadBytesExact(reader, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
                section = buffer.ToStructure<IMAGE_SECTION_HEADER>();

                this = section;
            }

            public string Section
            {
                get { return Name == null ? string.Empty : DecodeCoffShortNameUtf8WithFallback(Name, out bool _); }
            }
        }
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_RESOURCE_DIRECTORY
        {
            public UInt32 Characteristics; // Resource flags. This field is reserved for future use. It is currently set to zero.
            public UInt32 TimeDateStamp; // The time that the resource data was created by the resource compiler
            public ushort MajorVersion; // The major version number, set by the user
            public ushort MinorVersion; // The minor version number, set by the user
            public ushort NumberOfNamedEntries; // The number of directory entries immediately following the table that use strings to identify Type, Name, or Language entries 
            public ushort NumberOfIdEntries; // The number of directory entries immediately following the Name entries that use numeric IDs for Type, Name, or Language entries.
            //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            //public _IMAGE_RESOURCE_DIRECTORY_ENTRY[] DirectoryEntries;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct IMAGE_RESOURCE_DIRECTORY_ENTRY
        {
            #region union
            [FieldOffset(0)]
            public UInt32 NameRVA;
            [FieldOffset(0)]
            public ResourceType IntegerID;
            #endregion

            [FieldOffset(4)]
            public UInt32 DataEntryRVA; // High bit 0. Address of a Resource Data entry (a leaf).
            [FieldOffset(4)]
            public UInt32 SubdirectoryRVA; // High bit 1. The lower 31 bits are the address of another resource directory table (the next level down).

            public bool IsSubDirectory
            {
                get 
                {
                    bool isDir = (0 != (0x80000000 & SubdirectoryRVA));
                    if (isDir)
                    {
                        SubdirectoryRVA = 0x7FFFFFFF & SubdirectoryRVA;
                    }
                    return isDir; 
                }
            }

            public bool IsName
            {
                get { return 0 != (0x80000000 & NameRVA); }
            }
        }
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct CertificateTable 
        {
            public UInt32 dwLength;
            public CertificateRevision wRevision;
            public CertificateType wCertificateType;
            public byte[] bCertificate;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct CertificateTableHeader
        {
            public UInt32 dwLength;
            public CertificateRevision wRevision;
            public CertificateType wCertificateType;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DLLVERSIONINFO
        {
            public int cbSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformID;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct RESOURCE_DIRECTORY_TABLE
        {
            public UInt32 Characteristics; // should be 0
            public UInt32 TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public ushort NumberOfNameEntries;
            public ushort NumberOfIDEntries;
        }

        #endregion

        #region Converters
        T ByteArrayToStructure<T>(byte[] bytes) where T : struct
        {
            // Thanks to coincoin @ http://stackoverflow.com/questions/2871/reading-a-c-c-data-structure-in-c-sharp-from-a-byte-array
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T retVal = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return retVal;
        }

        private Byte[] StructureToByteArray<T>(T structure) where T : struct
        {
            byte[] returnValue = new byte[Marshal.SizeOf(structure)];
            GCHandle handle = GCHandle.Alloc(returnValue, GCHandleType.Pinned);
            Marshal.StructureToPtr(structure, handle.AddrOfPinnedObject(), false);
            handle.Free();

            return returnValue;
        }
        //private Byte[] StructureToByteArray<T>(T mystruct) where T : struct
        //{
        //    int objsize = Marshal.SizeOf(typeof(T));
        //    Byte[] ret = new Byte[objsize];
        //    IntPtr buff = Marshal.AllocHGlobal(objsize);
        //    Marshal.StructureToPtr(mystruct, buff, true);
        //    Marshal.Copy(buff, ret, 0, objsize);
        //    Marshal.FreeHGlobal(buff);
        //    return ret;
        //}
                
        #endregion

        #region Properties
        private string _productversion;
        public string ProductVersion
        {
            get
            {
                EnsureResourcesParsed();
                return _productversion;
            }
        }

        private string _fileversion;
        public string FileVersion
        {
            get
            {
                EnsureResourcesParsed();
                return _fileversion;
            }
        }

        private string _companyName;
        public string CompanyName
        {
            get
            {
                EnsureResourcesParsed();
                return _companyName;
            }
        }

        private string _fileDescription;
        public string FileDescription
        {
            get
            {
                EnsureResourcesParsed();
                return _fileDescription;
            }
        }

        private string _internalName;
        public string InternalName
        {
            get
            {
                EnsureResourcesParsed();
                return _internalName;
            }
        }

        private string _originalFilename;
        public string OriginalFilename
        {
            get
            {
                EnsureResourcesParsed();
                return _originalFilename;
            }
        }

        private string _productName;
        public string ProductName
        {
            get
            {
                EnsureResourcesParsed();
                return _productName;
            }
        }

        private string _comments;
        public string Comments
        {
            get
            {
                EnsureResourcesParsed();
                return _comments;
            }
        }

        private string _legalCopyright;
        public string LegalCopyright
        {
            get
            {
                EnsureResourcesParsed();
                return _legalCopyright;
            }
        }

        private string _legalTrademarks;
        public string LegalTrademarks
        {
            get
            {
                EnsureResourcesParsed();
                return _legalTrademarks;
            }
        }

        private string _privateBuild;
        public string PrivateBuild
        {
            get
            {
                EnsureResourcesParsed();
                return _privateBuild;
            }
        }

        private string _specialBuild;
        public string SpecialBuild
        {
            get
            {
                EnsureResourcesParsed();
                return _specialBuild;
            }
        }

        private string _language;
        public string Language
        {
            get
            {
                EnsureResourcesParsed();
                return _language;
            }
        }

        public string ImageKind
        {
            get { return _imageKind; }
        }

        public CoffObjectInfo CoffObject
        {
            get { return _coffObjectInfo; }
        }

        public CoffArchiveInfo CoffArchive
        {
            get { return _coffArchiveInfo; }
        }

        public DosRelocationInfo DosRelocations
        {
            get { return _dosRelocationInfo; }
        }

        public TeImageInfo TeImage
        {
            get { return _teImageInfo; }
        }

        public CatalogSignatureInfo CatalogSignature
        {
            get { return _catalogSignatureInfo; }
        }

        private bool _isObfuscated;
        public bool IsObfuscated
        {
            get 
            { 
                return _isObfuscated; 
            }
        }

        private double _obfuscationPercentage;
        public double ObfuscationPercentage
        {
            get 
            {
                return _obfuscationPercentage;
            }
        }

        private uint _fileAlignment;
        public uint FileAlignment
        {
            get { return _fileAlignment; }
        }

        private MachineTypes _machineType;

        private uint _sectionAlignment;
        public uint SectionAlignment
        {
            get { return _sectionAlignment; }
        }

        private ulong _imageBase;
        public ulong ImageBase
        {
            get { return _imageBase; }
        }

        private uint _sizeOfImage;
        public uint SizeOfImage
        {
            get { return _sizeOfImage; }
        }

        private uint _sizeOfCode;
        public uint SizeOfCode
        {
            get { return _sizeOfCode; }
        }

        private uint _sizeOfInitializedData;
        public uint SizeOfInitializedData
        {
            get { return _sizeOfInitializedData; }
        }

        private uint _numberOfRvaAndSizes;
        public uint NumberOfRvaAndSizes
        {
            get { return _numberOfRvaAndSizes; }
        }

        private uint _sizeOfHeaders;
        public uint SizeOfHeaders
        {
            get { return _sizeOfHeaders; }
        }

        private OverlayInfo _overlayInfo;
        public OverlayInfo OverlayInfo
        {
            get { return _overlayInfo; }
        }

        private readonly List<OverlayContainerInfo> _overlayContainers = new List<OverlayContainerInfo>();
        public OverlayContainerInfo[] OverlayContainers
        {
            get { return _overlayContainers.ToArray(); }
        }

        private readonly List<SectionEntropyInfo> _sectionEntropies = new List<SectionEntropyInfo>();
        public SectionEntropyInfo[] SectionEntropies
        {
            get { return _sectionEntropies.ToArray(); }
        }

        private readonly List<SectionSlackInfo> _sectionSlacks = new List<SectionSlackInfo>();
        public SectionSlackInfo[] SectionSlacks
        {
            get { return _sectionSlacks.ToArray(); }
        }

        private readonly List<SectionGapInfo> _sectionGaps = new List<SectionGapInfo>();
        public SectionGapInfo[] SectionGaps
        {
            get { return _sectionGaps.ToArray(); }
        }

        private readonly List<SectionPermissionInfo> _sectionPermissions = new List<SectionPermissionInfo>();
        public SectionPermissionInfo[] SectionPermissions
        {
            get { return _sectionPermissions.ToArray(); }
        }

        private readonly List<SectionHeaderInfo> _sectionHeaders = new List<SectionHeaderInfo>();
        public SectionHeaderInfo[] SectionHeaders
        {
            get { return _sectionHeaders.ToArray(); }
        }

        private readonly List<SectionDirectoryInfo> _sectionDirectoryCoverage = new List<SectionDirectoryInfo>();
        public SectionDirectoryInfo[] SectionDirectoryCoverage
        {
            get { return _sectionDirectoryCoverage.ToArray(); }
        }

        private readonly List<string> _unmappedDataDirectories = new List<string>();
        public string[] UnmappedDataDirectories
        {
            get { return _unmappedDataDirectories.ToArray(); }
        }

        private readonly List<DataDirectoryValidationInfo> _dataDirectoryValidations = new List<DataDirectoryValidationInfo>();
        public DataDirectoryValidationInfo[] DataDirectoryValidations
        {
            get { return _dataDirectoryValidations.ToArray(); }
        }

        private SubsystemInfo _subsystemInfo;
        public SubsystemInfo SubsystemInfo
        {
            get { return _subsystemInfo; }
        }

        private DllCharacteristicsInfo _dllCharacteristicsInfo;
        public DllCharacteristicsInfo DllCharacteristicsInfo
        {
            get { return _dllCharacteristicsInfo; }
        }

        private SecurityFeaturesInfo _securityFeaturesInfo;
        public SecurityFeaturesInfo SecurityFeaturesInfo
        {
            get
            {
                EnsureLoadConfigParsed();
                return _securityFeaturesInfo;
            }
        }

        private uint _optionalHeaderChecksum;
        public uint OptionalHeaderChecksum
        {
            get { return _optionalHeaderChecksum; }
        }

        private uint _computedChecksum;
        public uint ComputedChecksum
        {
            get { return _computedChecksum; }
        }

        private long _checksumFieldOffset;
        private long _certificateTableOffset;
        private long _certificateTableSize;

        public bool IsChecksumValid
        {
            get { return _optionalHeaderChecksum != 0 && _optionalHeaderChecksum == _computedChecksum; }
        }

        private uint _timeDateStamp;
        public uint TimeDateStamp
        {
            get { return _timeDateStamp; }
        }

        public DateTimeOffset? TimeDateStampUtc
        {
            get
            {
                if (_timeDateStamp == 0)
                {
                    return null;
                }

                return DateTimeOffset.FromUnixTimeSeconds(_timeDateStamp);
            }
        }

        private bool _isDotNetFile;
        public bool IsDotNetFile
        {
            get
            {
                return _isDotNetFile;
            }
        }

        private string _dotNetRuntimeHint;
        public string DotNetRuntimeHint
        {
            get
            {
                EnsureClrParsed();
                return _dotNetRuntimeHint;
            }
        }

        private string _hash;
        public string Hash
        {
            get => _hash;
        }

        private string _importHash;
        public string ImportHash
        {
            get => _importHash;
        }

        public bool HasCertificate
        {
            get => _certificates.Count > 0;
        }

        private byte[] _certificate;
        public byte[] Certificate
        {
            get => _certificate;
        }

        private List<byte[]> _certificates = new List<byte[]>();
        public byte[][] Certificates
        {
            get { return _certificates.ToArray(); }
        }

        private List<CertificateEntry> _certificateEntries = new List<CertificateEntry>();
        public CertificateEntry[] CertificateEntries
        {
            get { return _certificateEntries.ToArray(); }
        }

        private readonly List<ResourceEntry> _resources = new List<ResourceEntry>();
        public ResourceEntry[] Resources
        {
            get
            {
                EnsureResourcesParsed();
                return _resources.ToArray();
            }
        }

        private readonly List<ResourceStringTableInfo> _resourceStringTables = new List<ResourceStringTableInfo>();
        public ResourceStringTableInfo[] ResourceStringTables
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceStringTables.ToArray();
            }
        }

        private readonly List<ResourceStringCoverageInfo> _resourceStringCoverage = new List<ResourceStringCoverageInfo>();
        public ResourceStringCoverageInfo[] ResourceStringCoverage
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceStringCoverage.ToArray();
            }
        }

        private readonly List<ResourceManifestInfo> _resourceManifests = new List<ResourceManifestInfo>();
        public ResourceManifestInfo[] ResourceManifests
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceManifests.ToArray();
            }
        }

        private readonly List<ResourceLocaleCoverageInfo> _resourceLocaleCoverage = new List<ResourceLocaleCoverageInfo>();
        public ResourceLocaleCoverageInfo[] ResourceLocaleCoverage
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceLocaleCoverage.ToArray();
            }
        }

        private readonly List<ResourceMessageTableInfo> _resourceMessageTables = new List<ResourceMessageTableInfo>();
        public ResourceMessageTableInfo[] ResourceMessageTables
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceMessageTables.ToArray();
            }
        }

        private readonly List<ResourceDialogInfo> _resourceDialogs = new List<ResourceDialogInfo>();
        public ResourceDialogInfo[] ResourceDialogs
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceDialogs.ToArray();
            }
        }

        private readonly List<ResourceAcceleratorTableInfo> _resourceAccelerators = new List<ResourceAcceleratorTableInfo>();
        public ResourceAcceleratorTableInfo[] ResourceAccelerators
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceAccelerators.ToArray();
            }
        }

        private readonly List<ResourceMenuInfo> _resourceMenus = new List<ResourceMenuInfo>();
        public ResourceMenuInfo[] ResourceMenus
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceMenus.ToArray();
            }
        }

        private readonly List<ResourceToolbarInfo> _resourceToolbars = new List<ResourceToolbarInfo>();
        public ResourceToolbarInfo[] ResourceToolbars
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceToolbars.ToArray();
            }
        }

        private readonly List<ResourceBitmapInfo> _resourceBitmaps = new List<ResourceBitmapInfo>();
        public ResourceBitmapInfo[] ResourceBitmaps
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceBitmaps.ToArray();
            }
        }

        private readonly List<ResourceIconInfo> _resourceIcons = new List<ResourceIconInfo>();
        public ResourceIconInfo[] ResourceIcons
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceIcons.ToArray();
            }
        }

        private readonly List<ResourceCursorInfo> _resourceCursors = new List<ResourceCursorInfo>();
        public ResourceCursorInfo[] ResourceCursors
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceCursors.ToArray();
            }
        }

        private readonly List<ResourceCursorGroupInfo> _resourceCursorGroups = new List<ResourceCursorGroupInfo>();
        public ResourceCursorGroupInfo[] ResourceCursorGroups
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceCursorGroups.ToArray();
            }
        }

        private readonly List<ResourceFontInfo> _resourceFonts = new List<ResourceFontInfo>();
        public ResourceFontInfo[] ResourceFonts
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceFonts.ToArray();
            }
        }

        private readonly List<ResourceFontDirInfo> _resourceFontDirectories = new List<ResourceFontDirInfo>();
        public ResourceFontDirInfo[] ResourceFontDirectories
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceFontDirectories.ToArray();
            }
        }

        private readonly List<ResourceDlgInitInfo> _resourceDlgInit = new List<ResourceDlgInitInfo>();
        public ResourceDlgInitInfo[] ResourceDlgInit
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceDlgInit.ToArray();
            }
        }

        private readonly List<ResourceAnimatedInfo> _resourceAnimatedCursors = new List<ResourceAnimatedInfo>();
        public ResourceAnimatedInfo[] ResourceAnimatedCursors
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceAnimatedCursors.ToArray();
            }
        }

        private readonly List<ResourceAnimatedInfo> _resourceAnimatedIcons = new List<ResourceAnimatedInfo>();
        public ResourceAnimatedInfo[] ResourceAnimatedIcons
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceAnimatedIcons.ToArray();
            }
        }

        private readonly List<ResourceRcDataInfo> _resourceRcData = new List<ResourceRcDataInfo>();
        public ResourceRcDataInfo[] ResourceRcData
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceRcData.ToArray();
            }
        }

        private readonly List<ResourceRawInfo> _resourceHtml = new List<ResourceRawInfo>();
        public ResourceRawInfo[] ResourceHtml
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceHtml.ToArray();
            }
        }

        private readonly List<ResourceRawInfo> _resourceDlgInclude = new List<ResourceRawInfo>();
        public ResourceRawInfo[] ResourceDlgInclude
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceDlgInclude.ToArray();
            }
        }

        private readonly List<ResourceRawInfo> _resourcePlugAndPlay = new List<ResourceRawInfo>();
        public ResourceRawInfo[] ResourcePlugAndPlay
        {
            get
            {
                EnsureResourcesParsed();
                return _resourcePlugAndPlay.ToArray();
            }
        }

        private readonly List<ResourceRawInfo> _resourceVxd = new List<ResourceRawInfo>();
        public ResourceRawInfo[] ResourceVxd
        {
            get
            {
                EnsureResourcesParsed();
                return _resourceVxd.ToArray();
            }
        }

        private readonly List<IconGroupInfo> _iconGroups = new List<IconGroupInfo>();
        public IconGroupInfo[] IconGroups
        {
            get
            {
                EnsureResourcesParsed();
                return _iconGroups.ToArray();
            }
        }

        private VersionInfoDetails _versionInfoDetails;
        public VersionInfoDetails VersionInfoDetails
        {
            get
            {
                EnsureResourcesParsed();
                return _versionInfoDetails;
            }
        }

        private ClrMetadataInfo _clrMetadata;
        public ClrMetadataInfo ClrMetadata
        {
            get
            {
                EnsureClrParsed();
                return _clrMetadata;
            }
        }

        private StrongNameSignatureInfo _strongNameSignature;
        public StrongNameSignatureInfo StrongNameSignature
        {
            get
            {
                EnsureClrParsed();
                return _strongNameSignature;
            }
        }

        private StrongNameValidationInfo _strongNameValidation;
        public StrongNameValidationInfo StrongNameValidation
        {
            get
            {
                EnsureClrParsed();
                return _strongNameValidation;
            }
        }

        private ReadyToRunInfo _readyToRun;
        public ReadyToRunInfo ReadyToRun
        {
            get
            {
                EnsureClrParsed();
                return _readyToRun;
            }
        }

        private void EnsureResourcesParsed()
        {
            if (_resourcesParsed)
            {
                return;
            }

            _resourcesParsed = true;
            if (!_hasResourceDirectory || _dataDirectories == null || _dataDirectories.Length <= 2 || _sections.Count == 0)
            {
                return;
            }

            ParseResourceDirectoryTable(_dataDirectories[2], _sections);
        }

        private void EnsureDebugDirectoryParsed()
        {
            if (_debugParsed)
            {
                return;
            }

            _debugParsed = true;
            if (!_hasDebugDirectory || _dataDirectories == null || _dataDirectories.Length <= 6 || _sections.Count == 0)
            {
                return;
            }

            ParseDebugDirectory(_dataDirectories[6], _sections);
        }

        private void EnsureRelocationsParsed()
        {
            if (_relocationsParsed)
            {
                return;
            }

            _relocationsParsed = true;
            if (!_hasRelocationDirectory || _dataDirectories == null || _dataDirectories.Length <= 5 || _sections.Count == 0)
            {
                return;
            }

            ParseBaseRelocationTable(_dataDirectories[5], _sections);
            ValidateRelocationHints();
        }

        private void EnsureExceptionDirectoryParsed()
        {
            if (_exceptionParsed)
            {
                return;
            }

            _exceptionParsed = true;
            if (!_hasExceptionDirectory || _dataDirectories == null || _dataDirectories.Length <= 3 || _sections.Count == 0)
            {
                return;
            }

            ParseExceptionDirectory(_dataDirectories[3], _sections);
            BuildExceptionDirectorySummary(_sections);
        }

        private void EnsureLoadConfigParsed()
        {
            if (_loadConfigParsed)
            {
                return;
            }

            _loadConfigParsed = true;
            if (!_hasLoadConfigDirectory || _dataDirectories == null || _dataDirectories.Length <= 10 || _sections.Count == 0)
            {
                return;
            }

            ParseLoadConfigDirectory(_dataDirectories[10], _sections, _peHeaderIsPe32Plus);
            ComputeSecurityFeatures(_peHeaderIsPe32Plus);
        }

        private void EnsureClrParsed()
        {
            if (_clrParsed)
            {
                return;
            }

            _clrParsed = true;
            if (!_hasClrDirectory || _dataDirectories == null || _dataDirectories.Length <= 14 || _sections.Count == 0)
            {
                return;
            }

            ParseClrDirectory(_dataDirectories[14], _sections);
            ComputeDotNetRuntimeHint();
        }

        private List<string> imports = new List<string>();
        public string[] Imports
        {
            get { return imports.ToArray(); }
        }

        private readonly List<ImportEntry> _importEntries = new List<ImportEntry>();
        public ImportEntry[] ImportEntries
        {
            get { return _importEntries.ToArray(); }
        }

        private readonly List<ImportDescriptorInfo> _importDescriptors = new List<ImportDescriptorInfo>();
        public ImportDescriptorInfo[] ImportDescriptors
        {
            get { return _importDescriptors.ToArray(); }
        }

        public ApiSetSchemaInfo ApiSetSchema
        {
            get { return _apiSetSchemaInfo; }
        }

        private readonly List<ImportDescriptorInternal> _importDescriptorInternals = new List<ImportDescriptorInternal>();

        private readonly List<ImportEntry> _delayImportEntries = new List<ImportEntry>();
        public ImportEntry[] DelayImportEntries
        {
            get { return _delayImportEntries.ToArray(); }
        }

        private readonly List<DelayImportDescriptorInfo> _delayImportDescriptors = new List<DelayImportDescriptorInfo>();
        public DelayImportDescriptorInfo[] DelayImportDescriptors
        {
            get { return _delayImportDescriptors.ToArray(); }
        }

        private List<string> exports = new List<string>();
        public string[] Exports
        {
            get { return exports.ToArray(); }
        }

        private string _exportDllName;
        public string ExportDllName
        {
            get { return _exportDllName; }
        }

        private readonly List<ExportEntry> _exportEntries = new List<ExportEntry>();
        private int _exportOrdinalOutOfRangeCount;
        public ExportEntry[] ExportEntries
        {
            get { return _exportEntries.ToArray(); }
        }

        private ExportAnomalySummary _exportAnomalies = new ExportAnomalySummary(0, 0, 0, 0);
        public ExportAnomalySummary ExportAnomalies
        {
            get { return _exportAnomalies; }
        }

        private readonly List<BoundImportEntry> _boundImports = new List<BoundImportEntry>();
        public BoundImportEntry[] BoundImports
        {
            get { return _boundImports.ToArray(); }
        }

        private readonly List<DebugDirectoryEntry> _debugDirectories = new List<DebugDirectoryEntry>();
        public DebugDirectoryEntry[] DebugDirectories
        {
            get
            {
                EnsureDebugDirectoryParsed();
                return _debugDirectories.ToArray();
            }
        }

        private readonly List<BaseRelocationBlockInfo> _baseRelocations = new List<BaseRelocationBlockInfo>();
        public BaseRelocationBlockInfo[] BaseRelocations
        {
            get
            {
                EnsureRelocationsParsed();
                return _baseRelocations.ToArray();
            }
        }

        private readonly List<BaseRelocationSectionSummary> _baseRelocationSections = new List<BaseRelocationSectionSummary>();
        public BaseRelocationSectionSummary[] BaseRelocationSections
        {
            get
            {
                EnsureRelocationsParsed();
                return _baseRelocationSections.ToArray();
            }
        }

        private RelocationAnomalySummary _relocationAnomalies = new RelocationAnomalySummary(0, 0, 0, 0, 0, 0, 0, 0);
        public RelocationAnomalySummary RelocationAnomalies
        {
            get
            {
                EnsureRelocationsParsed();
                return _relocationAnomalies;
            }
        }

        private uint _exceptionDirectoryRva;
        private uint _exceptionDirectorySize;
        private string _exceptionDirectorySectionName = string.Empty;
        private bool _exceptionDirectoryInPdata;

        private readonly List<ExceptionFunctionInfo> _exceptionFunctions = new List<ExceptionFunctionInfo>();
        public ExceptionFunctionInfo[] ExceptionFunctions
        {
            get
            {
                EnsureExceptionDirectoryParsed();
                return _exceptionFunctions.ToArray();
            }
        }

        private readonly List<UnwindInfoDetail> _unwindInfoDetails = new List<UnwindInfoDetail>();
        public UnwindInfoDetail[] UnwindInfoDetails
        {
            get
            {
                EnsureExceptionDirectoryParsed();
                return _unwindInfoDetails.ToArray();
            }
        }

        private readonly List<Arm64UnwindInfoDetail> _arm64UnwindInfoDetails = new List<Arm64UnwindInfoDetail>();
        public Arm64UnwindInfoDetail[] Arm64UnwindInfoDetails
        {
            get
            {
                EnsureExceptionDirectoryParsed();
                return _arm64UnwindInfoDetails.ToArray();
            }
        }

        private readonly List<Arm32UnwindInfoDetail> _arm32UnwindInfoDetails = new List<Arm32UnwindInfoDetail>();
        public Arm32UnwindInfoDetail[] Arm32UnwindInfoDetails
        {
            get
            {
                EnsureExceptionDirectoryParsed();
                return _arm32UnwindInfoDetails.ToArray();
            }
        }

        private readonly List<Ia64UnwindInfoDetail> _ia64UnwindInfoDetails = new List<Ia64UnwindInfoDetail>();
        public Ia64UnwindInfoDetail[] Ia64UnwindInfoDetails
        {
            get
            {
                EnsureExceptionDirectoryParsed();
                return _ia64UnwindInfoDetails.ToArray();
            }
        }

        private ExceptionDirectorySummary _exceptionSummary;
        public ExceptionDirectorySummary ExceptionSummary
        {
            get
            {
                EnsureExceptionDirectoryParsed();
                return _exceptionSummary;
            }
        }

        private RichHeaderInfo _richHeader;
        public RichHeaderInfo RichHeader
        {
            get { return _richHeader; }
        }

        private TlsInfo _tlsInfo;
        public TlsInfo TlsInfo
        {
            get { return _tlsInfo; }
        }

        private LoadConfigInfo _loadConfig;
        public LoadConfigInfo LoadConfig
        {
            get
            {
                EnsureLoadConfigParsed();
                return _loadConfig;
            }
        }

        private DataDirectoryInfo[] _dataDirectoryInfos = Array.Empty<DataDirectoryInfo>();
        public DataDirectoryInfo[] DataDirectories
        {
            get { return _dataDirectoryInfos; }
        }

        private ArchitectureDirectoryInfo _architectureDirectory;
        public ArchitectureDirectoryInfo ArchitectureDirectory
        {
            get { return _architectureDirectory; }
        }

        private GlobalPtrDirectoryInfo _globalPtrDirectory;
        public GlobalPtrDirectoryInfo GlobalPtrDirectory
        {
            get { return _globalPtrDirectory; }
        }

        private IatDirectoryInfo _iatDirectory;
        public IatDirectoryInfo IatDirectory
        {
            get { return _iatDirectory; }
        }

        private readonly List<PackingHintInfo> _packingHints = new List<PackingHintInfo>();
        public PackingHintInfo[] PackingHints
        {
            get { return _packingHints.ToArray(); }
        }

        private List<AssemblyReferenceInfo> _assemblyReferenceInfos = new List<AssemblyReferenceInfo>();
        public string[] AssemblyReferences
        {
            get { return _assemblyReferenceInfos.Select(r => r.Name).ToArray(); }
        }

        public AssemblyReferenceInfo[] AssemblyReferenceInfos
        {
            get { return _assemblyReferenceInfos.ToArray(); }
        }

        private readonly List<CoffSymbolInfo> _coffSymbols = new List<CoffSymbolInfo>();
        public CoffSymbolInfo[] CoffSymbols
        {
            get { return _coffSymbols.ToArray(); }
        }

        private readonly List<CoffRelocationInfo> _coffRelocations = new List<CoffRelocationInfo>();
        public CoffRelocationInfo[] CoffRelocations
        {
            get { return _coffRelocations.ToArray(); }
        }

        private readonly List<CoffStringTableEntry> _coffStringTable = new List<CoffStringTableEntry>();
        public CoffStringTableEntry[] CoffStringTable
        {
            get { return _coffStringTable.ToArray(); }
        }

        private readonly List<CoffLineNumberInfo> _coffLineNumbers = new List<CoffLineNumberInfo>();
        public CoffLineNumberInfo[] CoffLineNumbers
        {
            get { return _coffLineNumbers.ToArray(); }
        }

        public ParseResult ParseResult => _parseResult;

        public PECOFFResult Result => ToResult();
        #endregion

        #region Functions

        private static byte[] ReadBytesExact(BinaryReader reader, int length)
        {
            byte[] buffer = reader.ReadBytes(length);
            if (buffer.Length != length)
            {
                throw new EndOfStreamException("Unexpected end of PE file while reading structure.");
            }

            return buffer;
        }

        private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int bytesRead = stream.Read(buffer, offset + totalRead, count - totalRead);
                if (bytesRead == 0)
                {
                    throw new EndOfStreamException("Unexpected end of PE file while reading stream.");
                }

                totalRead += bytesRead;
            }
        }

        private unsafe bool TryWithMappedSpan(long offset, int size, Action<ReadOnlySpan<byte>> action)
        {
            if (_memoryMappedAccessor == null || size <= 0 || offset < 0 || size > int.MaxValue)
            {
                return false;
            }

            long capacity = _memoryMappedAccessor.Capacity;
            if (offset > capacity || capacity - offset < size)
            {
                return false;
            }

            byte* pointer = null;
            try
            {
                _memoryMappedAccessor.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
                if (pointer == null)
                {
                    return false;
                }

                ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(pointer + offset, size);
                action(span);
                return true;
            }
            finally
            {
                if (pointer != null)
                {
                    _memoryMappedAccessor.SafeMemoryMappedViewHandle.ReleasePointer();
                }
            }
        }

        private bool TrySetPosition(long position, int requiredBytes = 0)
        {
            if (PEFileStream == null || position < 0)
            {
                return false;
            }

            if (requiredBytes < 0)
            {
                requiredBytes = 0;
            }

            long upperBound = position + requiredBytes;
            if (upperBound > PEFileStream.Length)
            {
                return false;
            }

            PEFileStream.Position = position;
            return true;
        }

        private bool TryGetFileOffset(List<IMAGE_SECTION_HEADER> sections, UInt32 directoryVA, out long fileOffset)
        {
            fileOffset = -1;
            foreach (IMAGE_SECTION_HEADER section in sections)
            {
                if (TryMapRvaToFileOffset(directoryVA, section.VirtualAddress, section.VirtualSize, section.PointerToRawData, section.SizeOfRawData, PEFileStream.Length, out fileOffset))
                {
                    return true;
                }
            }

            return false;
        }

        private bool TryResolvePdbPath(string pdbPath, out string resolvedPath)
        {
            resolvedPath = string.Empty;
            if (string.IsNullOrWhiteSpace(pdbPath))
            {
                return false;
            }

            if (File.Exists(pdbPath))
            {
                resolvedPath = pdbPath;
                return true;
            }

            string fileName = GetFileNameFromPath(pdbPath);
            if (string.IsNullOrWhiteSpace(fileName))
            {
                return false;
            }

            try
            {
                string baseDir = Path.GetDirectoryName(_filePath) ?? string.Empty;
                string candidate = Path.Combine(baseDir, fileName);
                if (File.Exists(candidate))
                {
                    resolvedPath = candidate;
                    return true;
                }
            }
            catch (Exception)
            {
            }

            return false;
        }

        private bool TryParsePdbInfo(string pdbPath, out PdbInfo info)
        {
            info = null;
            if (!TryResolvePdbPath(pdbPath, out string resolvedPath))
            {
                return false;
            }

            try
            {
                using FileStream stream = new FileStream(resolvedPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (!TryParseMsf(resolvedPath, stream, out info))
                {
                    return false;
                }

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool TryParseMsf(string path, FileStream stream, out PdbInfo info)
        {
            info = null;
            if (stream == null || !stream.CanRead)
            {
                return false;
            }

            byte[] header = new byte[64];
            int read = stream.Read(header, 0, header.Length);
            if (read < 56)
            {
                return false;
            }

            string format = string.Empty;
            if (HasPrefix(header, Msf70Signature))
            {
                format = "MSF 7.00";
            }
            else if (HasPrefix(header, Msf20Signature))
            {
                format = "MSF 2.00";
            }
            else
            {
                return false;
            }

            uint pageSize = ReadUInt32(header, 32);
            uint pageCount = ReadUInt32(header, 40);
            uint directorySize = ReadUInt32(header, 44);
            uint blockMapAddr = ReadUInt32(header, 52);
            if (pageSize == 0 || pageSize > 1_048_576 || pageCount == 0)
            {
                return false;
            }

            uint directoryPageCount = directorySize == 0
                ? 0u
                : (uint)((directorySize + pageSize - 1) / pageSize);
            if (directoryPageCount == 0)
            {
                return false;
            }
            if (directorySize > int.MaxValue)
            {
                return false;
            }

            if (!TryReadMsfDirectory(stream, pageSize, pageCount, blockMapAddr, directorySize, directoryPageCount, out byte[] directory))
            {
                return false;
            }

            if (directory.Length < 4)
            {
                return false;
            }

            uint streamCount = ReadUInt32(directory, 0);
            if (streamCount == 0 || streamCount > 2048)
            {
                return false;
            }

            int cursor = 4;
            uint[] streamSizes = new uint[streamCount];
            for (int i = 0; i < streamCount; i++)
            {
                if (cursor + 4 > directory.Length)
                {
                    return false;
                }
                streamSizes[i] = ReadUInt32(directory, cursor);
                cursor += 4;
            }

            List<uint[]> streamPages = new List<uint[]>();
            for (int i = 0; i < streamCount; i++)
            {
                uint size = streamSizes[i];
                if (size == 0xFFFFFFFF)
                {
                    streamPages.Add(Array.Empty<uint>());
                    continue;
                }

                int pageCountForStream = size == 0 ? 0 : (int)((size + pageSize - 1) / pageSize);
                if (cursor + (pageCountForStream * 4) > directory.Length)
                {
                    return false;
                }

                uint[] pages = new uint[pageCountForStream];
                for (int j = 0; j < pageCountForStream; j++)
                {
                    pages[j] = ReadUInt32(directory, cursor);
                    cursor += 4;
                }
                streamPages.Add(pages);
            }

            uint pdbSignature = 0;
            Guid pdbGuid = Guid.Empty;
            uint pdbAge = 0;
            string notes = string.Empty;
            PdbDbiInfo dbiInfo = null;
            PdbTpiInfo tpiInfo = null;
            PdbTpiInfo ipiInfo = null;
            PdbGsiInfo publicsInfo = null;
            PdbGsiInfo globalsInfo = null;
            int symbolRecordCount = 0;
            PdbSymbolRecordInfo[] symbolRecords = Array.Empty<PdbSymbolRecordInfo>();
            string symbolRecordNotes = string.Empty;

            if (streamCount > 1 && streamSizes[1] != 0xFFFFFFFF && streamSizes[1] > 0)
            {
                if (TryReadMsfStreamPartial(stream, pageSize, streamSizes[1], streamPages[1], 64, out byte[] pdbStream))
                {
                    if (!TryParsePdbStream(pdbStream, out pdbSignature, out pdbGuid, out pdbAge, out string pdbNote))
                    {
                        notes = AppendNote(notes, pdbNote);
                    }
                    else if (!string.IsNullOrWhiteSpace(pdbNote))
                    {
                        notes = AppendNote(notes, pdbNote);
                    }
                }
            }

            List<string> publics = new List<string>();
            if (streamCount > 2 && streamSizes[2] != 0xFFFFFFFF && streamSizes[2] > 0)
            {
                if (TryReadMsfStreamPartial(stream, pageSize, streamSizes[2], streamPages[2], 256, out byte[] tpiStream) &&
                    TryParseTpiStream(tpiStream, false, out PdbTpiInfo parsedTpi, out string tpiNote))
                {
                    tpiInfo = parsedTpi;
                    notes = AppendNote(notes, tpiNote);
                }
            }

            if (streamCount > 4 && streamSizes[4] != 0xFFFFFFFF && streamSizes[4] > 0)
            {
                if (TryReadMsfStreamPartial(stream, pageSize, streamSizes[4], streamPages[4], 256, out byte[] ipiStream) &&
                    TryParseTpiStream(ipiStream, true, out PdbTpiInfo parsedIpi, out string ipiNote))
                {
                    ipiInfo = parsedIpi;
                    notes = AppendNote(notes, ipiNote);
                }
            }

            int dbiStreamIndex = -1;
            if (streamCount > 3 && streamSizes[3] != 0xFFFFFFFF && streamSizes[3] > 0)
            {
                if (TryReadMsfStreamPartial(stream, pageSize, streamSizes[3], streamPages[3], 128, out byte[] dbiStream) &&
                    TryParseDbiStream(dbiStream, out dbiInfo, out string dbiNote))
                {
                    dbiStreamIndex = 3;
                    notes = AppendNote(notes, dbiNote);
                }
            }

            if (dbiInfo == null)
            {
                for (int i = 0; i < streamCount; i++)
                {
                    if (streamSizes[i] == 0 || streamSizes[i] == 0xFFFFFFFF)
                    {
                        continue;
                    }
                    if (!TryReadMsfStreamPartial(stream, pageSize, streamSizes[i], streamPages[i], 128, out byte[] dbiCandidate))
                    {
                        continue;
                    }

                    if (TryParseDbiStream(dbiCandidate, out dbiInfo, out string dbiNote))
                    {
                        dbiStreamIndex = i;
                        notes = AppendNote(notes, dbiNote);
                        break;
                    }
                }
            }

            if (dbiInfo != null)
            {
                int publicStreamIndex = dbiInfo.PublicStreamIndex;
                if (publicStreamIndex >= 0 && publicStreamIndex < streamCount)
                {
                    if (TryReadMsfStreamPartial(stream, pageSize, streamSizes[publicStreamIndex], streamPages[publicStreamIndex], 65536, out byte[] publicStream))
                    {
                        publicsInfo = TryParseGsiStream(publicStream, "Publics", publicStreamIndex, streamSizes[publicStreamIndex], out string gsiNote, publics);
                        notes = AppendNote(notes, gsiNote);
                    }
                }

                int globalStreamIndex = dbiInfo.GlobalStreamIndex;
                if (globalStreamIndex >= 0 && globalStreamIndex < streamCount)
                {
                    if (TryReadMsfStreamPartial(stream, pageSize, streamSizes[globalStreamIndex], streamPages[globalStreamIndex], 32768, out byte[] globalStream))
                    {
                        globalsInfo = TryParseGsiStream(globalStream, "Globals", globalStreamIndex, streamSizes[globalStreamIndex], out string gsiNote, null);
                        notes = AppendNote(notes, gsiNote);
                    }
                }

                int symStreamIndex = dbiInfo.SymRecordStreamIndex;
                if (symStreamIndex >= 0 && symStreamIndex < streamCount &&
                    streamSizes[symStreamIndex] != 0xFFFFFFFF && streamSizes[symStreamIndex] > 0)
                {
                    int maxBytes = 512 * 1024;
                    if (TryReadMsfStreamPartial(stream, pageSize, streamSizes[symStreamIndex], streamPages[symStreamIndex], maxBytes, out byte[] symStream))
                    {
                        string symNote = string.Empty;
                        if (TryParsePdbSymbolRecords(symStream, out int totalSymbols, out PdbSymbolRecordInfo[] parsedRecords, out symNote))
                        {
                            symbolRecordCount = totalSymbols;
                            symbolRecords = parsedRecords ?? Array.Empty<PdbSymbolRecordInfo>();
                            symbolRecordNotes = symNote ?? string.Empty;
                            notes = AppendNote(notes, symNote);
                        }
                        else if (!string.IsNullOrWhiteSpace(symNote))
                        {
                            symbolRecordNotes = symNote;
                            notes = AppendNote(notes, symNote);
                        }
                    }
                }
            }

            if (publics.Count == 0)
            {
                for (int i = 2; i < streamCount; i++)
                {
                    if (streamSizes[i] == 0 || streamSizes[i] == 0xFFFFFFFF)
                    {
                        continue;
                    }

                    if (TryReadMsfStreamPartial(stream, pageSize, streamSizes[i], streamPages[i], 8192, out byte[] candidate))
                    {
                        if (TryParsePublicsStream(candidate, publics))
                        {
                            if (publicsInfo == null)
                            {
                                publicsInfo = new PdbGsiInfo("Publics", i, streamSizes[i], ReadUInt32(candidate, 0), ReadUInt32(candidate, 4), publics.ToArray(), string.Empty);
                            }
                            break;
                        }
                    }
                }
            }

            info = new PdbInfo(
                path,
                format,
                pageSize,
                streamCount,
                directorySize,
                pdbSignature,
                pdbGuid,
                pdbAge,
                publics.Count,
                publics.ToArray(),
                symbolRecordCount,
                symbolRecords,
                symbolRecordNotes,
                dbiInfo,
                tpiInfo,
                ipiInfo,
                publicsInfo,
                globalsInfo,
                notes);
            return true;
        }

        private static bool TryReadMsfDirectory(
            FileStream stream,
            uint pageSize,
            uint pageCount,
            uint blockMapAddr,
            uint directorySize,
            uint directoryPageCount,
            out byte[] directory)
        {
            directory = Array.Empty<byte>();
            if (blockMapAddr >= pageCount)
            {
                return false;
            }

            long blockMapOffset = (long)blockMapAddr * pageSize;
            if (blockMapOffset < 0 || blockMapOffset >= stream.Length)
            {
                return false;
            }

            if (blockMapOffset + pageSize > stream.Length)
            {
                return false;
            }

            byte[] blockMap = new byte[pageSize];
            stream.Position = blockMapOffset;
            ReadExactly(stream, blockMap, 0, blockMap.Length);

            uint[] directoryPages = new uint[directoryPageCount];
            int cursor = 0;
            for (int i = 0; i < directoryPageCount; i++)
            {
                if (cursor + 4 > blockMap.Length)
                {
                    return false;
                }

                directoryPages[i] = ReadUInt32(blockMap, cursor);
                cursor += 4;
            }

            directory = new byte[directorySize];
            int destOffset = 0;
            for (int i = 0; i < directoryPages.Length; i++)
            {
                uint page = directoryPages[i];
                if (page >= pageCount)
                {
                    return false;
                }

                long pageOffset = (long)page * pageSize;
                if (pageOffset < 0 || pageOffset >= stream.Length)
                {
                    return false;
                }

                stream.Position = pageOffset;
                int toRead = (int)Math.Min(pageSize, (uint)directory.Length - (uint)destOffset);
                int pageRead = stream.Read(directory, destOffset, toRead);
                if (pageRead <= 0)
                {
                    return false;
                }

                destOffset += pageRead;
                if (destOffset >= directory.Length)
                {
                    break;
                }
            }

            return true;
        }

        private static bool TryReadMsfStreamPartial(
            FileStream stream,
            uint pageSize,
            uint streamSize,
            uint[] pages,
            int maxBytes,
            out byte[] data)
        {
            data = Array.Empty<byte>();
            if (streamSize == 0 || pages == null || pages.Length == 0)
            {
                return false;
            }

            int targetSize = streamSize > int.MaxValue ? int.MaxValue : (int)streamSize;
            targetSize = Math.Min(targetSize, maxBytes);
            if (targetSize <= 0)
            {
                return false;
            }

            data = new byte[targetSize];
            int offset = 0;
            for (int i = 0; i < pages.Length && offset < targetSize; i++)
            {
                long pageOffset = (long)pages[i] * pageSize;
                if (pageOffset < 0 || pageOffset >= stream.Length)
                {
                    return false;
                }

                stream.Position = pageOffset;
                int toRead = Math.Min((int)pageSize, targetSize - offset);
                int pageRead = stream.Read(data, offset, toRead);
                if (pageRead <= 0)
                {
                    return false;
                }

                offset += pageRead;
            }

            return offset > 0;
        }

        private static bool TryParsePdbStream(ReadOnlySpan<byte> data, out uint signature, out Guid guid, out uint age, out string note)
        {
            signature = 0;
            guid = Guid.Empty;
            age = 0;
            note = string.Empty;
            if (data.Length < 8)
            {
                note = "PDB stream too small.";
                return false;
            }

            if (data.Length >= 24)
            {
                signature = ReadUInt32(data, 0);
                guid = new Guid(data.Slice(4, 16).ToArray());
                age = ReadUInt32(data, 20);
                if (guid != Guid.Empty || age != 0)
                {
                    return true;
                }

                signature = ReadUInt32(data, 0);
                age = ReadUInt32(data, 4);
                guid = new Guid(data.Slice(8, 16).ToArray());
                note = "PDB stream used legacy layout.";
                return true;
            }

            signature = ReadUInt32(data, 0);
            age = ReadUInt32(data, 4);
            return true;
        }

        private static bool TryParseDbiStream(ReadOnlySpan<byte> data, out PdbDbiInfo info, out string note)
        {
            info = null;
            note = string.Empty;
            if (data.Length < 64)
            {
                note = "DBI stream too small.";
                return false;
            }

            int signature = ReadInt32(data, 0);
            int version = ReadInt32(data, 4);
            int age = ReadInt32(data, 8);
            ushort globalStreamIndex = ReadUInt16(data, 12);
            ushort buildNumber = ReadUInt16(data, 14);
            ushort publicStreamIndex = ReadUInt16(data, 16);
            ushort pdbDllVersion = ReadUInt16(data, 18);
            ushort symRecordStreamIndex = ReadUInt16(data, 20);
            ushort pdbDllRbld = ReadUInt16(data, 22);
            int moduleInfoSize = ReadInt32(data, 24);
            int sectionContribSize = ReadInt32(data, 28);
            int sectionMapSize = ReadInt32(data, 32);
            int sourceInfoSize = ReadInt32(data, 36);
            int typeServerSize = ReadInt32(data, 40);
            int mfcTypeServerIndex = ReadInt32(data, 44);
            int optionalDbgHeaderSize = ReadInt32(data, 48);
            int ecSubstreamSize = ReadInt32(data, 52);
            ushort flags = ReadUInt16(data, 56);
            ushort machine = ReadUInt16(data, 58);
            int reserved = ReadInt32(data, 60);

            if (moduleInfoSize < 0 || sectionContribSize < 0 || sectionMapSize < 0 || sourceInfoSize < 0 ||
                typeServerSize < 0 || optionalDbgHeaderSize < 0 || ecSubstreamSize < 0)
            {
                note = "DBI stream contains negative sizes.";
            }
            if (signature == 0 && version == 0)
            {
                note = AppendNote(note, "DBI signature/version are zero.");
            }

            info = new PdbDbiInfo(
                signature,
                version,
                age,
                globalStreamIndex,
                publicStreamIndex,
                symRecordStreamIndex,
                machine,
                flags,
                moduleInfoSize,
                sectionContribSize,
                sectionMapSize,
                sourceInfoSize,
                optionalDbgHeaderSize,
                typeServerSize,
                ecSubstreamSize,
                AppendNote(note, $"Build={buildNumber}, PdbDll={pdbDllVersion}, Rbld={pdbDllRbld}, MfcIdx={mfcTypeServerIndex}, Reserved={reserved}"));
            return true;
        }

        private static bool TryParseTpiStream(ReadOnlySpan<byte> data, bool isIpi, out PdbTpiInfo info, out string note)
        {
            info = null;
            note = string.Empty;
            if (data.Length < 56)
            {
                note = (isIpi ? "IPI" : "TPI") + " stream too small.";
                return false;
            }

            uint version = ReadUInt32(data, 0);
            uint headerSize = ReadUInt32(data, 4);
            uint typeIndexBegin = ReadUInt32(data, 8);
            uint typeIndexEnd = ReadUInt32(data, 12);
            uint typeRecordBytes = ReadUInt32(data, 16);
            ushort hashStreamIndex = ReadUInt16(data, 20);
            ushort hashAuxStreamIndex = ReadUInt16(data, 22);
            uint hashKeySize = ReadUInt32(data, 24);
            uint hashBucketCount = ReadUInt32(data, 28);
            uint hashValueBufferOffset = ReadUInt32(data, 32);
            uint hashValueBufferLength = ReadUInt32(data, 36);
            uint indexOffsetBufferOffset = ReadUInt32(data, 40);
            uint indexOffsetBufferLength = ReadUInt32(data, 44);
            uint hashAdjBufferOffset = ReadUInt32(data, 48);
            uint hashAdjBufferLength = ReadUInt32(data, 52);

            if (headerSize < 56)
            {
                note = AppendNote(note, (isIpi ? "IPI" : "TPI") + " header size is smaller than expected.");
            }
            if (typeIndexEnd < typeIndexBegin)
            {
                note = AppendNote(note, (isIpi ? "IPI" : "TPI") + " type index range is invalid.");
            }

            info = new PdbTpiInfo(
                version,
                headerSize,
                typeIndexBegin,
                typeIndexEnd,
                typeRecordBytes,
                hashStreamIndex,
                hashAuxStreamIndex,
                hashKeySize,
                hashBucketCount,
                hashValueBufferLength,
                indexOffsetBufferLength,
                hashAdjBufferLength,
                AppendNote(note, $"HashValueOffset={hashValueBufferOffset}, IndexOffset={indexOffsetBufferOffset}, HashAdjOffset={hashAdjBufferOffset}"));
            return true;
        }

        private static PdbGsiInfo TryParseGsiStream(
            ReadOnlySpan<byte> data,
            string kind,
            int streamIndex,
            uint streamSize,
            out string note,
            List<string> names)
        {
            note = string.Empty;
            if (data.Length == 0)
            {
                return null;
            }

            List<string> localNames = names ?? new List<string>();
            if (localNames.Count == 0)
            {
                TryParsePublicsStream(data, localNames);
            }
            if (localNames.Count == 0)
            {
                ExtractSymbolNames(data, localNames, 50);
            }

            uint signature = ReadUInt32(data, 0);
            uint version = data.Length >= 8 ? ReadUInt32(data, 4) : 0;
            if (localNames.Count == 0 && signature == 0 && version == 0)
            {
                note = AppendNote(note, kind + " stream did not yield symbols.");
            }

            return new PdbGsiInfo(
                kind,
                streamIndex,
                streamSize,
                signature,
                version,
                localNames.ToArray(),
                note);
        }

        private static void ExtractSymbolNames(ReadOnlySpan<byte> data, List<string> names, int maxNames)
        {
            if (data.Length == 0 || names == null || maxNames <= 0)
            {
                return;
            }

            int cursor = 0;
            while (cursor < data.Length && names.Count < maxNames)
            {
                while (cursor < data.Length && (data[cursor] < 0x20 || data[cursor] > 0x7E))
                {
                    cursor++;
                }

                int start = cursor;
                while (cursor < data.Length && data[cursor] >= 0x20 && data[cursor] <= 0x7E)
                {
                    cursor++;
                }

                int length = cursor - start;
                if (length >= 2 && length <= 256)
                {
                    ReadOnlySpan<byte> slice = data.Slice(start, length);
                    if (IsLikelySymbolName(slice))
                    {
                        names.Add(Encoding.ASCII.GetString(slice));
                    }
                }
            }
        }

        private static bool IsLikelySymbolName(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                return false;
            }

            bool hasAlpha = false;
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                bool isAlpha = (b >= (byte)'A' && b <= (byte)'Z') ||
                               (b >= (byte)'a' && b <= (byte)'z');
                bool isDigit = b >= (byte)'0' && b <= (byte)'9';
                if (isAlpha)
                {
                    hasAlpha = true;
                }
                if (!isAlpha && !isDigit && b != (byte)'_' && b != (byte)'@' && b != (byte)'?' &&
                    b != (byte)'$' && b != (byte)'.' && b != (byte)':' && b != (byte)'~')
                {
                    return false;
                }
            }

            return hasAlpha;
        }

        private static bool TryParsePublicsStream(ReadOnlySpan<byte> data, List<string> publics)
        {
            if (data.Length < 8 || publics == null)
            {
                return false;
            }

            int cursor = 0;
            if (HasPrefix(data, Encoding.ASCII.GetBytes("PUBLICS\0")))
            {
                cursor = 8;
            }
            else if (HasPrefix(data, Encoding.ASCII.GetBytes("PUBS\0")))
            {
                cursor = 5;
            }
            else
            {
                return false;
            }

            while (cursor < data.Length && publics.Count < 50)
            {
                int start = cursor;
                while (cursor < data.Length && data[cursor] != 0)
                {
                    cursor++;
                }

                int length = cursor - start;
                if (length >= 2 && length <= 256)
                {
                    string name = Encoding.ASCII.GetString(data.Slice(start, length));
                    if (IsAsciiIdentifier(Encoding.ASCII.GetBytes(name)))
                    {
                        publics.Add(name);
                    }
                }

                cursor++;
            }

            return publics.Count > 0;
        }

        private const int MaxPdbSymbolRecords = 200;

        private static bool TryParsePdbSymbolRecords(
            ReadOnlySpan<byte> data,
            out int totalCount,
            out PdbSymbolRecordInfo[] records,
            out string note)
        {
            totalCount = 0;
            records = Array.Empty<PdbSymbolRecordInfo>();
            note = string.Empty;

            if (data.Length < 4)
            {
                note = "Symbol record stream too small.";
                return false;
            }

            List<PdbSymbolRecordInfo> entries = new List<PdbSymbolRecordInfo>();
            int cursor = 0;
            int guard = 0;
            while (cursor + 4 <= data.Length && guard++ < 200000)
            {
                ushort length = ReadUInt16(data, cursor);
                if (length == 0)
                {
                    cursor += 2;
                    if ((cursor & 1) != 0)
                    {
                        cursor++;
                    }
                    continue;
                }

                int recordEnd = cursor + 2 + length;
                if (recordEnd > data.Length)
                {
                    note = AppendNote(note, "Symbol record truncated.");
                    break;
                }

                ushort recordType = ReadUInt16(data, cursor + 2);
                ReadOnlySpan<byte> recordData = data.Slice(cursor + 4, length - 2);
                string recordTypeName = GetPdbSymbolRecordTypeName(recordType);
                string kind = GetPdbSymbolRecordKind(recordType);
                ushort segment = 0;
                uint offset = 0;
                uint typeIndex = 0;
                string name = string.Empty;
                string recordNote = string.Empty;

                if (TryDecodePdbSymbolRecord(recordType, recordData, out segment, out offset, out typeIndex, out int nameOffset))
                {
                    name = ReadPdbSymbolName(recordData, nameOffset);
                }
                else
                {
                    name = ReadPdbSymbolName(recordData, 0);
                }

                if (string.IsNullOrWhiteSpace(name) && nameOffset >= 0 && recordData.Length >= nameOffset + 4)
                {
                    uint stringOffset = ReadUInt32(recordData, nameOffset);
                    if (stringOffset != 0)
                    {
                        recordNote = "string-table:0x" + stringOffset.ToString("X8", CultureInfo.InvariantCulture);
                    }
                }

                totalCount++;
                if (entries.Count < MaxPdbSymbolRecords)
                {
                    entries.Add(new PdbSymbolRecordInfo(
                        kind,
                        recordType,
                        recordTypeName,
                        name,
                        segment,
                        offset,
                        typeIndex,
                        recordNote));
                }

                cursor = recordEnd;
                if ((cursor & 1) != 0)
                {
                    cursor++;
                }
            }

            records = entries.ToArray();
            if (totalCount > records.Length)
            {
                note = AppendNote(note, $"Symbol records truncated to {records.Length} entries.");
            }

            return totalCount > 0;
        }

        private static bool TryDecodePdbSymbolRecord(
            ushort recordType,
            ReadOnlySpan<byte> data,
            out ushort segment,
            out uint offset,
            out uint typeIndex,
            out int nameOffset)
        {
            segment = 0;
            offset = 0;
            typeIndex = 0;
            nameOffset = -1;

            switch (recordType)
            {
                case 0x110E: // S_PUB32
                case 0x100E: // S_PUB32_ST
                    if (data.Length < 10)
                    {
                        return false;
                    }
                    offset = ReadUInt32(data, 4);
                    segment = ReadUInt16(data, 8);
                    nameOffset = 10;
                    return true;
                case 0x110D: // S_GDATA32
                case 0x100D: // S_GDATA32_ST
                case 0x110C: // S_LDATA32
                case 0x100C: // S_LDATA32_ST
                    if (data.Length < 10)
                    {
                        return false;
                    }
                    typeIndex = ReadUInt32(data, 0);
                    offset = ReadUInt32(data, 4);
                    segment = ReadUInt16(data, 8);
                    nameOffset = 10;
                    return true;
                case 0x110F: // S_GPROC32
                case 0x1110: // S_LPROC32
                case 0x1147: // S_GPROC32_ID
                case 0x1148: // S_LPROC32_ID
                case 0x1112: // S_GPROC32_32? (compat)
                    if (data.Length < 35)
                    {
                        return false;
                    }
                    typeIndex = ReadUInt32(data, 24);
                    offset = ReadUInt32(data, 28);
                    segment = ReadUInt16(data, 32);
                    nameOffset = 35;
                    return true;
                case 0x113E: // S_LOCAL
                    if (data.Length < 8)
                    {
                        return false;
                    }
                    typeIndex = ReadUInt32(data, 0);
                    nameOffset = 8;
                    return true;
                default:
                    return false;
            }
        }

        private static string ReadPdbSymbolName(ReadOnlySpan<byte> data, int offset)
        {
            if (offset < 0 || offset >= data.Length)
            {
                return string.Empty;
            }

            ReadOnlySpan<byte> slice = data.Slice(offset);
            int nullIndex = slice.IndexOf((byte)0);
            if (nullIndex > 0)
            {
                return ReadAsciiSymbol(slice.Slice(0, nullIndex));
            }

            if (slice.Length > 1 && slice[0] > 0 && slice[0] < slice.Length)
            {
                int len = slice[0];
                return ReadAsciiSymbol(slice.Slice(1, len));
            }

            return ReadAsciiSymbol(slice);
        }

        private static string ReadAsciiSymbol(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                return string.Empty;
            }

            int length = Math.Min(data.Length, 256);
            ReadOnlySpan<byte> slice = data.Slice(0, length);
            for (int i = 0; i < slice.Length; i++)
            {
                byte b = slice[i];
                if (b < 0x20 || b > 0x7E)
                {
                    return string.Empty;
                }
            }

            return Encoding.ASCII.GetString(slice);
        }

        private static string GetPdbSymbolRecordKind(ushort recordType)
        {
            switch (recordType)
            {
                case 0x110E:
                case 0x100E:
                    return "Public";
                case 0x110D:
                case 0x100D:
                    return "Global";
                case 0x110C:
                case 0x100C:
                case 0x113E:
                    return "Local";
                case 0x110F:
                case 0x1110:
                case 0x1147:
                case 0x1148:
                case 0x1112:
                    return "Proc";
                default:
                    return "Other";
            }
        }

        private static string GetPdbSymbolRecordTypeName(ushort recordType)
        {
            switch (recordType)
            {
                case 0x110E: return "S_PUB32";
                case 0x100E: return "S_PUB32_ST";
                case 0x110D: return "S_GDATA32";
                case 0x100D: return "S_GDATA32_ST";
                case 0x110C: return "S_LDATA32";
                case 0x100C: return "S_LDATA32_ST";
                case 0x110F: return "S_GPROC32";
                case 0x1110: return "S_LPROC32";
                case 0x1147: return "S_GPROC32_ID";
                case 0x1148: return "S_LPROC32_ID";
                case 0x1112: return "S_GPROC32_32";
                case 0x113E: return "S_LOCAL";
                default: return "0x" + recordType.ToString("X4", CultureInfo.InvariantCulture);
            }
        }

        private bool TryGetFileOffset(List<IMAGE_SECTION_HEADER> sections, uint rva, uint size, out long fileOffset)
        {
            fileOffset = -1;
            if (!TryGetSectionByRvaRange(sections, rva, size, out IMAGE_SECTION_HEADER section))
            {
                return false;
            }

            return TryMapRvaToFileOffset(rva, section.VirtualAddress, section.VirtualSize, section.PointerToRawData, section.SizeOfRawData, PEFileStream.Length, out fileOffset);
        }

        private static bool TryMapRvaToFileOffset(
            uint rva,
            uint sectionVirtualAddress,
            uint sectionVirtualSize,
            uint sectionRawPointer,
            uint sectionRawSize,
            long fileLength,
            out long fileOffset)
        {
            fileOffset = -1;
            uint sectionSize = Math.Max(sectionVirtualSize, sectionRawSize);
            if (sectionSize == 0)
            {
                return false;
            }

            ulong sectionStart = sectionVirtualAddress;
            ulong sectionEnd = sectionStart + sectionSize;
            if (rva < sectionStart || rva >= sectionEnd)
            {
                return false;
            }

            fileOffset = (long)(rva - sectionVirtualAddress) + sectionRawPointer;
            return fileOffset >= 0 && fileOffset <= fileLength;
        }

        internal static bool TryGetFileOffsetForTest(IReadOnlyList<SectionRange> sections, uint rva, long fileLength, out long fileOffset)
        {
            fileOffset = -1;
            if (sections == null)
            {
                return false;
            }

            foreach (SectionRange section in sections)
            {
                if (TryMapRvaToFileOffset(rva, section.VirtualAddress, section.VirtualSize, section.RawPointer, section.RawSize, fileLength, out fileOffset))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool TryGetSectionByRva(List<IMAGE_SECTION_HEADER> sections, uint rva, out IMAGE_SECTION_HEADER result)
        {
            foreach (IMAGE_SECTION_HEADER section in sections)
            {
                uint sectionSize = GetSectionSpan(section);
                if (sectionSize == 0)
                {
                    continue;
                }

                uint sectionStart = section.VirtualAddress;
                uint sectionEnd = sectionStart + sectionSize;
                if (rva >= sectionStart && rva < sectionEnd)
                {
                    result = section;
                    return true;
                }
            }

            result = default;
            return false;
        }

        private static bool TryGetSectionIndexByRva(
            List<IMAGE_SECTION_HEADER> sections,
            uint rva,
            out int index,
            out IMAGE_SECTION_HEADER result)
        {
            index = -1;
            if (sections == null)
            {
                result = default;
                return false;
            }

            for (int i = 0; i < sections.Count; i++)
            {
                IMAGE_SECTION_HEADER section = sections[i];
                uint sectionSize = GetSectionSpan(section);
                if (sectionSize == 0)
                {
                    continue;
                }

                uint sectionStart = section.VirtualAddress;
                uint sectionEnd = sectionStart + sectionSize;
                if (rva >= sectionStart && rva < sectionEnd)
                {
                    index = i;
                    result = section;
                    return true;
                }
            }

            result = default;
            return false;
        }

        private static bool TryGetSectionByRvaRange(List<IMAGE_SECTION_HEADER> sections, uint rva, uint size, out IMAGE_SECTION_HEADER result)
        {
            foreach (IMAGE_SECTION_HEADER section in sections)
            {
                uint sectionSize = GetSectionSpan(section);
                if (sectionSize == 0)
                {
                    continue;
                }

                uint sectionStart = section.VirtualAddress;
                uint sectionEnd = sectionStart + sectionSize;
                if (rva < sectionStart || rva >= sectionEnd)
                {
                    continue;
                }

                if (size == 0)
                {
                    result = section;
                    return true;
                }

                ulong end = (ulong)rva + size;
                if (end <= sectionEnd)
                {
                    result = section;
                    return true;
                }
            }

            result = default;
            return false;
        }

        private static string GetDataDirectoryName(int index)
        {
            if (index >= 0 && index < DataDirectoryNames.Length)
            {
                return DataDirectoryNames[index];
            }

            return "Directory" + index.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        private static string DecodeUtf8WithLatin1Fallback(ReadOnlySpan<byte> bytes, out bool usedFallback)
        {
            try
            {
                usedFallback = false;
                return StrictUtf8.GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                usedFallback = true;
                return Encoding.Latin1.GetString(bytes);
            }
        }

        private static string DecodeCoffShortNameUtf8WithFallback(ReadOnlySpan<byte> bytes, out bool usedFallback)
        {
            int length = bytes.Length;
            while (length > 0 && bytes[length - 1] == 0)
            {
                length--;
            }

            if (length <= 0)
            {
                usedFallback = false;
                return string.Empty;
            }

            ReadOnlySpan<byte> slice = bytes.Slice(0, length);
            return DecodeUtf8WithLatin1Fallback(slice, out usedFallback);
        }

        private static string NormalizeSectionName(IMAGE_SECTION_HEADER section)
        {
            if (section.Name == null || section.Name.Length == 0)
            {
                return string.Empty;
            }

            return DecodeCoffShortNameUtf8WithFallback(section.Name, out bool _);
        }

        private void BuildDataDirectoryInfos(IMAGE_DATA_DIRECTORY[] directories, List<IMAGE_SECTION_HEADER> sections, bool isPe32Plus)
        {
            if (directories == null || directories.Length == 0)
            {
                _dataDirectoryInfos = Array.Empty<DataDirectoryInfo>();
                _architectureDirectory = null;
                _globalPtrDirectory = null;
                _iatDirectory = null;
                return;
            }

            DataDirectoryInfo[] infos = new DataDirectoryInfo[directories.Length];
            for (int i = 0; i < directories.Length; i++)
            {
                IMAGE_DATA_DIRECTORY directory = directories[i];
                bool mapped = false;
                string sectionName = string.Empty;
                uint sectionRva = 0;
                uint sectionSize = 0;
                if (directory.Size > 0 &&
                    TryGetSectionByRvaRange(sections, directory.VirtualAddress, directory.Size, out IMAGE_SECTION_HEADER section))
                {
                    mapped = true;
                    sectionName = NormalizeSectionName(section);
                    sectionRva = section.VirtualAddress;
                    sectionSize = GetSectionSpan(section);
                }

                infos[i] = new DataDirectoryInfo(
                    i,
                    GetDataDirectoryName(i),
                    directory.VirtualAddress,
                    directory.Size,
                    mapped,
                    sectionName,
                    sectionRva,
                    sectionSize);
            }

            _dataDirectoryInfos = infos;

            _architectureDirectory = BuildArchitectureDirectoryInfo(directories, sections);
            _globalPtrDirectory = BuildGlobalPtrDirectoryInfo(directories, sections, isPe32Plus);
            _iatDirectory = BuildIatDirectoryInfo(directories, sections, isPe32Plus);
            BuildDataDirectoryValidations(directories, sections, isPe32Plus);
        }

        private void BuildDataDirectoryValidations(IMAGE_DATA_DIRECTORY[] directories, List<IMAGE_SECTION_HEADER> sections, bool isPe32Plus)
        {
            _dataDirectoryValidations.Clear();
            if (directories == null || directories.Length == 0)
            {
                return;
            }

            for (int i = 0; i < directories.Length; i++)
            {
                IMAGE_DATA_DIRECTORY directory = directories[i];
                DataDirectoryInfo info = i < _dataDirectoryInfos.Length ? _dataDirectoryInfos[i] : null;
                string name = info?.Name ?? GetDataDirectoryName(i);
                bool usesFileOffset = i == 4; // Security directory uses file offset, not RVA

                IMAGE_SECTION_HEADER startSection = default;
                bool startMapped = false;
                uint sectionRva = info?.SectionRva ?? 0;
                uint sectionSize = info?.SectionSize ?? 0;
                string sectionName = info?.SectionName ?? string.Empty;
                if (directory.Size > 0 && TryGetSectionByRva(sections, directory.VirtualAddress, out startSection))
                {
                    startMapped = true;
                    sectionRva = startSection.VirtualAddress;
                    sectionSize = GetSectionSpan(startSection);
                    if (string.IsNullOrWhiteSpace(sectionName))
                    {
                        sectionName = NormalizeSectionName(startSection.Section);
                    }
                }

                _dataDirectoryValidations.Add(BuildDataDirectoryValidationCore(
                    i,
                    name,
                    directory.VirtualAddress,
                    directory.Size,
                    isPe32Plus,
                    startMapped && directory.Size > 0,
                    sectionRva,
                    sectionSize,
                    sectionName,
                    usesFileOffset));
            }
        }

        internal static DataDirectoryValidationInfo BuildDataDirectoryValidationForTest(
            int index,
            uint virtualAddress,
            uint size,
            bool isPe32Plus,
            bool startMapped,
            uint sectionRva,
            uint sectionSize,
            string sectionName)
        {
            string name = GetDataDirectoryName(index);
            bool usesFileOffset = index == 4;

            return BuildDataDirectoryValidationCore(
                index,
                name,
                virtualAddress,
                size,
                isPe32Plus,
                startMapped && size > 0,
                sectionRva,
                sectionSize,
                sectionName,
                usesFileOffset);
        }

        private static DataDirectoryValidationInfo BuildDataDirectoryValidationCore(
            int index,
            string name,
            uint virtualAddress,
            uint size,
            bool isPe32Plus,
            bool startMapped,
            uint sectionRva,
            uint sectionSize,
            string sectionName,
            bool usesFileOffset)
        {
            string notes = string.Empty;
            if (usesFileOffset && size > 0)
            {
                notes = AppendNote(notes, "uses file offset (WIN_CERTIFICATE)");
            }

            if (index == 7 && (virtualAddress != 0 || size != 0))
            {
                notes = AppendNote(notes, "SPEC violation: Architecture directory is reserved and must be zero");
            }
            else if (index == 8 && size != 0)
            {
                notes = AppendNote(notes, "SPEC violation: GlobalPtr directory Size must be zero");
            }
            else if (index == 15 && (virtualAddress != 0 || size != 0))
            {
                notes = AppendNote(notes, "SPEC violation: Reserved directory entry must be zero");
            }

            bool fullyMapped = false;
            if (startMapped && size > 0)
            {
                ulong endRva = (ulong)virtualAddress + size;
                ulong sectionEnd = (ulong)sectionRva + sectionSize;
                fullyMapped = endRva <= sectionEnd;
                if (!fullyMapped && !usesFileOffset)
                {
                    notes = AppendNote(notes, "directory spans beyond section");
                }
            }

            if (size > 0 && !startMapped && !usesFileOffset)
            {
                notes = AppendNote(notes, "RVA not mapped to a section");
            }

            (uint minSize, uint entrySize) = GetDataDirectorySizeExpectations(index, isPe32Plus);
            bool sizePlausible = size == 0 || size >= minSize;
            if (!sizePlausible)
            {
                notes = AppendNote(notes, "size below minimum header size");
            }

            bool sizeAligned = entrySize == 0 || size == 0 || (size % entrySize) == 0;
            if (!sizeAligned && entrySize > 0)
            {
                notes = AppendNote(notes, "size not aligned to entry size");
            }

            uint directoryEndRva = size == 0 ? virtualAddress : virtualAddress + size;
            uint sectionEndRva = sectionSize == 0 ? sectionRva : sectionRva + sectionSize;

            return new DataDirectoryValidationInfo(
                index,
                name,
                virtualAddress,
                size,
                startMapped,
                fullyMapped,
                sectionName,
                sectionRva,
                sectionSize,
                directoryEndRva,
                sectionEndRva,
                minSize,
                entrySize,
                sizeAligned,
                sizePlausible,
                usesFileOffset,
                notes);
        }

        private static (uint MinSize, uint EntrySize) GetDataDirectorySizeExpectations(int index, bool isPe32Plus)
        {
            switch (index)
            {
                case 0: // Export
                    return (40, 0);
                case 1: // Import
                    return (20, 20);
                case 2: // Resource
                    return (16, 0);
                case 3: // Exception
                    return (12, 12);
                case 4: // Security
                    return (8, 8);
                case 5: // Base Reloc
                    return (8, 4);
                case 6: // Debug
                    return (28, 28);
                case 7: // Architecture
                    return (24, 0);
                case 8: // GlobalPtr
                    return (isPe32Plus ? 8u : 4u, isPe32Plus ? 8u : 4u);
                case 9: // TLS
                    return (isPe32Plus ? 40u : 24u, 0);
                case 10: // Load config
                    return (isPe32Plus ? 0x40u : 0x40u, 0);
                case 11: // Bound import
                    return (8, 8);
                case 12: // IAT
                    return (isPe32Plus ? 8u : 4u, isPe32Plus ? 8u : 4u);
                case 13: // Delay import
                    return (32, 32);
                case 14: // CLR
                    return (72, 0);
                default:
                    return (0, 0);
            }
        }

        private ArchitectureDirectoryInfo BuildArchitectureDirectoryInfo(
            IMAGE_DATA_DIRECTORY[] directories,
            List<IMAGE_SECTION_HEADER> sections)
        {
            const int index = 7;
            if (directories == null || index >= directories.Length)
            {
                return null;
            }

            IMAGE_DATA_DIRECTORY directory = directories[index];
            if (directory.Size == 0 && directory.VirtualAddress == 0)
            {
                return null;
            }

            IMAGE_SECTION_HEADER section = default;
            bool mapped = directory.Size > 0 &&
                          TryGetSectionByRvaRange(sections, directory.VirtualAddress, directory.Size, out section);
            string sectionName = mapped ? NormalizeSectionName(section) : string.Empty;
            if (directory.Size > 0 && !mapped)
            {
                Warn(ParseIssueCategory.OptionalHeader, $"{GetDataDirectoryName(index)} directory is not mapped to a section.");
            }
            bool parsed = false;
            uint magic = 0;
            uint major = 0;
            uint minor = 0;
            uint sizeOfData = 0;
            uint firstEntryRva = 0;
            uint numberOfEntries = 0;
            List<ArchitectureDirectoryEntryInfo> entries = new List<ArchitectureDirectoryEntryInfo>();
            int parsedEntryCount = 0;
            bool entriesTruncated = false;
            if (mapped && directory.Size >= 24 &&
                TryGetFileOffset(sections, directory.VirtualAddress, out long archOffset) &&
                TrySetPosition(archOffset, 24))
            {
                byte[] buffer = new byte[24];
                ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                parsed = TryParseArchitectureHeader(buffer, out magic, out major, out minor, out sizeOfData, out firstEntryRva, out numberOfEntries);
                if (parsed && numberOfEntries > 0 && firstEntryRva != 0)
                {
                    uint entrySize = 8;
                    uint maxEntriesBySize = sizeOfData > 0 ? sizeOfData / entrySize : 0;
                    if (maxEntriesBySize == 0 && directory.Size > 24)
                    {
                        maxEntriesBySize = (directory.Size - 24) / entrySize;
                    }

                    uint toRead = maxEntriesBySize > 0 ? Math.Min(numberOfEntries, maxEntriesBySize) : numberOfEntries;
                    int maxEntries = 64;
                    entriesTruncated = toRead > maxEntries;
                    int readCount = (int)Math.Min(toRead, (uint)maxEntries);
                    if (readCount > 0 &&
                        TryGetFileOffset(sections, firstEntryRva, out long entriesOffset) &&
                        TrySetPosition(entriesOffset, readCount * (int)entrySize))
                    {
                        byte[] entryBuffer = new byte[readCount * (int)entrySize];
                        ReadExactly(PEFileStream, entryBuffer, 0, entryBuffer.Length);
                        int cursor = 0;
                        for (int i = 0; i < readCount; i++)
                        {
                            uint fixupRva = ReadUInt32(entryBuffer, cursor);
                            uint newInst = ReadUInt32(entryBuffer, cursor + 4);
                            cursor += (int)entrySize;
                            bool fixupMapped = TryGetSectionByRva(sections, fixupRva, out IMAGE_SECTION_HEADER fixupSection);
                            string fixupSectionName = fixupMapped ? NormalizeSectionName(fixupSection) : string.Empty;
                            entries.Add(new ArchitectureDirectoryEntryInfo(fixupRva, newInst, fixupMapped, fixupSectionName));
                        }
                        parsedEntryCount = entries.Count;
                    }
                    else if (!TryGetFileOffset(sections, firstEntryRva, out _))
                    {
                        Warn(ParseIssueCategory.OptionalHeader, $"{GetDataDirectoryName(index)} entries RVA is not mapped to a section.");
                    }
                }
            }

            return new ArchitectureDirectoryInfo(
                directory.VirtualAddress,
                directory.Size,
                mapped,
                sectionName,
                parsed,
                magic,
                major,
                minor,
                sizeOfData,
                firstEntryRva,
                numberOfEntries,
                parsedEntryCount,
                entriesTruncated,
                entries.ToArray());
        }

        private GlobalPtrDirectoryInfo BuildGlobalPtrDirectoryInfo(
            IMAGE_DATA_DIRECTORY[] directories,
            List<IMAGE_SECTION_HEADER> sections,
            bool isPe32Plus)
        {
            const int index = 8;
            if (directories == null || index >= directories.Length)
            {
                return null;
            }

            IMAGE_DATA_DIRECTORY directory = directories[index];
            if (directory.Size == 0 && directory.VirtualAddress == 0)
            {
                return null;
            }

            IMAGE_SECTION_HEADER section = default;
            bool mapped = directory.VirtualAddress != 0 &&
                          TryGetSectionByRva(sections, directory.VirtualAddress, out section);
            string sectionName = mapped ? NormalizeSectionName(section) : string.Empty;
            if (directory.Size > 0 && !mapped)
            {
                Warn(ParseIssueCategory.OptionalHeader, $"{GetDataDirectoryName(index)} directory is not mapped to a section.");
            }

            bool valueMapped = false;
            ulong value = 0;
            bool hasRva = false;
            uint rva = 0;
            string rvaKind = string.Empty;
            bool rvaMapped = false;
            string rvaSectionName = string.Empty;
            int pointerSize = isPe32Plus ? 8 : 4;
            if (mapped && TryGetFileOffset(sections, directory.VirtualAddress, out long gpOffset) &&
                TrySetPosition(gpOffset, pointerSize))
            {
                value = isPe32Plus ? PEFile.ReadUInt64() : PEFile.ReadUInt32();
                valueMapped = true;
                if (TryComputeRvaFromPointer(value, _imageBase, _sizeOfImage, out rva, out rvaKind))
                {
                    hasRva = true;
                    if (TryGetSectionByRva(sections, rva, out IMAGE_SECTION_HEADER rvaSection))
                    {
                        rvaMapped = true;
                        rvaSectionName = NormalizeSectionName(rvaSection);
                    }
                }
            }

            return new GlobalPtrDirectoryInfo(
                directory.VirtualAddress,
                directory.Size,
                mapped,
                sectionName,
                valueMapped,
                value,
                hasRva,
                rva,
                rvaKind,
                rvaMapped,
                rvaSectionName);
        }

        private IatDirectoryInfo BuildIatDirectoryInfo(
            IMAGE_DATA_DIRECTORY[] directories,
            List<IMAGE_SECTION_HEADER> sections,
            bool isPe32Plus)
        {
            const int index = 12;
            if (directories == null || index >= directories.Length)
            {
                return null;
            }

            IMAGE_DATA_DIRECTORY directory = directories[index];
            if (directory.Size == 0 && directory.VirtualAddress == 0)
            {
                return null;
            }

            IMAGE_SECTION_HEADER section = default;
            bool mapped = directory.Size > 0 &&
                          TryGetSectionByRvaRange(sections, directory.VirtualAddress, directory.Size, out section);
            string sectionName = mapped ? NormalizeSectionName(section) : string.Empty;
            if (directory.Size > 0 && !mapped)
            {
                Warn(ParseIssueCategory.OptionalHeader, "IAT directory is not mapped to a section.");
            }

            uint entrySize = isPe32Plus ? 8u : 4u;
            bool sizeAligned = entrySize != 0 && directory.Size % entrySize == 0;
            if (directory.Size > 0 && !sizeAligned)
            {
                Warn(ParseIssueCategory.Imports, "IAT directory size is not aligned to pointer size.");
            }

            uint entryCount = entrySize == 0 ? 0 : directory.Size / entrySize;
            uint nonZeroCount = 0;
            uint zeroCount = 0;
            uint sampleCount = 0;
            bool samplesTruncated = false;
            uint mappedEntryCount = 0;
            List<IatEntryInfo> samples = new List<IatEntryInfo>();
            if (mapped && entrySize > 0 && directory.Size >= entrySize &&
                TryGetFileOffset(sections, directory.VirtualAddress, out long iatOffset))
            {
                CountIatEntries(iatOffset, directory.Size, entrySize, out nonZeroCount, out zeroCount);
                ReadIatSamples(iatOffset, directory.Size, entrySize, sections, out samples, out sampleCount, out samplesTruncated, out mappedEntryCount);
            }

            return new IatDirectoryInfo(
                directory.VirtualAddress,
                directory.Size,
                mapped,
                sectionName,
                entryCount,
                entrySize,
                sizeAligned,
                nonZeroCount,
                zeroCount,
                sampleCount,
                samplesTruncated,
                mappedEntryCount,
                samples.ToArray());
        }

        private void ParseCoffSymbolTable(uint pointerToSymbolTable, uint numberOfSymbols, List<IMAGE_SECTION_HEADER> sections)
        {
            if (pointerToSymbolTable == 0 || numberOfSymbols == 0)
            {
                return;
            }

            if (PEFileStream == null)
            {
                return;
            }

            long fileLength = PEFileStream.Length;
            long tableSize = (long)numberOfSymbols * CoffSymbolSize;
            if (tableSize <= 0 || tableSize > int.MaxValue)
            {
                Warn(ParseIssueCategory.Header, "COFF symbol table size exceeds supported limits.");
                return;
            }

            if (pointerToSymbolTable >= fileLength || pointerToSymbolTable + tableSize > fileLength)
            {
                Warn(ParseIssueCategory.Header, "COFF symbol table extends beyond end of file.");
                return;
            }

            if (!TrySetPosition(pointerToSymbolTable, (int)tableSize))
            {
                Warn(ParseIssueCategory.Header, "COFF symbol table offset outside file bounds.");
                return;
            }

            byte[] symbolData = new byte[tableSize];
            ReadExactly(PEFileStream, symbolData, 0, symbolData.Length);

            long stringTableOffset = pointerToSymbolTable + tableSize;
            Dictionary<uint, string> stringTable = new Dictionary<uint, string>();
            if (stringTableOffset + 4 <= fileLength)
            {
                if (TrySetPosition(stringTableOffset, 4))
                {
                    byte[] lengthBytes = new byte[4];
                    ReadExactly(PEFileStream, lengthBytes, 0, lengthBytes.Length);
                    uint stringTableLength = BitConverter.ToUInt32(lengthBytes, 0);
                    if (stringTableLength >= 4 && stringTableLength <= fileLength - stringTableOffset)
                    {
                        int stringDataLength = (int)stringTableLength - 4;
                        if (stringDataLength > 0)
                        {
                            byte[] stringData = new byte[stringDataLength];
                            ReadExactly(PEFileStream, stringData, 0, stringData.Length);
                            ParseCoffStringTable(stringData, stringTable);
                        }
                    }
                    else if (stringTableLength != 0)
                    {
                        Warn(ParseIssueCategory.Header, "COFF string table length is invalid.");
                    }
                }
            }

            for (int index = 0; index < numberOfSymbols; index++)
            {
                int symbolOffset = index * CoffSymbolSize;
                if (symbolOffset + CoffSymbolSize > symbolData.Length)
                {
                    break;
                }

                ReadOnlySpan<byte> entry = new ReadOnlySpan<byte>(symbolData, symbolOffset, CoffSymbolSize);
                string name = ResolveCoffSymbolName(entry, stringTable, out bool shortNameUsedFallback);
                if (shortNameUsedFallback)
                {
                    Warn(
                        ParseIssueCategory.Header,
                        string.Format(
                            CultureInfo.InvariantCulture,
                            "SPEC violation: COFF short symbol name for symbol #{0} is not valid UTF-8 and was decoded using Latin-1 fallback (value=\"{1}\").",
                            index,
                            name));
                }
                uint value = BitConverter.ToUInt32(entry.Slice(8, 4));
                short sectionNumber = BitConverter.ToInt16(entry.Slice(12, 2));
                ushort type = BitConverter.ToUInt16(entry.Slice(14, 2));
                string typeName = DecodeCoffSymbolTypeName(type);
                byte storageClass = entry[16];
                byte auxCount = entry[17];
                string storageClassName = GetCoffStorageClassName(storageClass);
                string scopeName = GetCoffSymbolScopeName(sectionNumber, storageClass);

                string sectionName = string.Empty;
                if (sectionNumber > 0 && sectionNumber <= sections.Count)
                {
                    sectionName = NormalizeSectionName(sections[sectionNumber - 1]);
                }

                byte[] auxData = Array.Empty<byte>();
                int auxBytes = auxCount * CoffSymbolSize;
                if (auxBytes > 0)
                {
                    int auxStart = symbolOffset + CoffSymbolSize;
                    int auxAvailable = symbolData.Length - auxStart;
                    int auxLength = Math.Min(auxBytes, auxAvailable);
                    if (auxLength > 0)
                    {
                        auxData = new byte[auxLength];
                        Array.Copy(symbolData, auxStart, auxData, 0, auxLength);
                    }
                }

                CoffAuxSymbolInfo[] auxSymbols = DecodeCoffAuxSymbols(name, type, storageClass, auxCount, auxData, sectionNumber, value);
                ValidateCoffAuxSymbolConformance(index, name, storageClass, auxCount, auxData, auxSymbols);

                _coffSymbols.Add(new CoffSymbolInfo(
                    index,
                    name,
                    value,
                    sectionNumber,
                    sectionName,
                    type,
                    typeName,
                    storageClass,
                    storageClassName,
                    scopeName,
                    auxCount,
                    auxData,
                    auxSymbols));

                if (auxCount > 0)
                {
                    index += auxCount;
                }
            }

            string[] sectionNames = sections.Select(section => NormalizeSectionName(section)).ToArray();
            CoffSymbolInfo[] resolved = ResolveCoffAuxDetails(_coffSymbols, sectionNames);
            if (resolved.Length == _coffSymbols.Count && resolved.Length > 0)
            {
                _coffSymbols.Clear();
                _coffSymbols.AddRange(resolved);
            }

            ValidateCoffWeakExternalConformance(_coffSymbols);
        }

        private void ParseCoffLineNumbers(List<IMAGE_SECTION_HEADER> sections)
        {
            if (PEFileStream == null || sections == null || sections.Count == 0)
            {
                return;
            }

            long fileLength = PEFileStream.Length;
            for (int i = 0; i < sections.Count; i++)
            {
                IMAGE_SECTION_HEADER section = sections[i];
                if (section.NumberOfLinenumbers == 0)
                {
                    continue;
                }

                if (section.PointerToLinenumbers == 0)
                {
                    Warn(ParseIssueCategory.Header, $"Section {NormalizeSectionName(section)} has line numbers count but no pointer.");
                    continue;
                }

                long offset = section.PointerToLinenumbers;
                long totalSize = (long)section.NumberOfLinenumbers * CoffLineNumberSize;
                if (offset + totalSize > fileLength)
                {
                    Warn(ParseIssueCategory.Header, $"Line number table for section {NormalizeSectionName(section)} exceeds file size.");
                    totalSize = Math.Max(0, fileLength - offset);
                }

                if (totalSize <= 0 || totalSize > int.MaxValue)
                {
                    continue;
                }

                if (!TrySetPosition(offset, (int)totalSize))
                {
                    Warn(ParseIssueCategory.Header, $"Line number table for section {NormalizeSectionName(section)} outside file bounds.");
                    continue;
                }

                byte[] buffer = new byte[totalSize];
                ReadExactly(PEFileStream, buffer, 0, buffer.Length);

                int entries = buffer.Length / CoffLineNumberSize;
                for (int j = 0; j < entries; j++)
                {
                    int entryOffset = j * CoffLineNumberSize;
                    uint addressOrIndex = BitConverter.ToUInt32(buffer, entryOffset);
                    ushort line = BitConverter.ToUInt16(buffer, entryOffset + 4);
                    bool isFunction = line == 0;
                    uint virtualAddress = isFunction ? 0u : addressOrIndex;
                    uint symbolIndex = isFunction ? addressOrIndex : 0u;
                    _coffLineNumbers.Add(new CoffLineNumberInfo(
                        NormalizeSectionName(section),
                        i + 1,
                        virtualAddress,
                        symbolIndex,
                        line,
                        isFunction,
                        offset + entryOffset));
                }
            }
        }

        private void ValidateCoffAuxSymbolConformance(
            int symbolIndex,
            string symbolName,
            byte storageClass,
            byte auxCount,
            byte[] auxData,
            CoffAuxSymbolInfo[] auxSymbols)
        {
            if (auxCount == 0)
            {
                return;
            }

            int expectedBytes = auxCount * CoffSymbolSize;
            int actualBytes = auxData?.Length ?? 0;
            if (actualBytes < expectedBytes)
            {
                Warn(
                    ParseIssueCategory.Header,
                    string.Format(
                        CultureInfo.InvariantCulture,
                        "SPEC violation: COFF auxiliary records for symbol #{0} ({1}) are truncated (expected {2} bytes, got {3}).",
                        symbolIndex,
                        string.IsNullOrWhiteSpace(symbolName) ? "<unnamed>" : symbolName,
                        expectedBytes,
                        actualBytes));
            }

            bool functionLayoutExpected =
                storageClass == 0x65 ||
                string.Equals(symbolName, ".bf", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(symbolName, ".ef", StringComparison.OrdinalIgnoreCase);
            bool functionLayoutRecognized = false;

            if (auxSymbols == null || auxSymbols.Length == 0)
            {
                if (functionLayoutExpected)
                {
                    Warn(
                        ParseIssueCategory.Header,
                        string.Format(
                            CultureInfo.InvariantCulture,
                            "SPEC violation: COFF function auxiliary layout for symbol #{0} ({1}) is malformed.",
                            symbolIndex,
                            string.IsNullOrWhiteSpace(symbolName) ? "<unnamed>" : symbolName));
                }
                return;
            }

            for (int i = 0; i < auxSymbols.Length; i++)
            {
                CoffAuxSymbolInfo aux = auxSymbols[i];
                if (aux == null)
                {
                    continue;
                }

                if (string.Equals(aux.Kind, "ClrToken", StringComparison.OrdinalIgnoreCase))
                {
                    if (aux.ClrAuxType != CoffAuxSymbolInfo.ClrTokenAuxTypeDefinition)
                    {
                        Warn(
                            ParseIssueCategory.Header,
                            string.Format(
                                CultureInfo.InvariantCulture,
                                "SPEC violation: COFF CLR token aux record for symbol #{0} ({1}) has invalid AuxType 0x{2:X2} (expected 0x{3:X2}).",
                                symbolIndex,
                                string.IsNullOrWhiteSpace(symbolName) ? "<unnamed>" : symbolName,
                                aux.ClrAuxType,
                                CoffAuxSymbolInfo.ClrTokenAuxTypeDefinition));
                    }

                    if (!aux.ClrReservedFieldsValid)
                    {
                        Warn(
                            ParseIssueCategory.Header,
                            string.Format(
                                CultureInfo.InvariantCulture,
                                "SPEC violation: COFF CLR token aux record for symbol #{0} ({1}) has non-zero reserved fields.",
                                symbolIndex,
                                string.IsNullOrWhiteSpace(symbolName) ? "<unnamed>" : symbolName));
                    }
                }

                if (string.Equals(aux.Kind, "FunctionDefinition", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(aux.Kind, "FunctionLineInfo", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(aux.Kind, "FunctionBegin", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(aux.Kind, "FunctionEnd", StringComparison.OrdinalIgnoreCase))
                {
                    functionLayoutRecognized = true;

                    if (!aux.FunctionAuxReservedFieldsValid)
                    {
                        Warn(
                            ParseIssueCategory.Header,
                            string.Format(
                                CultureInfo.InvariantCulture,
                                "SPEC violation: COFF function auxiliary reserved fields are non-zero for symbol #{0} ({1}).",
                                symbolIndex,
                                string.IsNullOrWhiteSpace(symbolName) ? "<unnamed>" : symbolName));
                    }

                    if (!aux.FunctionAuxPointerToNextFunctionValid)
                    {
                        Warn(
                            ParseIssueCategory.Header,
                            string.Format(
                                CultureInfo.InvariantCulture,
                                "SPEC violation: COFF .ef auxiliary record should not define PointerToNextFunction for symbol #{0} ({1}).",
                                symbolIndex,
                                string.IsNullOrWhiteSpace(symbolName) ? "<unnamed>" : symbolName));
                    }
                }
            }

            if (functionLayoutExpected && !functionLayoutRecognized)
            {
                Warn(
                    ParseIssueCategory.Header,
                    string.Format(
                        CultureInfo.InvariantCulture,
                        "SPEC violation: COFF function auxiliary layout for symbol #{0} ({1}) is malformed.",
                        symbolIndex,
                        string.IsNullOrWhiteSpace(symbolName) ? "<unnamed>" : symbolName));
            }
        }

        private void ValidateCoffWeakExternalConformance(IReadOnlyList<CoffSymbolInfo> symbols)
        {
            if (symbols == null || symbols.Count == 0)
            {
                return;
            }

            Dictionary<int, CoffSymbolInfo> symbolsByTableIndex = BuildCoffSymbolsByTableIndex(symbols);
            for (int i = 0; i < symbols.Count; i++)
            {
                CoffSymbolInfo symbol = symbols[i];
                if (symbol?.AuxSymbols == null || symbol.AuxSymbols.Count == 0)
                {
                    continue;
                }

                for (int j = 0; j < symbol.AuxSymbols.Count; j++)
                {
                    CoffAuxSymbolInfo aux = symbol.AuxSymbols[j];
                    if (aux == null || !string.Equals(aux.Kind, "WeakExternal", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (TryResolveWeakExternalTargetName(symbols, symbolsByTableIndex, aux.WeakTagIndex, out string _))
                    {
                        continue;
                    }

                    Warn(
                        ParseIssueCategory.Header,
                        string.Format(
                            CultureInfo.InvariantCulture,
                            "SPEC violation: COFF weak external aux record for symbol #{0} ({1}) references unresolved TagIndex {2}.",
                            symbol.Index,
                            string.IsNullOrWhiteSpace(symbol.Name) ? "<unnamed>" : symbol.Name,
                            aux.WeakTagIndex));
                }
            }
        }

        private void ValidateSectionNameEncoding(IReadOnlyList<IMAGE_SECTION_HEADER> sections)
        {
            if (sections == null || sections.Count == 0)
            {
                return;
            }

            for (int i = 0; i < sections.Count; i++)
            {
                IMAGE_SECTION_HEADER section = sections[i];
                bool usedFallback = false;
                string name = DecodeCoffShortNameUtf8WithFallback(section.Name ?? Array.Empty<byte>(), out usedFallback);
                if (!usedFallback)
                {
                    continue;
                }

                Warn(
                    ParseIssueCategory.Sections,
                    string.Format(
                        CultureInfo.InvariantCulture,
                        "SPEC violation: Section header short name #{0} is not valid UTF-8 and was decoded using Latin-1 fallback (value=\"{1}\").",
                        i + 1,
                        name));
            }
        }

        private void ParseCoffRelocations(List<IMAGE_SECTION_HEADER> sections)
        {
            if (PEFileStream == null || sections == null || sections.Count == 0)
            {
                return;
            }

            _coffRelocations.Clear();
            Dictionary<int, CoffSymbolInfo> symbolsByTableIndex = BuildCoffSymbolsByTableIndex(_coffSymbols);
            long fileLength = PEFileStream.Length;
            for (int i = 0; i < sections.Count; i++)
            {
                IMAGE_SECTION_HEADER section = sections[i];
                string sectionName = NormalizeSectionName(section);
                if (section.NumberOfRelocations == 0)
                {
                    continue;
                }

                if (section.PointerToRelocations == 0)
                {
                    Warn(ParseIssueCategory.Header, $"Section {sectionName} has relocations but no pointer.");
                    continue;
                }

                long offset = section.PointerToRelocations;
                long totalSize = (long)section.NumberOfRelocations * CoffRelocationSize;
                if (offset + totalSize > fileLength)
                {
                    Warn(ParseIssueCategory.Header, $"Relocation table for section {sectionName} exceeds file size.");
                    totalSize = Math.Max(0, fileLength - offset);
                }

                if (totalSize <= 0 || totalSize > int.MaxValue)
                {
                    continue;
                }

                if (!TrySetPosition(offset, (int)totalSize))
                {
                    Warn(ParseIssueCategory.Header, $"Relocation table for section {sectionName} outside file bounds.");
                    continue;
                }

                byte[] buffer = new byte[totalSize];
                ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                int entries = buffer.Length / CoffRelocationSize;
                for (int j = 0; j < entries; j++)
                {
                    int entryOffset = j * CoffRelocationSize;
                    uint virtualAddress = ReadUInt32(buffer, entryOffset);
                    uint symbolIndex = ReadUInt32(buffer, entryOffset + 4);
                    ushort type = ReadUInt16(buffer, entryOffset + 8);
                    string typeName = GetCoffRelocationTypeName(_machineType, type);
                    string symbolName = string.Empty;
                    bool usesPairDisplacement = IsPairRelocationDisplacementCarrier(_machineType, type);
                    if (!usesPairDisplacement)
                    {
                        if (symbolIndex <= int.MaxValue &&
                            symbolsByTableIndex.TryGetValue((int)symbolIndex, out CoffSymbolInfo symbol))
                        {
                            symbolName = symbol?.Name ?? string.Empty;
                        }
                        else
                        {
                            Warn(
                                ParseIssueCategory.Relocations,
                                string.Format(
                                    CultureInfo.InvariantCulture,
                                    "SPEC violation: COFF relocation entry #{0} in section {1} references invalid SymbolTableIndex {2}.",
                                    j,
                                    string.IsNullOrWhiteSpace(sectionName) ? "<unnamed>" : sectionName,
                                    symbolIndex));
                        }
                    }

                    _coffRelocations.Add(new CoffRelocationInfo(
                        sectionName,
                        i + 1,
                        virtualAddress,
                        symbolIndex,
                        symbolName,
                        type,
                        typeName,
                        offset + entryOffset));
                }
            }
        }

        private static CoffAuxSymbolInfo[] DecodeCoffAuxSymbols(
            string name,
            ushort type,
            byte storageClass,
            byte auxCount,
            byte[] auxData,
            short sectionNumber = 0,
            uint symbolValue = 0)
        {
            if (auxCount == 0 || auxData == null || auxData.Length == 0)
            {
                return Array.Empty<CoffAuxSymbolInfo>();
            }

            List<CoffAuxSymbolInfo> results = new List<CoffAuxSymbolInfo>();
            int totalAux = auxData.Length / CoffSymbolSize;
            if (storageClass == 0x67) // FILE
            {
                int bytes = Math.Min(totalAux * CoffSymbolSize, auxData.Length);
                string fileName = ReadNullTerminatedLatin1(auxData, 0, out int _);
                if (string.IsNullOrWhiteSpace(fileName) && bytes > 0)
                {
                    fileName = Encoding.Latin1.GetString(auxData, 0, bytes).TrimEnd('\0', ' ');
                }

                results.Add(new CoffAuxSymbolInfo(
                    "File",
                    fileName,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    false,
                    true,
                    string.Empty,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    BuildHexPreview(auxData, 32)));
                return results.ToArray();
            }

            bool isFunction = (type & 0x20) != 0;
            if (isFunction && auxData.Length >= CoffSymbolSize)
            {
                uint tagIndex = ReadUInt32(auxData, 0);
                uint totalSize = ReadUInt32(auxData, 4);
                uint linePtr = ReadUInt32(auxData, 8);
                uint nextFn = ReadUInt32(auxData, 12);
                byte[] reservedTail = new byte[2];
                reservedTail[0] = auxData[16];
                reservedTail[1] = auxData[17];
                bool reservedTailValid = reservedTail[0] == 0 && reservedTail[1] == 0;
                results.Add(new CoffAuxSymbolInfo(
                    "FunctionDefinition",
                    string.Empty,
                    tagIndex,
                    totalSize,
                    linePtr,
                    nextFn,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    false,
                    true,
                    string.Empty,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    BuildHexPreview(auxData, 32),
                    functionAuxReservedFieldsValid: reservedTailValid,
                    functionAuxReservedBytesPreview: BuildHexPreview(reservedTail, reservedTail.Length),
                    functionAuxPointerToNextFunctionValid: true));
                return results.ToArray();
            }

            if ((string.Equals(name, ".bf", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(name, ".ef", StringComparison.OrdinalIgnoreCase)) &&
                auxData.Length >= CoffSymbolSize)
            {
                ushort lineNumber = ReadUInt16(auxData, 4);
                bool isBegin = string.Equals(name, ".bf", StringComparison.OrdinalIgnoreCase);
                uint nextFn = ReadUInt32(auxData, 12);
                byte[] reservedBytes = new byte[12];
                Array.Copy(auxData, 0, reservedBytes, 0, 6);
                Array.Copy(auxData, 6, reservedBytes, 6, 6);
                bool reservedValid = reservedBytes.All(b => b == 0) && auxData[16] == 0 && auxData[17] == 0;
                bool nextPointerValid = isBegin || nextFn == 0;
                results.Add(new CoffAuxSymbolInfo(
                    isBegin ? "FunctionBegin" : "FunctionEnd",
                    string.Empty,
                    0,
                    0,
                    0,
                    nextFn,
                    lineNumber,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    false,
                    true,
                    string.Empty,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    BuildHexPreview(auxData, 32),
                    functionAuxReservedFieldsValid: reservedValid,
                    functionAuxReservedBytesPreview: BuildHexPreview(reservedBytes, reservedBytes.Length),
                    functionAuxPointerToNextFunctionValid: nextPointerValid));
                return results.ToArray();
            }

            if (storageClass == 0x65 && auxData.Length >= CoffSymbolSize) // FUNCTION
            {
                ushort lineNumber = ReadUInt16(auxData, 4);
                uint nextFn = ReadUInt32(auxData, 12);
                byte[] reservedBytes = new byte[12];
                Array.Copy(auxData, 0, reservedBytes, 0, 6);
                Array.Copy(auxData, 6, reservedBytes, 6, 6);
                bool reservedValid = reservedBytes.All(b => b == 0) && auxData[16] == 0 && auxData[17] == 0;
                results.Add(new CoffAuxSymbolInfo(
                    "FunctionLineInfo",
                    string.Empty,
                    0,
                    0,
                    0,
                    nextFn,
                    lineNumber,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    false,
                    true,
                    string.Empty,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    BuildHexPreview(auxData, 32),
                    functionAuxReservedFieldsValid: reservedValid,
                    functionAuxReservedBytesPreview: BuildHexPreview(reservedBytes, reservedBytes.Length),
                    functionAuxPointerToNextFunctionValid: true));
                return results.ToArray();
            }

            if ((storageClass == 0x03 || storageClass == 0x68) && auxData.Length >= CoffSymbolSize) // STATIC/SECTION
            {
                uint length = ReadUInt32(auxData, 0);
                ushort relocations = ReadUInt16(auxData, 4);
                ushort lineNumbers = ReadUInt16(auxData, 6);
                uint checksum = ReadUInt32(auxData, 8);
                ushort associatedSectionNumber = ReadUInt16(auxData, 12);
                byte selection = auxData[14];
                bool isComdat = selection != 0;
                bool comdatSelectionValid = selection <= 7;
                string comdatNote = string.Empty;
                if (isComdat && !comdatSelectionValid)
                {
                    comdatNote = "Invalid COMDAT selection.";
                }
                else if (selection == 5 && associatedSectionNumber == 0)
                {
                    comdatNote = "Associative COMDAT missing section index.";
                }
                results.Add(new CoffAuxSymbolInfo(
                    "SectionDefinition",
                    string.Empty,
                    0,
                    0,
                    0,
                    0,
                    0,
                    length,
                    relocations,
                    lineNumbers,
                    checksum,
                    associatedSectionNumber,
                    selection,
                    GetComdatSelectionName(selection),
                    string.Empty,
                    isComdat,
                    comdatSelectionValid,
                    comdatNote,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    BuildHexPreview(auxData, 32)));
                return results.ToArray();
            }

            bool weakExternalSpecForm = storageClass == 0x02 && sectionNumber == 0 && symbolValue == 0;
            if ((storageClass == 0x69 || weakExternalSpecForm) && auxData.Length >= CoffSymbolSize) // WEAK_EXTERNAL
            {
                uint tagIndex = ReadUInt32(auxData, 0);
                uint characteristics = ReadUInt32(auxData, 4);
                results.Add(new CoffAuxSymbolInfo(
                    "WeakExternal",
                    string.Empty,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    false,
                    true,
                    string.Empty,
                    tagIndex,
                    characteristics,
                    GetWeakExternalCharacteristicsName(characteristics),
                    string.Empty,
                    BuildHexPreview(auxData, 32)));
                return results.ToArray();
            }

            if (storageClass == 0x6B && auxData.Length >= CoffSymbolSize) // CLR_TOKEN
            {
                byte auxType = auxData[0];
                byte reserved = auxData[1];
                uint symbolIndex = ReadUInt32(auxData, 2);
                byte[] reservedTail = new byte[12];
                Array.Copy(auxData, 6, reservedTail, 0, reservedTail.Length);
                bool reservedValid = reserved == 0 && reservedTail.All(b => b == 0);
                results.Add(new CoffAuxSymbolInfo(
                    "ClrToken",
                    string.Empty,
                    symbolIndex,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    false,
                    true,
                    reservedValid ? string.Empty : "Reserved CLR token fields must be zero.",
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    BuildHexPreview(auxData, 32),
                    auxType,
                    reserved,
                    symbolIndex,
                    BuildHexPreview(reservedTail, reservedTail.Length),
                    reservedValid));
                return results.ToArray();
            }

            if (auxData.Length >= CoffSymbolSize && IsGenericAuxSymbolStorageClass(storageClass))
            {
                uint tagIndex = ReadUInt32(auxData, 0);
                uint totalSize = ReadUInt32(auxData, 4);
                uint pointerToLine = ReadUInt32(auxData, 8);
                uint pointerToNextFunction = ReadUInt32(auxData, 12);
                ushort tvIndex = ReadUInt16(auxData, 16);
                results.Add(new CoffAuxSymbolInfo(
                    "SymbolDefinition",
                    string.Empty,
                    tagIndex,
                    totalSize,
                    pointerToLine,
                    pointerToNextFunction,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    false,
                    true,
                    tvIndex == 0 ? string.Empty : $"TvIndex={tvIndex}",
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    BuildHexPreview(auxData, 32)));
                return results.ToArray();
            }

            for (int i = 0; i < totalAux; i++)
            {
                int offset = i * CoffSymbolSize;
                byte[] slice = new byte[Math.Min(CoffSymbolSize, auxData.Length - offset)];
                Array.Copy(auxData, offset, slice, 0, slice.Length);
                results.Add(new CoffAuxSymbolInfo(
                    "Unknown",
                    string.Empty,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    false,
                    true,
                    string.Empty,
                    0,
                    0,
                    string.Empty,
                    string.Empty,
                    BuildHexPreview(slice, 32)));
            }

            return results.ToArray();
        }

        private static bool IsGenericAuxSymbolStorageClass(byte storageClass)
        {
            switch (storageClass)
            {
                case 0x02: // EXTERNAL
                case 0x03: // STATIC
                case 0x04: // REGISTER
                case 0x05: // EXTERNAL_DEF
                case 0x0A: // STRUCT_TAG
                case 0x0C: // UNION_TAG
                case 0x0F: // ENUM_TAG
                case 0x68: // SECTION
                    return true;
                default:
                    return false;
            }
        }

        private static CoffSymbolInfo[] ResolveCoffAuxDetails(IReadOnlyList<CoffSymbolInfo> symbols, string[] sectionNames)
        {
            if (symbols == null || symbols.Count == 0)
            {
                return Array.Empty<CoffSymbolInfo>();
            }

            Dictionary<int, CoffSymbolInfo> symbolsByTableIndex = BuildCoffSymbolsByTableIndex(symbols);
            bool anyUpdated = false;
            CoffSymbolInfo[] resolved = new CoffSymbolInfo[symbols.Count];
            for (int i = 0; i < symbols.Count; i++)
            {
                CoffSymbolInfo symbol = symbols[i];
                if (symbol.AuxSymbols == null || symbol.AuxSymbols.Count == 0)
                {
                    resolved[i] = symbol;
                    continue;
                }

                bool updated = false;
                CoffAuxSymbolInfo[] aux = new CoffAuxSymbolInfo[symbol.AuxSymbols.Count];
                for (int j = 0; j < symbol.AuxSymbols.Count; j++)
                {
                    CoffAuxSymbolInfo info = symbol.AuxSymbols[j];
                    string associatedSectionName = info.AssociatedSectionName;
                    string comdatNote = info.ComdatSelectionNote;
                    if (info != null &&
                        string.Equals(info.Kind, "SectionDefinition", StringComparison.OrdinalIgnoreCase) &&
                        info.Selection == 5 &&
                        info.SectionNumber > 0 &&
                        sectionNames != null &&
                        info.SectionNumber <= sectionNames.Length)
                    {
                        string resolvedSection = sectionNames[info.SectionNumber - 1] ?? string.Empty;
                        if (!string.Equals(associatedSectionName, resolvedSection, StringComparison.Ordinal))
                        {
                            associatedSectionName = resolvedSection;
                            updated = true;
                        }
                    }

                    if (info != null &&
                        info.IsComdat &&
                        info.Selection == 5 &&
                        string.IsNullOrEmpty(associatedSectionName) &&
                        string.IsNullOrEmpty(comdatNote))
                    {
                        comdatNote = "Associative COMDAT missing section.";
                        updated = true;
                    }

                    if (info != null &&
                        string.Equals(info.Kind, "WeakExternal", StringComparison.OrdinalIgnoreCase) &&
                        TryResolveWeakExternalTargetName(symbols, symbolsByTableIndex, info.WeakTagIndex, out string targetName))
                    {
                        if (!string.Equals(info.WeakDefaultSymbol, targetName, StringComparison.Ordinal))
                        {
                            aux[j] = new CoffAuxSymbolInfo(
                                info.Kind,
                                info.FileName,
                                info.TagIndex,
                                info.TotalSize,
                                info.PointerToLineNumber,
                                info.PointerToNextFunction,
                                info.FunctionLineNumber,
                                info.SectionLength,
                                info.RelocationCount,
                                info.LineNumberCount,
                                info.Checksum,
                                info.SectionNumber,
                                info.Selection,
                                info.SelectionName,
                                associatedSectionName,
                                info.IsComdat,
                                info.ComdatSelectionValid,
                                comdatNote,
                                info.WeakTagIndex,
                                info.WeakCharacteristics,
                                info.WeakCharacteristicsName,
                                targetName,
                                info.RawPreview,
                                info.ClrAuxType,
                                info.ClrReservedByte,
                                info.ClrSymbolTableIndex,
                                info.ClrReservedBytesPreview,
                                info.ClrReservedFieldsValid);
                            updated = true;
                        }
                        else
                        {
                            if (!string.Equals(info.AssociatedSectionName, associatedSectionName, StringComparison.Ordinal))
                            {
                                aux[j] = new CoffAuxSymbolInfo(
                                    info.Kind,
                                    info.FileName,
                                    info.TagIndex,
                                    info.TotalSize,
                                    info.PointerToLineNumber,
                                    info.PointerToNextFunction,
                                    info.FunctionLineNumber,
                                    info.SectionLength,
                                    info.RelocationCount,
                                    info.LineNumberCount,
                                    info.Checksum,
                                    info.SectionNumber,
                                    info.Selection,
                                    info.SelectionName,
                                    associatedSectionName,
                                    info.IsComdat,
                                    info.ComdatSelectionValid,
                                    comdatNote,
                                    info.WeakTagIndex,
                                    info.WeakCharacteristics,
                                    info.WeakCharacteristicsName,
                                    info.WeakDefaultSymbol,
                                    info.RawPreview,
                                    info.ClrAuxType,
                                    info.ClrReservedByte,
                                    info.ClrSymbolTableIndex,
                                    info.ClrReservedBytesPreview,
                                    info.ClrReservedFieldsValid);
                                updated = true;
                            }
                            else
                            {
                                aux[j] = info;
                            }
                        }
                    }
                    else
                    {
                        if (!string.Equals(info.AssociatedSectionName, associatedSectionName, StringComparison.Ordinal))
                        {
                            aux[j] = new CoffAuxSymbolInfo(
                                info.Kind,
                                info.FileName,
                                info.TagIndex,
                                info.TotalSize,
                                info.PointerToLineNumber,
                                info.PointerToNextFunction,
                                info.FunctionLineNumber,
                                info.SectionLength,
                                info.RelocationCount,
                                info.LineNumberCount,
                                info.Checksum,
                                info.SectionNumber,
                                info.Selection,
                                info.SelectionName,
                                associatedSectionName,
                                info.IsComdat,
                                info.ComdatSelectionValid,
                                comdatNote,
                                info.WeakTagIndex,
                                info.WeakCharacteristics,
                                info.WeakCharacteristicsName,
                                info.WeakDefaultSymbol,
                                info.RawPreview,
                                info.ClrAuxType,
                                info.ClrReservedByte,
                                info.ClrSymbolTableIndex,
                                info.ClrReservedBytesPreview,
                                info.ClrReservedFieldsValid);
                            updated = true;
                        }
                        else
                        {
                            aux[j] = info;
                        }
                    }
                }

                if (updated)
                {
                    resolved[i] = new CoffSymbolInfo(
                        symbol.Index,
                        symbol.Name,
                        symbol.Value,
                        symbol.SectionNumber,
                        symbol.SectionName,
                        symbol.Type,
                        symbol.TypeName,
                        symbol.StorageClass,
                        symbol.StorageClassName,
                        symbol.ScopeName,
                        symbol.AuxSymbolCount,
                        symbol.AuxData,
                        aux);
                    anyUpdated = true;
                }
                else
                {
                    resolved[i] = symbol;
                }
            }

            return anyUpdated ? resolved : symbols.ToArray();
        }

        private static Dictionary<int, CoffSymbolInfo> BuildCoffSymbolsByTableIndex(IReadOnlyList<CoffSymbolInfo> symbols)
        {
            Dictionary<int, CoffSymbolInfo> map = new Dictionary<int, CoffSymbolInfo>();
            if (symbols == null)
            {
                return map;
            }

            for (int i = 0; i < symbols.Count; i++)
            {
                CoffSymbolInfo symbol = symbols[i];
                if (symbol == null || map.ContainsKey(symbol.Index))
                {
                    continue;
                }

                map[symbol.Index] = symbol;
            }

            return map;
        }

        private static bool TryResolveWeakExternalTargetName(
            IReadOnlyList<CoffSymbolInfo> symbols,
            Dictionary<int, CoffSymbolInfo> symbolsByTableIndex,
            uint weakTagIndex,
            out string targetName)
        {
            targetName = string.Empty;

            if (symbolsByTableIndex != null &&
                weakTagIndex <= int.MaxValue &&
                symbolsByTableIndex.TryGetValue((int)weakTagIndex, out CoffSymbolInfo byTableIndex))
            {
                targetName = byTableIndex?.Name ?? string.Empty;
                return true;
            }

            // Compatibility fallback for producers that encoded compact-symbol indices.
            if (symbols != null && weakTagIndex < symbols.Count)
            {
                targetName = symbols[(int)weakTagIndex].Name;
                return true;
            }

            return false;
        }

        private static string DecodeCoffSymbolTypeName(ushort type)
        {
            ushort baseType = (ushort)(type & 0x0F);
            string baseName = GetCoffBaseTypeName(baseType);
            ushort derived = (ushort)(type >> 4);

            if (derived == 0)
            {
                return baseName;
            }

            List<string> chain = new List<string>();
            for (int i = 0; i < 6 && derived != 0; i++)
            {
                int code = derived & 0x03;
                if (code == 0)
                {
                    break;
                }
                chain.Add(GetCoffDerivedTypeName(code));
                derived >>= 2;
            }

            if (chain.Count == 0)
            {
                return baseName;
            }

            return string.Join("->", chain) + "->" + baseName;
        }

        private static string GetCoffBaseTypeName(ushort baseType)
        {
            switch (baseType)
            {
                case 0: return "NULL";
                case 1: return "VOID";
                case 2: return "CHAR";
                case 3: return "SHORT";
                case 4: return "INT";
                case 5: return "LONG";
                case 6: return "FLOAT";
                case 7: return "DOUBLE";
                case 8: return "STRUCT";
                case 9: return "UNION";
                case 10: return "ENUM";
                case 11: return "MOE";
                case 12: return "BYTE";
                case 13: return "WORD";
                case 14: return "UINT";
                case 15: return "DWORD";
                default: return "TYPE_" + baseType.ToString(CultureInfo.InvariantCulture);
            }
        }

        private static string GetCoffDerivedTypeName(int code)
        {
            switch (code)
            {
                case 1: return "PTR";
                case 2: return "FUNC";
                case 3: return "ARRAY";
                default: return "DTYPE_" + code.ToString(CultureInfo.InvariantCulture);
            }
        }

        private void ParseCoffStringTable(byte[] data, Dictionary<uint, string> table)
        {
            if (data == null || data.Length == 0)
            {
                return;
            }

            int index = 0;
            while (index < data.Length)
            {
                int start = index;
                while (index < data.Length && data[index] != 0)
                {
                    index++;
                }

                int length = index - start;
                if (length > 0)
                {
                    uint offset = (uint)(start + 4);
                    string value = DecodeUtf8WithLatin1Fallback(new ReadOnlySpan<byte>(data, start, length), out bool usedFallback);
                    if (usedFallback)
                    {
                        Warn(
                            ParseIssueCategory.Header,
                            string.Format(
                                CultureInfo.InvariantCulture,
                                "SPEC violation: COFF string-table entry at offset {0} is not valid UTF-8 and was decoded using Latin-1 fallback.",
                                offset));
                    }

                    if (!table.ContainsKey(offset))
                    {
                        table[offset] = value;
                    }
                    _coffStringTable.Add(new CoffStringTableEntry(offset, value));
                }

                index++;
            }
        }

        internal static bool TryParseCoffSymbolTableForTest(
            byte[] symbolData,
            byte[] stringTableData,
            string[] sectionNames,
            out CoffSymbolInfo[] symbols,
            out CoffStringTableEntry[] stringTableEntries)
        {
            symbols = Array.Empty<CoffSymbolInfo>();
            stringTableEntries = Array.Empty<CoffStringTableEntry>();

            if (symbolData == null || symbolData.Length < CoffSymbolSize)
            {
                return false;
            }

            Dictionary<uint, string> stringTable = new Dictionary<uint, string>();
            List<CoffStringTableEntry> entries = new List<CoffStringTableEntry>();
            if (stringTableData != null && stringTableData.Length > 0)
            {
                int index = 0;
                while (index < stringTableData.Length)
                {
                    int start = index;
                    while (index < stringTableData.Length && stringTableData[index] != 0)
                    {
                        index++;
                    }

                    int length = index - start;
                    if (length > 0)
                    {
                        string value = DecodeUtf8WithLatin1Fallback(new ReadOnlySpan<byte>(stringTableData, start, length), out bool _);
                        uint offset = (uint)(start + 4);
                        if (!stringTable.ContainsKey(offset))
                        {
                            stringTable[offset] = value;
                        }
                        entries.Add(new CoffStringTableEntry(offset, value));
                    }

                    index++;
                }
            }

            List<CoffSymbolInfo> parsed = new List<CoffSymbolInfo>();
            int totalSymbols = symbolData.Length / CoffSymbolSize;
            for (int index = 0; index < totalSymbols; index++)
            {
                int symbolOffset = index * CoffSymbolSize;
                ReadOnlySpan<byte> entry = new ReadOnlySpan<byte>(symbolData, symbolOffset, CoffSymbolSize);
                string name = ResolveCoffSymbolName(entry, stringTable, out bool _);
                uint value = BitConverter.ToUInt32(entry.Slice(8, 4));
                short sectionNumber = BitConverter.ToInt16(entry.Slice(12, 2));
                ushort type = BitConverter.ToUInt16(entry.Slice(14, 2));
                string typeName = DecodeCoffSymbolTypeName(type);
                byte storageClass = entry[16];
                byte auxCount = entry[17];

                string sectionName = string.Empty;
                if (sectionNumber > 0 && sectionNames != null && sectionNumber <= sectionNames.Length)
                {
                    sectionName = sectionNames[sectionNumber - 1] ?? string.Empty;
                }

                byte[] auxData = Array.Empty<byte>();
                int auxBytes = auxCount * CoffSymbolSize;
                if (auxBytes > 0)
                {
                    int auxStart = symbolOffset + CoffSymbolSize;
                    int auxAvailable = symbolData.Length - auxStart;
                    int auxLength = Math.Min(auxBytes, auxAvailable);
                    if (auxLength > 0)
                    {
                        auxData = new byte[auxLength];
                        Array.Copy(symbolData, auxStart, auxData, 0, auxLength);
                    }
                }

                string storageClassName = GetCoffStorageClassName(storageClass);
                string scopeName = GetCoffSymbolScopeName(sectionNumber, storageClass);
                CoffAuxSymbolInfo[] auxSymbols = DecodeCoffAuxSymbols(name, type, storageClass, auxCount, auxData, sectionNumber, value);

                parsed.Add(new CoffSymbolInfo(
                    index,
                    name,
                    value,
                    sectionNumber,
                    sectionName,
                    type,
                    typeName,
                    storageClass,
                    storageClassName,
                    scopeName,
                    auxCount,
                    auxData,
                    auxSymbols));

                if (auxCount > 0)
                {
                    index += auxCount;
                }
            }

            symbols = ResolveCoffAuxDetails(parsed, sectionNames ?? Array.Empty<string>());
            stringTableEntries = entries.ToArray();
            return true;
        }

        private static string ResolveCoffSymbolName(ReadOnlySpan<byte> entry, Dictionary<uint, string> stringTable, out bool shortNameUsedFallback)
        {
            shortNameUsedFallback = false;
            if (entry.Length < CoffSymbolSize)
            {
                return string.Empty;
            }

            uint zeroCheck = BitConverter.ToUInt32(entry.Slice(0, 4));
            if (zeroCheck == 0)
            {
                uint offset = BitConverter.ToUInt32(entry.Slice(4, 4));
                if (offset != 0 && stringTable != null && stringTable.TryGetValue(offset, out string value))
                {
                    return value ?? string.Empty;
                }

                return string.Empty;
            }

            int length = 0;
            for (int i = 0; i < 8; i++)
            {
                if (entry[i] == 0)
                {
                    break;
                }
                length++;
            }

            if (length == 0)
            {
                return string.Empty;
            }

            return DecodeCoffShortNameUtf8WithFallback(entry.Slice(0, length), out shortNameUsedFallback);
        }

        private static uint GetSectionSpan(IMAGE_SECTION_HEADER section)
        {
            return Math.Max(section.VirtualSize, section.SizeOfRawData);
        }

        private bool TryReadNullTerminatedString(long startOffset, out string value, int maxLength = 4096)
        {
            value = null;
            if (!TrySetPosition(startOffset))
            {
                return false;
            }

            List<byte> bytes = new List<byte>();
            while (bytes.Count < maxLength && PEFileStream.Position < PEFileStream.Length)
            {
                byte b = PEFile.ReadByte();
                if (b == 0)
                {
                    value = Encoding.UTF8.GetString(bytes.ToArray());
                    return true;
                }

                bytes.Add(b);
            }

            return false;
        }

        private sealed class ApiSetSchemaData
        {
            public Dictionary<string, string[]> Map { get; }
            public int Version { get; }
            public string SourcePath { get; }

            public ApiSetSchemaData(Dictionary<string, string[]> map, int version, string sourcePath)
            {
                Map = map ?? new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                Version = version;
                SourcePath = sourcePath ?? string.Empty;
            }
        }

        private ApiSetSchemaData EnsureApiSetSchema()
        {
            if (_apiSetSchemaLoaded)
            {
                return _apiSetSchema;
            }

            _apiSetSchemaLoaded = true;
            string path = ResolveApiSetSchemaPath();
            if (string.IsNullOrWhiteSpace(path))
            {
                _apiSetSchemaInfo = new ApiSetSchemaInfo(false, 0, string.Empty, string.Empty);
                return null;
            }

            if (!File.Exists(path))
            {
                Warn(ParseIssueCategory.Imports, $"API set schema file not found: {path}");
                _apiSetSchemaInfo = new ApiSetSchemaInfo(false, 0, string.Empty, path);
                return null;
            }

            try
            {
                byte[] data = File.ReadAllBytes(path);
                if (TryParseApiSetSchema(data, path, out ApiSetSchemaData schema, out string error))
                {
                    _apiSetSchema = schema;
                    _apiSetSchemaInfo = new ApiSetSchemaInfo(true, schema.Version, GetApiSetFlavor(schema.Version), schema.SourcePath);
                }
                else if (!string.IsNullOrWhiteSpace(error))
                {
                    Warn(ParseIssueCategory.Imports, $"API set schema parse failed: {error}");
                    _apiSetSchemaInfo = new ApiSetSchemaInfo(false, 0, string.Empty, path);
                }
            }
            catch (Exception ex)
            {
                Warn(ParseIssueCategory.Imports, $"API set schema load failed: {ex.Message}");
                _apiSetSchemaInfo = new ApiSetSchemaInfo(false, 0, string.Empty, path);
            }

            return _apiSetSchema;
        }

        private string ResolveApiSetSchemaPath()
        {
            if (_options != null && !string.IsNullOrWhiteSpace(_options.ApiSetSchemaPath))
            {
                return _options.ApiSetSchemaPath;
            }

            if (!OperatingSystem.IsWindows())
            {
                return null;
            }

            try
            {
                string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (!string.IsNullOrWhiteSpace(windowsDir))
                {
                    string candidate = Path.Combine(windowsDir, "System32", "apisetschema.dll");
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }
            catch (Exception)
            {
            }

            try
            {
                string systemDir = Environment.SystemDirectory;
                if (!string.IsNullOrWhiteSpace(systemDir))
                {
                    string candidate = Path.Combine(systemDir, "apisetschema.dll");
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }
            catch (Exception)
            {
            }

            return null;
        }

        private static string GetApiSetFlavor(int version)
        {
            if (version >= 6)
            {
                return "Windows 10/11";
            }

            if (version >= 4)
            {
                return "Windows 8/8.1";
            }

            if (version >= 2)
            {
                return "Windows 7";
            }

            return "Unknown";
        }

        private ApiSetResolutionInfo ResolveApiSetResolution(string dllName)
        {
            if (!IsApiSetName(dllName))
            {
                return new ApiSetResolutionInfo(
                    false,
                    false,
                    false,
                    string.Empty,
                    "None",
                    "None",
                    Array.Empty<string>(),
                    Array.Empty<string>());
            }

            string normalized = NormalizeApiSetName(dllName);
            ApiSetSchemaData schema = EnsureApiSetSchema();
            if (schema != null && schema.Map.TryGetValue(normalized, out string[] targets) && targets.Length > 0)
            {
                string[] canonicalTargets = NormalizeApiSetTargets(targets);
                return new ApiSetResolutionInfo(
                    true,
                    true,
                    false,
                    normalized,
                    "Schema",
                    "High",
                    targets,
                    canonicalTargets);
            }

            string[] fallbackTargets = GuessApiSetTargets(normalized);
            bool resolved = fallbackTargets.Length > 0;
            string[] canonicalFallback = NormalizeApiSetTargets(fallbackTargets);
            return new ApiSetResolutionInfo(
                true,
                resolved,
                true,
                normalized,
                "Heuristic",
                resolved ? "Low" : "None",
                fallbackTargets,
                canonicalFallback);
        }

        private static bool IsApiSetName(string dllName)
        {
            if (string.IsNullOrWhiteSpace(dllName))
            {
                return false;
            }

            string name = dllName.Trim();
            return name.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase) ||
                   name.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeApiSetName(string dllName)
        {
            string name = dllName?.Trim().ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrEmpty(name))
            {
                return string.Empty;
            }

            if (!name.EndsWith(".dll", StringComparison.Ordinal))
            {
                name += ".dll";
            }

            return name;
        }

        private static string[] NormalizeApiSetTargets(string[] targets)
        {
            if (targets == null || targets.Length == 0)
            {
                return Array.Empty<string>();
            }

            HashSet<string> normalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string target in targets)
            {
                if (string.IsNullOrWhiteSpace(target))
                {
                    continue;
                }

                string trimmed = target.Trim().ToLowerInvariant();
                if (!trimmed.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    trimmed += ".dll";
                }

                normalized.Add(trimmed);
            }

            return normalized.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private static string[] GuessApiSetTargets(string apiSetName)
        {
            if (string.IsNullOrWhiteSpace(apiSetName))
            {
                return Array.Empty<string>();
            }

            string name = apiSetName.ToLowerInvariant();
            if (name.Contains("crt-"))
            {
                return new[] { "ucrtbase.dll" };
            }

            if (name.Contains("ntuser") || name.Contains("user"))
            {
                return new[] { "user32.dll" };
            }

            if (name.Contains("gdi"))
            {
                return new[] { "gdi32.dll" };
            }

            if (name.Contains("crypt"))
            {
                return new[] { "crypt32.dll" };
            }

            if (name.Contains("shell"))
            {
                return new[] { "shell32.dll" };
            }

            if (name.Contains("advapi"))
            {
                return new[] { "advapi32.dll" };
            }

            if (name.StartsWith("api-ms-win-core-", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("ext-ms-win-", StringComparison.OrdinalIgnoreCase))
            {
                return new[] { "kernelbase.dll" };
            }

            return Array.Empty<string>();
        }

        private static bool TryParseApiSetSchema(byte[] data, string sourcePath, out ApiSetSchemaData schema, out string error)
        {
            schema = null;
            error = string.Empty;
            if (data == null || data.Length < 0x100)
            {
                error = "File too small.";
                return false;
            }

            if (!TryFindApiSetSection(data, out int sectionOffset, out int sectionSize))
            {
                error = "API set section not found.";
                return false;
            }

            if (sectionOffset < 0 || sectionSize <= 0 || sectionOffset + sectionSize > data.Length)
            {
                error = "API set section out of bounds.";
                return false;
            }

            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(data, sectionOffset, sectionSize);
            if (span.Length < 28)
            {
                error = "API set section too small.";
                return false;
            }

            uint version = ReadUInt32(span, 0);
            uint count = ReadUInt32(span, 12);
            uint entryOffset = ReadUInt32(span, 16);

            if (count == 0 || entryOffset >= span.Length)
            {
                error = "API set header invalid.";
                return false;
            }

            int entrySize = 24;
            int valueSize = 20;
            Dictionary<string, string[]> map = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < count; i++)
            {
                int entryPos = checked((int)entryOffset + (i * entrySize));
                if (entryPos < 0 || entryPos + entrySize > span.Length)
                {
                    break;
                }

                uint nameOffset = ReadUInt32(span, entryPos + 4);
                uint nameLength = ReadUInt32(span, entryPos + 8);
                uint valueOffset = ReadUInt32(span, entryPos + 16);
                uint valueCount = ReadUInt32(span, entryPos + 20);

                if (nameOffset >= span.Length || nameLength == 0)
                {
                    continue;
                }

                string name = ReadUnicodeString(span, (int)nameOffset, (int)nameLength);
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                if (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    name += ".dll";
                }

                List<string> targets = new List<string>();
                for (int j = 0; j < valueCount; j++)
                {
                    int valuePos = checked((int)valueOffset + (j * valueSize));
                    if (valuePos < 0 || valuePos + valueSize > span.Length)
                    {
                        break;
                    }

                    uint valueNameOffset = ReadUInt32(span, valuePos + 4);
                    uint valueNameLength = ReadUInt32(span, valuePos + 8);
                    uint valueOffsetEntry = ReadUInt32(span, valuePos + 12);
                    uint valueLengthEntry = ReadUInt32(span, valuePos + 16);

                    string target = string.Empty;
                    if (valueOffsetEntry < span.Length && valueLengthEntry > 0)
                    {
                        target = ReadUnicodeString(span, (int)valueOffsetEntry, (int)valueLengthEntry);
                    }

                    if (string.IsNullOrWhiteSpace(target) && valueNameOffset < span.Length && valueNameLength > 0)
                    {
                        target = ReadUnicodeString(span, (int)valueNameOffset, (int)valueNameLength);
                    }

                    if (!string.IsNullOrWhiteSpace(target))
                    {
                        if (!target.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                        {
                            target += ".dll";
                        }

                        targets.Add(target);
                    }
                }

                if (targets.Count == 0)
                {
                    continue;
                }

                map[name.ToLowerInvariant()] = targets.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            }

            if (map.Count == 0)
            {
                error = $"No API set entries parsed (version {version}).";
                return false;
            }

            schema = new ApiSetSchemaData(map, (int)version, sourcePath);
            return true;
        }

        private static bool TryFindApiSetSection(byte[] data, out int sectionOffset, out int sectionSize)
        {
            sectionOffset = 0;
            sectionSize = 0;

            if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
            {
                return false;
            }

            int peOffset = (int)ReadUInt32(data, 0x3C);
            if (peOffset <= 0 || peOffset + 0x18 > data.Length)
            {
                return false;
            }

            if (data[peOffset] != 'P' || data[peOffset + 1] != 'E')
            {
                return false;
            }

            int fileHeaderOffset = peOffset + 4;
            ushort numberOfSections = (ushort)ReadUInt16(data, fileHeaderOffset + 2);
            ushort sizeOfOptionalHeader = (ushort)ReadUInt16(data, fileHeaderOffset + 16);
            int sectionHeaderOffset = fileHeaderOffset + 20 + sizeOfOptionalHeader;

            if (sectionHeaderOffset <= 0 || sectionHeaderOffset + (numberOfSections * 40) > data.Length)
            {
                return false;
            }

            for (int i = 0; i < numberOfSections; i++)
            {
                int offset = sectionHeaderOffset + (i * 40);
                string name = Encoding.ASCII.GetString(data, offset, 8).TrimEnd('\0', ' ');
                int size = (int)ReadUInt32(data, offset + 16);
                int pointer = (int)ReadUInt32(data, offset + 20);

                if (string.Equals(name, ".apiset", StringComparison.OrdinalIgnoreCase))
                {
                    sectionOffset = pointer;
                    sectionSize = size;
                    return true;
                }
            }

            return false;
        }

        private static string ReadUnicodeString(ReadOnlySpan<byte> buffer, int offset, int byteLength)
        {
            if (offset < 0 || byteLength <= 0 || offset + byteLength > buffer.Length)
            {
                return string.Empty;
            }

            string value = Encoding.Unicode.GetString(buffer.Slice(offset, byteLength)).TrimEnd('\0');
            return value;
        }

        public PECOFFResult ToResult()
        {
            EnsureResourcesParsed();
            EnsureDebugDirectoryParsed();
            EnsureRelocationsParsed();
            EnsureExceptionDirectoryParsed();
            EnsureLoadConfigParsed();
            EnsureClrParsed();

            ApiSetSchemaInfo apiSetInfo = _apiSetSchemaInfo;
            if (apiSetInfo == null)
            {
                if (_apiSetSchema != null)
                {
                    apiSetInfo = new ApiSetSchemaInfo(true, _apiSetSchema.Version, GetApiSetFlavor(_apiSetSchema.Version), _apiSetSchema.SourcePath);
                }
                else
                {
                    apiSetInfo = new ApiSetSchemaInfo(false, 0, string.Empty, string.Empty);
                }
            }

            return new PECOFFResult(
                _filePath,
                _parseResult.Snapshot(),
                _imageKind,
                _coffObjectInfo,
                _coffArchiveInfo,
                _teImageInfo,
                _hash ?? string.Empty,
                _importHash ?? string.Empty,
                _isDotNetFile,
                _dotNetRuntimeHint ?? string.Empty,
                _isObfuscated,
                _obfuscationPercentage,
                _fileversion ?? string.Empty,
                _productversion ?? string.Empty,
                _companyName ?? string.Empty,
                _fileDescription ?? string.Empty,
                _internalName ?? string.Empty,
                _originalFilename ?? string.Empty,
                _productName ?? string.Empty,
                _comments ?? string.Empty,
                _legalCopyright ?? string.Empty,
                _legalTrademarks ?? string.Empty,
                _privateBuild ?? string.Empty,
                _specialBuild ?? string.Empty,
                _language ?? string.Empty,
                _versionInfoDetails,
                _fileAlignment,
                _sectionAlignment,
                _sizeOfHeaders,
                _dosRelocationInfo,
                _overlayInfo,
                _overlayContainers.ToArray(),
                _packingHints.ToArray(),
                _sectionEntropies.ToArray(),
                _sectionSlacks.ToArray(),
                _sectionGaps.ToArray(),
                _sectionPermissions.ToArray(),
                _sectionHeaders.ToArray(),
                _sectionDirectoryCoverage.ToArray(),
                _unmappedDataDirectories.ToArray(),
                _optionalHeaderChecksum,
                _computedChecksum,
                IsChecksumValid,
                _timeDateStamp,
                TimeDateStampUtc,
                _subsystemInfo,
                _dllCharacteristicsInfo,
                _securityFeaturesInfo,
                _dataDirectoryInfos,
                _dataDirectoryValidations.ToArray(),
                _architectureDirectory,
                _globalPtrDirectory,
                _iatDirectory,
                HasCertificate,
                _certificate ?? Array.Empty<byte>(),
                _certificates.ToArray(),
                _certificateEntries.ToArray(),
                _catalogSignatureInfo,
                _resources.ToArray(),
                _resourceStringTables.ToArray(),
                _resourceStringCoverage.ToArray(),
                _resourceMessageTables.ToArray(),
                _resourceDialogs.ToArray(),
                _resourceAccelerators.ToArray(),
                _resourceMenus.ToArray(),
                _resourceToolbars.ToArray(),
                _resourceManifests.ToArray(),
                _resourceLocaleCoverage.ToArray(),
                _resourceBitmaps.ToArray(),
                _resourceIcons.ToArray(),
                _resourceCursors.ToArray(),
                _resourceCursorGroups.ToArray(),
                _resourceFonts.ToArray(),
                _resourceFontDirectories.ToArray(),
                _resourceDlgInit.ToArray(),
                _resourceAnimatedCursors.ToArray(),
                _resourceAnimatedIcons.ToArray(),
                _resourceRcData.ToArray(),
                _resourceHtml.ToArray(),
                _resourceDlgInclude.ToArray(),
                _resourcePlugAndPlay.ToArray(),
                _resourceVxd.ToArray(),
                _iconGroups.ToArray(),
                _clrMetadata,
                _strongNameSignature,
                _strongNameValidation,
                _readyToRun,
                imports.ToArray(),
                _importEntries.ToArray(),
                _importDescriptors.ToArray(),
                _delayImportEntries.ToArray(),
                _delayImportDescriptors.ToArray(),
                exports.ToArray(),
                _exportEntries.ToArray(),
                _exportAnomalies,
                _boundImports.ToArray(),
                _debugDirectories.ToArray(),
                _baseRelocations.ToArray(),
                _baseRelocationSections.ToArray(),
                _relocationAnomalies,
                apiSetInfo,
                _exceptionFunctions.ToArray(),
                _exceptionSummary,
                _unwindInfoDetails.ToArray(),
                _arm64UnwindInfoDetails.ToArray(),
                _arm32UnwindInfoDetails.ToArray(),
                _ia64UnwindInfoDetails.ToArray(),
                _richHeader,
                _tlsInfo,
                _loadConfig,
                _assemblyReferenceInfos.Select(r => r.Name).ToArray(),
                _assemblyReferenceInfos.ToArray(),
                _coffRelocations.ToArray(),
                _coffSymbols.ToArray(),
                _coffStringTable.ToArray(),
                _coffLineNumbers.ToArray());
        }

        private static bool TryGetIntSize(uint size, out int intSize)
        {
            if (size > int.MaxValue)
            {
                intSize = 0;
                return false;
            }

            intSize = (int)size;
            return true;
        }

        private static void SetIfEmpty(ref string target, string value)
        {
            if (string.IsNullOrWhiteSpace(target) && !string.IsNullOrWhiteSpace(value))
            {
                target = value;
            }
        }

        private static int Align8(int value)
        {
            return (value + 7) & ~7;
        }

        private static int Align4(int value)
        {
            return (value + 3) & ~3;
        }

        private static uint AlignUp(uint value, uint alignment)
        {
            if (alignment == 0)
            {
                return value;
            }

            uint mask = alignment - 1;
            return (value + mask) & ~mask;
        }

        private static bool IsPowerOfTwo(uint value)
        {
            return value != 0 && (value & (value - 1)) == 0;
        }

        private bool IsStrictCertificateUniquenessModeEnabled()
        {
            return _options != null &&
                   (_options.StrictMode || _options.ValidationProfile == ValidationProfile.Strict);
        }

        private static CertificateTypeMetadataInfo BuildCertificateTypeMetadata(CertificateTypeKind typeKind, byte[] certData)
        {
            certData ??= Array.Empty<byte>();
            string sha256 = certData.Length > 0 ? ToHex(SHA256.HashData(certData)) : string.Empty;
            string preview = BuildHexPreview(certData, 32);

            switch (typeKind)
            {
                case CertificateTypeKind.X509:
                    if (certData.Length == 0)
                    {
                        return new CertificateTypeMetadataInfo(
                            "X509",
                            false,
                            "Empty X509 payload.",
                            string.Empty,
                            string.Empty,
                            string.Empty,
                            sha256,
                            preview);
                    }

                    try
                    {
                        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(certData);
                        string notes = string.IsNullOrWhiteSpace(certificate.NotBefore.ToString("O", CultureInfo.InvariantCulture)) ||
                                       string.IsNullOrWhiteSpace(certificate.NotAfter.ToString("O", CultureInfo.InvariantCulture))
                            ? string.Empty
                            : $"NotBefore={certificate.NotBefore:O}; NotAfter={certificate.NotAfter:O}";
                        return new CertificateTypeMetadataInfo(
                            "X509",
                            true,
                            notes,
                            certificate.Subject ?? string.Empty,
                            certificate.Issuer ?? string.Empty,
                            certificate.Thumbprint ?? string.Empty,
                            sha256,
                            preview);
                    }
                    catch (Exception ex)
                    {
                        return new CertificateTypeMetadataInfo(
                            "X509",
                            false,
                            ex.Message,
                            string.Empty,
                            string.Empty,
                            string.Empty,
                            sha256,
                            preview);
                    }

                case CertificateTypeKind.TsStackSigned:
                {
                    string notes = certData.Length >= 4
                        ? $"Header=0x{ReadUInt32(certData, 0):X8}; PayloadBytes={certData.Length}"
                        : $"PayloadBytes={certData.Length}";
                    return new CertificateTypeMetadataInfo(
                        "TsStackSigned",
                        certData.Length > 0,
                        notes,
                        string.Empty,
                        string.Empty,
                        string.Empty,
                        sha256,
                        preview);
                }

                case CertificateTypeKind.PkcsSignedData:
                    return new CertificateTypeMetadataInfo(
                        "PkcsSignedData",
                        certData.Length > 0,
                        $"PayloadBytes={certData.Length}",
                        string.Empty,
                        string.Empty,
                        string.Empty,
                        sha256,
                        preview);

                default:
                    return new CertificateTypeMetadataInfo(
                        typeKind.ToString(),
                        certData.Length > 0,
                        $"PayloadBytes={certData.Length}",
                        string.Empty,
                        string.Empty,
                        string.Empty,
                        sha256,
                        preview);
            }
        }

        private static SubsystemInfo BuildSubsystemInfo(Subsystem subsystem)
        {
            ushort value = (ushort)subsystem;
            string name = Enum.IsDefined(typeof(Subsystem), subsystem)
                ? subsystem.ToString()
                : "Unknown";

            bool isGui = subsystem == Subsystem.IMAGE_SUBSYSTEM_WINDOWS_GUI ||
                         subsystem == Subsystem.IMAGE_SUBSYSTEM_WINDOWS_CE_GUI;
            bool isConsole = subsystem == Subsystem.IMAGE_SUBSYSTEM_WINDOWS_CUI ||
                             subsystem == Subsystem.IMAGE_SUBSYSTEM_POSIX_CUI;

            return new SubsystemInfo(value, name, isGui, isConsole);
        }

        private static DllCharacteristicsInfo BuildDllCharacteristicsInfo(DllCharacteristics characteristics)
        {
            List<string> flags = new List<string>();
            foreach (DllCharacteristics flag in Enum.GetValues(typeof(DllCharacteristics)))
            {
                if (flag == 0)
                {
                    continue;
                }

                if ((characteristics & flag) != 0)
                {
                    flags.Add(flag.ToString());
                }
            }

            bool nxCompat = (characteristics & DllCharacteristics.IMAGE_DLL_CHARACTERISTICS_NX_COMPAT) != 0;
            bool aslrEnabled = (characteristics & DllCharacteristics.IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE) != 0;
            bool guardCf = (characteristics & DllCharacteristics.IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
            bool highEntropyVa = (characteristics & DllCharacteristics.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;

            return new DllCharacteristicsInfo(
                (ushort)characteristics,
                flags.ToArray(),
                nxCompat,
                aslrEnabled,
                guardCf,
                highEntropyVa);
        }

        private static LoadConfigGuardFlagsInfo DecodeGuardFlags(uint guardFlags)
        {
            if (guardFlags == 0)
            {
                return new LoadConfigGuardFlagsInfo(
                    guardFlags,
                    Array.Empty<string>(),
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false);
            }

            List<string> names = new List<string>();
            foreach (GuardFlags flag in Enum.GetValues(typeof(GuardFlags)))
            {
                if ((guardFlags & (uint)flag) != 0)
                {
                    names.Add(flag.ToString());
                }
            }

            bool cfInstrumented = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_CF_INSTRUMENTED) != 0;
            bool cfwInstrumented = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_CFW_INSTRUMENTED) != 0;
            bool cfFunctionTablePresent = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT) != 0;
            bool securityCookieUnused = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_SECURITY_COOKIE_UNUSED) != 0;
            bool protectDelayLoadIat = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_PROTECT_DELAYLOAD_IAT) != 0;
            bool delayLoadIatInOwnSection = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION) != 0;
            bool exportSuppressionInfoPresent = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT) != 0;
            bool enableExportSuppression = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION) != 0;
            bool longjumpTablePresent = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT) != 0;
            bool rfInstrumented = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_RF_INSTRUMENTED) != 0;
            bool rfEnable = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_RF_ENABLE) != 0;
            bool rfStrict = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_RF_STRICT) != 0;
            bool retpolinePresent = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_RETPOLINE_PRESENT) != 0;
            bool ehContinuationTablePresent = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT) != 0;
            bool xfgEnabled = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_XFG_ENABLED) != 0;
            bool xfgTablePresent = (guardFlags & (uint)GuardFlags.IMAGE_GUARD_XFG_TABLE_PRESENT) != 0;

            return new LoadConfigGuardFlagsInfo(
                guardFlags,
                names.ToArray(),
                cfInstrumented,
                cfwInstrumented,
                cfFunctionTablePresent,
                securityCookieUnused,
                protectDelayLoadIat,
                delayLoadIatInOwnSection,
                exportSuppressionInfoPresent,
                enableExportSuppression,
                longjumpTablePresent,
                rfInstrumented,
                rfEnable,
                rfStrict,
                retpolinePresent,
                ehContinuationTablePresent,
                xfgEnabled,
                xfgTablePresent);
        }

        internal static LoadConfigGuardFlagsInfo DecodeGuardFlagsForTest(uint guardFlags)
        {
            return DecodeGuardFlags(guardFlags);
        }

        private static LoadConfigGlobalFlagsInfo DecodeGlobalFlags(uint globalFlagsClear, uint globalFlagsSet)
        {
            uint effective = globalFlagsSet & ~globalFlagsClear;
            if (effective == 0)
            {
                return new LoadConfigGlobalFlagsInfo(0, Array.Empty<string>());
            }

            List<string> names = new List<string>();
            uint knownMask = 0;
            foreach (GlobalFlags flag in Enum.GetValues(typeof(GlobalFlags)))
            {
                uint value = (uint)flag;
                knownMask |= value;
                if ((effective & value) != 0)
                {
                    names.Add(flag.ToString());
                }
            }

            uint unknown = effective & ~knownMask;
            if (unknown != 0)
            {
                names.Add("0x" + unknown.ToString("X8", CultureInfo.InvariantCulture));
            }

            return new LoadConfigGlobalFlagsInfo(effective, names.ToArray());
        }

        internal static LoadConfigGlobalFlagsInfo DecodeGlobalFlagsForTest(uint globalFlagsClear, uint globalFlagsSet)
        {
            return DecodeGlobalFlags(globalFlagsClear, globalFlagsSet);
        }

        private static int GetOptionalHeaderChecksumOffset(PEFormat magic)
        {
            if (magic == PEFormat.PE32plus)
            {
                return (int)Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER64), nameof(IMAGE_OPTIONAL_HEADER64.CheckSum));
            }

            return (int)Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER32), nameof(IMAGE_OPTIONAL_HEADER32.CheckSum));
        }

        private static uint ComputeChecksum(Stream stream, long checksumOffset)
        {
            if (stream == null || !stream.CanRead || !stream.CanSeek || checksumOffset < 0)
            {
                return 0;
            }

            long originalPosition = stream.Position;
            stream.Position = 0;

            ulong sum = 0;
            long length = stream.Length;
            long offset = 0;
            bool hasPending = false;
            byte pending = 0;

            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                int bytesRead;
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    int index = 0;
                    while (index < bytesRead)
                    {
                        long globalOffset = offset + index;
                        if (globalOffset >= checksumOffset && globalOffset < checksumOffset + 4)
                        {
                            index++;
                            continue;
                        }

                        byte current = buffer[index];
                        if (!hasPending)
                        {
                            pending = current;
                            hasPending = true;
                        }
                        else
                        {
                            ushort word = (ushort)(pending | (current << 8));
                            sum += word;
                            sum = (sum & 0xFFFF) + (sum >> 16);
                            hasPending = false;
                            pending = 0;
                        }

                        index++;
                    }

                    offset += bytesRead;
                }

                if (hasPending)
                {
                    sum += pending;
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }

                sum = (sum & 0xFFFF) + (sum >> 16);
                sum = (sum & 0xFFFF) + (sum >> 16);
                sum += (uint)length;
                sum = (sum & 0xFFFF) + (sum >> 16);
                sum = sum & 0xFFFF;
                return (uint)sum;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                stream.Position = originalPosition;
            }
        }

        private static string ComputeHash(Stream stream)
        {
            if (stream == null || !stream.CanRead || !stream.CanSeek)
            {
                return string.Empty;
            }

            long originalPosition = stream.Position;
            stream.Position = 0;

            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                using (IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    int bytesRead;
                    while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        hasher.AppendData(buffer, 0, bytesRead);
                    }

                    byte[] hash = hasher.GetHashAndReset();
                    StringBuilder sbHash = new StringBuilder(hash.Length * 2);
                    foreach (byte b in hash)
                    {
                        sbHash.Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
                    }
                    return sbHash.ToString();
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                stream.Position = originalPosition;
            }
        }

        private void ComputeImportHash()
        {
            if (_options == null || !_options.ComputeImportHash)
            {
                _importHash = string.Empty;
                return;
            }

            _importHash = ComputeImportHash(_importEntries);
        }

        private void ComputeCatalogSignatureInfo()
        {
            _catalogSignatureInfo = null;
            if (_options?.AuthenticodePolicy == null || !_options.AuthenticodePolicy.EnableCatalogSignatureCheck)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(_filePath))
            {
                return;
            }

            CatalogSignatureInfo info = CertificateUtilities.GetCatalogSignatureInfo(_filePath, _options.AuthenticodePolicy);
            _catalogSignatureInfo = info;
            if (info != null && info.Checked && !string.IsNullOrWhiteSpace(info.Error))
            {
                Warn(ParseIssueCategory.Authenticode, "Catalog signature check: " + info.Error);
            }
        }

        private static string ComputeImportHash(IReadOnlyList<ImportEntry> entries)
        {
            if (entries == null || entries.Count == 0)
            {
                return string.Empty;
            }

            Dictionary<string, bool> useIntByDll = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (ImportEntry entry in entries)
            {
                if (string.IsNullOrWhiteSpace(entry.DllName))
                {
                    continue;
                }

                if (entry.Source == ImportThunkSource.ImportNameTable)
                {
                    useIntByDll[entry.DllName] = true;
                }
                else if (!useIntByDll.ContainsKey(entry.DllName))
                {
                    useIntByDll[entry.DllName] = false;
                }
            }

            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach (ImportEntry entry in entries)
            {
                if (string.IsNullOrWhiteSpace(entry.DllName))
                {
                    continue;
                }

                if (!useIntByDll.TryGetValue(entry.DllName, out bool useInt))
                {
                    continue;
                }

                if (useInt && entry.Source != ImportThunkSource.ImportNameTable)
                {
                    continue;
                }

                if (!useInt && entry.Source != ImportThunkSource.ImportAddressTable)
                {
                    continue;
                }

                string dllName = NormalizeImportHashName(entry.DllName);
                if (string.IsNullOrWhiteSpace(dllName))
                {
                    continue;
                }

                string functionName;
                if (entry.IsByOrdinal || string.IsNullOrWhiteSpace(entry.Name))
                {
                    functionName = "ord" + entry.Ordinal.ToString(System.Globalization.CultureInfo.InvariantCulture);
                }
                else
                {
                    functionName = entry.Name.ToLowerInvariant();
                }

                if (!first)
                {
                    sb.Append(',');
                }

                sb.Append(dllName)
                  .Append('.')
                  .Append(functionName);
                first = false;
            }

            if (first)
            {
                return string.Empty;
            }

            using (MD5 md5 = MD5.Create())
            {
                byte[] data = Encoding.ASCII.GetBytes(sb.ToString());
                byte[] hash = md5.ComputeHash(data);
                return ToHex(hash).ToLowerInvariant();
            }
        }

        private static string NormalizeImportHashName(string dllName)
        {
            if (string.IsNullOrWhiteSpace(dllName))
            {
                return string.Empty;
            }

            string normalized = dllName.Trim().ToLowerInvariant();
            if (normalized.EndsWith(".dll", StringComparison.Ordinal))
            {
                return normalized.Substring(0, normalized.Length - 4);
            }

            if (normalized.EndsWith(".ocx", StringComparison.Ordinal) ||
                normalized.EndsWith(".sys", StringComparison.Ordinal))
            {
                return normalized.Substring(0, normalized.Length - 4);
            }

            return normalized;
        }

        private void ComputeOverlayInfo(List<IMAGE_SECTION_HEADER> sections)
        {
            if (PEFileStream == null)
            {
                _overlayInfo = new OverlayInfo(0, 0);
                return;
            }

            long fileLength = PEFileStream.Length;
            long maxEnd = 0;
            if (sections != null)
            {
                foreach (IMAGE_SECTION_HEADER section in sections)
                {
                    long start = section.PointerToRawData;
                    long size = section.SizeOfRawData;
                    if (start < 0 || size <= 0)
                    {
                        continue;
                    }

                    long end = start + size;
                    if (end > maxEnd)
                    {
                        maxEnd = end;
                    }
                }
            }

            if (maxEnd > fileLength)
            {
                maxEnd = fileLength;
            }

            long overlaySize = fileLength - maxEnd;
            if (overlaySize < 0)
            {
                overlaySize = 0;
            }

            _overlayInfo = new OverlayInfo(maxEnd, overlaySize);
        }

        private void ComputeSectionEntropies(List<IMAGE_SECTION_HEADER> sections)
        {
            _sectionEntropies.Clear();
            if (_options == null || !_options.ComputeSectionEntropy || PEFileStream == null)
            {
                return;
            }

            foreach (IMAGE_SECTION_HEADER section in sections)
            {
                if (section.SizeOfRawData == 0)
                {
                    continue;
                }

                if (!TryGetIntSize(section.SizeOfRawData, out int size) || size <= 0)
                {
                    continue;
                }

                if (!TrySetPosition(section.PointerToRawData, size))
                {
                    continue;
                }

                byte[] buffer = ArrayPool<byte>.Shared.Rent(size);
                try
                {
                    ReadExactly(PEFileStream, buffer, 0, size);
                    double entropy = ComputeShannonEntropy(new ReadOnlySpan<byte>(buffer, 0, size));
                    string name = section.Section.TrimEnd('\0');
                    _sectionEntropies.Add(new SectionEntropyInfo(name, section.SizeOfRawData, entropy));

                    bool isExecutable = (section.Characteristics & SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0;
                    bool isWritable = (section.Characteristics & SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0;
                    bool isCode = (section.Characteristics & SectionCharacteristics.IMAGE_SCN_CNT_CODE) != 0;
                    if (entropy >= 7.3 && isExecutable && isWritable)
                    {
                        Warn(ParseIssueCategory.Sections, $"Section {name} has high entropy and is RWX.");
                    }
                    else if (entropy >= 7.3 && isExecutable && !isCode)
                    {
                        Warn(ParseIssueCategory.Sections, $"Section {name} has high entropy and is executable but not marked as code.");
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
        }

        private void ComputePackingHints(List<IMAGE_SECTION_HEADER> sections)
        {
            _packingHints.Clear();
            if (PEFileStream == null || sections == null)
            {
                return;
            }

            byte[] headerBuffer = new byte[5];
            foreach (IMAGE_SECTION_HEADER section in sections)
            {
                string name = NormalizeSectionName(section.Section);
                if (name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase))
                {
                    _packingHints.Add(new PackingHintInfo("Section", name, "Section name suggests UPX packing."));
                }

                if (section.SizeOfRawData >= 5 && TrySetPosition(section.PointerToRawData, 5))
                {
                    int read = PEFileStream.Read(headerBuffer, 0, headerBuffer.Length);
                    if (read == headerBuffer.Length && IsLzmaHeader(headerBuffer))
                    {
                        _packingHints.Add(new PackingHintInfo("Section", name, "LZMA header detected in section."));
                    }
                }
            }

            foreach (SectionEntropyInfo entropy in _sectionEntropies)
            {
                if (entropy.RawSize >= 1024 && entropy.Entropy >= 7.2)
                {
                    _packingHints.Add(new PackingHintInfo(
                        "SectionEntropy",
                        entropy.Name,
                        string.Format(CultureInfo.InvariantCulture, "High entropy ({0:F2}).", entropy.Entropy)));
                }
            }

            if (_overlayInfo != null && _overlayInfo.HasOverlay)
            {
                long size = _overlayInfo.Size;
                int sampleSize = (int)Math.Min(64, size);
                if (sampleSize > 0 && TrySetPosition(_overlayInfo.StartOffset, sampleSize))
                {
                    byte[] overlaySample = new byte[sampleSize];
                    ReadExactly(PEFileStream, overlaySample, 0, overlaySample.Length);
                    AddOverlaySignatureHints(overlaySample);
                }

                ParseOverlayContainers();
            }
        }

        private void AddOverlaySignatureHints(ReadOnlySpan<byte> data)
        {
            foreach (PackingHintInfo hint in GetOverlaySignatureHints(data))
            {
                _packingHints.Add(hint);
            }
        }

        internal static PackingHintInfo[] DetectOverlayHintsForTest(byte[] data)
        {
            if (data == null)
            {
                return Array.Empty<PackingHintInfo>();
            }

            return GetOverlaySignatureHints(data);
        }

        internal static OverlayContainerInfo ParseZipContainerForTest(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            using MemoryStream stream = new MemoryStream(data, writable: false);
            return TryParseZipContainer(stream, 0, data.Length, out OverlayContainerInfo info) ? info : null;
        }

        internal static OverlayContainerInfo ParseSevenZipContainerForTest(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            using MemoryStream stream = new MemoryStream(data, writable: false);
            return TryParseSevenZipContainer(stream, 0, data.Length, out OverlayContainerInfo info) ? info : null;
        }

        internal static OverlayContainerInfo ParseRar5ContainerForTest(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            using MemoryStream stream = new MemoryStream(data, writable: false);
            return TryParseRarContainer(stream, 0, data.Length, out OverlayContainerInfo info) ? info : null;
        }

        internal static bool TryReadRar5VintForTest(byte[] data, out ulong value, out int bytesRead)
        {
            value = 0;
            bytesRead = 0;
            if (data == null)
            {
                return false;
            }

            int offset = 0;
            if (!TryReadRar5Vint(data, ref offset, out value))
            {
                return false;
            }

            bytesRead = offset;
            return true;
        }

        private static PackingHintInfo[] GetOverlaySignatureHints(ReadOnlySpan<byte> data)
        {
            List<PackingHintInfo> hints = new List<PackingHintInfo>();
            if (data.Length < 4)
            {
                return hints.ToArray();
            }

            if (HasPrefix(data, new byte[] { 0x55, 0x50, 0x58, 0x21 })) // "UPX!"
            {
                hints.Add(new PackingHintInfo("Overlay", "UPX", "UPX overlay signature detected."));
            }

            if (HasPrefix(data, new byte[] { 0x50, 0x4B, 0x03, 0x04 })) // ZIP
            {
                hints.Add(new PackingHintInfo("Overlay", "ZIP", "ZIP archive signature detected."));
            }

            if (HasPrefix(data, new byte[] { 0x52, 0x61, 0x72, 0x21 })) // "Rar!"
            {
                hints.Add(new PackingHintInfo("Overlay", "RAR", "RAR archive signature detected."));
            }

            if (HasPrefix(data, new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C })) // 7z
            {
                hints.Add(new PackingHintInfo("Overlay", "7-Zip", "7z archive signature detected."));
            }

            if (IsLzmaHeader(data))
            {
                hints.Add(new PackingHintInfo("Overlay", "LZMA", "LZMA header detected."));
            }

            if (ContainsAscii(data, "Nullsoft", 4096) || ContainsAscii(data, "NSIS", 4096))
            {
                hints.Add(new PackingHintInfo("Overlay", "NSIS", "NSIS installer signature detected."));
            }

            return hints.ToArray();
        }

        private void ParseOverlayContainers()
        {
            _overlayContainers.Clear();
            if (PEFileStream == null || _overlayInfo == null || !_overlayInfo.HasOverlay)
            {
                return;
            }

            long overlayStart = _overlayInfo.StartOffset;
            long overlaySize = _overlayInfo.Size;
            if (overlaySize <= 0)
            {
                return;
            }

            int headerSize = (int)Math.Min(64, overlaySize);
            if (!TrySetPosition(overlayStart, headerSize))
            {
                return;
            }

            byte[] header = new byte[headerSize];
            ReadExactly(PEFileStream, header, 0, header.Length);
            int zipOffset = IndexOfSignature(header, new byte[] { 0x50, 0x4B, 0x03, 0x04 });
            int rarOffset = IndexOfSignature(header, new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 });
            int sevenOffset = IndexOfSignature(header, new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C });

            if (zipOffset >= 0)
            {
                long archiveStart = overlayStart + zipOffset;
                long archiveSize = overlaySize - zipOffset;
                if (TryParseZipContainer(PEFileStream, archiveStart, archiveSize, out OverlayContainerInfo info))
                {
                    _overlayContainers.Add(info);
                }
            }
            else if (rarOffset >= 0)
            {
                long archiveStart = overlayStart + rarOffset;
                long archiveSize = overlaySize - rarOffset;
                if (TryParseRarContainer(PEFileStream, archiveStart, archiveSize, out OverlayContainerInfo info))
                {
                    _overlayContainers.Add(info);
                }
            }
            else if (sevenOffset >= 0)
            {
                long archiveStart = overlayStart + sevenOffset;
                long archiveSize = overlaySize - sevenOffset;
                if (TryParseSevenZipContainer(PEFileStream, archiveStart, archiveSize, out OverlayContainerInfo info))
                {
                    _overlayContainers.Add(info);
                }
            }
        }

        private static bool TryParseZipContainer(Stream stream, long archiveStart, long archiveSize, out OverlayContainerInfo info)
        {
            info = null;
            if (archiveSize < 22 || !stream.CanSeek)
            {
                return false;
            }

            long originalPosition = stream.Position;
            try
            {
                int tailSize = (int)Math.Min(archiveSize, 0x10000 + 22);
                long tailOffset = archiveStart + archiveSize - tailSize;
                if (!TrySetPosition(stream, tailOffset, tailSize))
                {
                    return false;
                }

                byte[] tail = new byte[tailSize];
                ReadExactly(stream, tail, 0, tail.Length);
                int eocdIndex = FindZipEocd(tail);
                if (eocdIndex < 0)
                {
                    return false;
                }

                ushort totalEntries = ReadUInt16(tail, eocdIndex + 10);
                uint centralDirSize = ReadUInt32(tail, eocdIndex + 12);
                uint centralDirOffset = ReadUInt32(tail, eocdIndex + 16);
                bool zip64 = totalEntries == 0xFFFF || centralDirSize == 0xFFFFFFFF || centralDirOffset == 0xFFFFFFFF;

                long centralDirAbsolute = archiveStart + centralDirOffset;
                long archiveEnd = archiveStart + archiveSize;
                bool sizeFits = centralDirAbsolute >= archiveStart && centralDirAbsolute <= archiveEnd &&
                                centralDirAbsolute + centralDirSize <= archiveEnd;
                string notes = zip64 ? "Zip64 values detected; entry counts may be partial." : string.Empty;
                if (!sizeFits)
                {
                    notes = AppendNote(notes, "central directory outside overlay bounds");
                }

                int maxEntries = Math.Min(totalEntries == 0xFFFF ? 200 : totalEntries, 200);
                List<OverlayContainerEntry> entries = new List<OverlayContainerEntry>();
                bool truncated = false;
                if (sizeFits && maxEntries > 0)
                {
                    if (!TrySetPosition(stream, centralDirAbsolute, (int)Math.Min(centralDirSize, int.MaxValue)))
                    {
                        notes = AppendNote(notes, "central directory offset invalid");
                    }
                    else
                    {
                        for (int i = 0; i < maxEntries; i++)
                        {
                            if (!TryReadZipCentralDirectoryEntry(stream, out OverlayContainerEntry entry))
                            {
                                notes = AppendNote(notes, "failed to parse central directory entries");
                                break;
                            }

                            entries.Add(entry);
                        }

                        if ((totalEntries != 0xFFFF && totalEntries > maxEntries) ||
                            (totalEntries == 0xFFFF && entries.Count == maxEntries))
                        {
                            truncated = true;
                        }
                    }
                }

                int declaredCount = totalEntries == 0xFFFF ? entries.Count : totalEntries;
                info = new OverlayContainerInfo(
                    "ZIP",
                    zip64 ? "Zip64" : "Zip",
                    archiveStart,
                    archiveSize,
                    declaredCount,
                    truncated,
                    notes,
                    entries.ToArray());
                return true;
            }
            finally
            {
                if (stream.CanSeek)
                {
                    stream.Position = originalPosition;
                }
            }
        }

        private static bool TryParseRarContainer(Stream stream, long archiveStart, long archiveSize, out OverlayContainerInfo info)
        {
            info = null;
            if (archiveSize < 7 || !stream.CanSeek)
            {
                return false;
            }

            long originalPosition = stream.Position;
            try
            {
                if (!TrySetPosition(stream, archiveStart, (int)Math.Min(8, archiveSize)))
                {
                    return false;
                }

                byte[] signature = new byte[Math.Min(8, (int)archiveSize)];
                ReadExactly(stream, signature, 0, signature.Length);
                if (HasPrefix(signature, new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 }))
                {
                    if (TryParseRar5Container(stream, archiveStart, archiveSize, out OverlayContainerInfo rar5Info))
                    {
                        info = rar5Info;
                        return true;
                    }
                }

                if (!HasPrefix(signature, new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 }))
                {
                    return false;
                }

                long offset = archiveStart + 7;
                long archiveEnd = archiveStart + archiveSize;
                List<OverlayContainerEntry> entries = new List<OverlayContainerEntry>();
                int maxEntries = 200;
                bool truncated = false;
                string notes = string.Empty;

                while (offset + 7 <= archiveEnd && entries.Count < maxEntries)
                {
                    if (!TrySetPosition(stream, offset, 7))
                    {
                        break;
                    }

                    byte[] header = new byte[7];
                    ReadExactly(stream, header, 0, header.Length);
                    ushort flags = ReadUInt16(header, 3);
                    ushort headSize = ReadUInt16(header, 5);
                    if (headSize < 7)
                    {
                        notes = AppendNote(notes, "invalid header size");
                        break;
                    }

                    uint addSize = 0;
                    int extraSize = 0;
                    if ((flags & 0x8000) != 0)
                    {
                        if (!TrySetPosition(stream, offset + 7, 4))
                        {
                            break;
                        }

                        byte[] addSizeBytes = new byte[4];
                        ReadExactly(stream, addSizeBytes, 0, addSizeBytes.Length);
                        addSize = ReadUInt32(addSizeBytes, 0);
                        extraSize = 4;
                    }

                    int headerDataSize = headSize - 7 - extraSize;
                    if (headerDataSize < 0)
                    {
                        notes = AppendNote(notes, "header data size underflow");
                        break;
                    }

                    byte[] headerData = new byte[headerDataSize];
                    if (headerDataSize > 0)
                    {
                        if (!TrySetPosition(stream, offset + 7 + extraSize, headerDataSize))
                        {
                            break;
                        }

                        ReadExactly(stream, headerData, 0, headerData.Length);
                    }

                    byte headerType = header[2];
                    if (headerType == 0x74)
                    {
                        TryParseRar4FileHeader(headerData, flags, out OverlayContainerEntry entry);
                        if (entry != null)
                        {
                            entries.Add(entry);
                        }
                    }

                    long advance = headSize + addSize;
                    if (advance <= 0)
                    {
                        break;
                    }

                    offset += advance;
                }

                if (entries.Count >= maxEntries)
                {
                    truncated = true;
                }

                info = new OverlayContainerInfo(
                    "RAR",
                    "RAR4",
                    archiveStart,
                    archiveSize,
                    entries.Count,
                    truncated,
                    notes,
                    entries.ToArray());
                return true;
            }
            finally
            {
                if (stream.CanSeek)
                {
                    stream.Position = originalPosition;
                }
            }
        }

        private static bool TryParseSevenZipContainer(Stream stream, long archiveStart, long archiveSize, out OverlayContainerInfo info)
        {
            info = null;
            if (archiveSize < 32 || !stream.CanSeek)
            {
                return false;
            }

            long originalPosition = stream.Position;
            try
            {
                if (!TrySetPosition(stream, archiveStart, 32))
                {
                    return false;
                }

                byte[] header = new byte[32];
                ReadExactly(stream, header, 0, header.Length);
                if (!HasPrefix(header, new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }))
                {
                    return false;
                }

                byte major = header[6];
                byte minor = header[7];
                ulong nextHeaderOffset = ReadUInt64(header, 12);
                ulong nextHeaderSize = ReadUInt64(header, 20);
                uint nextHeaderCrc = ReadUInt32(header, 28);
                string notes = string.Format(
                    CultureInfo.InvariantCulture,
                    "NextHeaderOffset=0x{0:X}, Size={1}, CRC=0x{2:X8}",
                    nextHeaderOffset,
                    nextHeaderSize,
                    nextHeaderCrc);

                OverlayContainerEntry[] entries = Array.Empty<OverlayContainerEntry>();
                bool truncated = false;
                if (nextHeaderSize > 0)
                {
                    if (TryParseSevenZipNextHeader(stream, archiveStart, nextHeaderOffset, nextHeaderSize, out entries, out truncated, out string headerNotes))
                    {
                        notes = AppendNote(notes, headerNotes);
                    }
                    else
                    {
                        notes = AppendNote(notes, "NextHeader parsing failed");
                    }
                }

                info = new OverlayContainerInfo(
                    "7-Zip",
                    string.Format(CultureInfo.InvariantCulture, "{0}.{1}", major, minor),
                    archiveStart,
                    archiveSize,
                    entries.Length,
                    truncated,
                    notes,
                    entries);
                return true;
            }
            finally
            {
                if (stream.CanSeek)
                {
                    stream.Position = originalPosition;
                }
            }
        }

        private static bool TryParseRar5Container(Stream stream, long archiveStart, long archiveSize, out OverlayContainerInfo info)
        {
            info = null;
            if (archiveSize < 8 || !stream.CanSeek)
            {
                return false;
            }

            long originalPosition = stream.Position;
            try
            {
                if (!TrySetPosition(stream, archiveStart + 8, 1))
                {
                    return false;
                }

                long cursor = archiveStart + 8;
                long archiveEnd = archiveStart + archiveSize;
                int headerCount = 0;
                int fileHeaderCount = 0;
                List<OverlayContainerEntry> entries = new List<OverlayContainerEntry>();
                string notes = string.Empty;
                int maxHeaders = 200;

                while (cursor + 6 <= archiveEnd && headerCount < maxHeaders)
                {
                    int previewSize = (int)Math.Min(64, archiveEnd - cursor);
                    if (!TrySetPosition(stream, cursor, previewSize))
                    {
                        break;
                    }

                    byte[] headerPrefix = new byte[previewSize];
                    ReadExactly(stream, headerPrefix, 0, headerPrefix.Length);
                    int offset = 0;
                    if (headerPrefix.Length < 5)
                    {
                        break;
                    }

                    uint _ = ReadUInt32(headerPrefix, offset);
                    offset += 4;
                    if (!TryReadRar5Vint(headerPrefix, ref offset, out ulong headerSize))
                    {
                        notes = AppendNote(notes, "RAR5 header size decode failed");
                        break;
                    }

                    long headerDataStart = cursor + offset;
                    long headerDataEnd = headerDataStart + (long)headerSize;
                    if (headerSize == 0 || headerDataEnd > archiveEnd)
                    {
                        notes = AppendNote(notes, "RAR5 header size out of bounds");
                        break;
                    }

                    int headerBaseOffset = offset;
                    int headerDataOffset = offset;
                    if (!TryReadRar5Vint(headerPrefix, ref headerDataOffset, out ulong headerType))
                    {
                        notes = AppendNote(notes, "RAR5 header type decode failed");
                        break;
                    }

                    if (!TryReadRar5Vint(headerPrefix, ref headerDataOffset, out ulong headerFlags))
                    {
                        notes = AppendNote(notes, "RAR5 header flags decode failed");
                        break;
                    }

                    if (headerType == 1)
                    {
                        // main header
                    }

                    ulong dataSize = 0;
                    if ((headerFlags & 0x0002) != 0)
                    {
                        TryReadRar5Vint(headerPrefix, ref headerDataOffset, out dataSize);
                    }

                    ulong headerDataSize = 0;
                    if (headerSize > (ulong)(headerDataOffset - headerBaseOffset))
                    {
                        headerDataSize = headerSize - (ulong)(headerDataOffset - headerBaseOffset);
                    }
                    long fileHeaderDataStart = cursor + headerDataOffset;

                    if (headerType == 2 || headerType == 3)
                    {
                        if (TryParseRar5FileEntry(stream, fileHeaderDataStart, headerDataSize, dataSize, out OverlayContainerEntry entry))
                        {
                            entries.Add(entry);
                            fileHeaderCount++;
                        }
                    }

                    headerCount++;
                    long next = headerDataEnd;
                    if (dataSize > 0)
                    {
                        long remaining = archiveEnd - headerDataEnd;
                        next += (long)Math.Min(dataSize, (ulong)Math.Max(0, remaining));
                    }

                    if (next <= cursor)
                    {
                        break;
                    }

                    cursor = next;
                }

                if (headerCount >= maxHeaders)
                {
                    notes = AppendNote(notes, "header parsing truncated");
                }

                notes = AppendNote(notes, string.Format(CultureInfo.InvariantCulture, "Headers={0}, FileHeaders={1}", headerCount, fileHeaderCount));
                info = new OverlayContainerInfo(
                    "RAR",
                    "RAR5",
                    archiveStart,
                    archiveSize,
                    fileHeaderCount,
                    headerCount >= maxHeaders,
                    notes,
                    entries.ToArray());
                return true;
            }
            finally
            {
                if (stream.CanSeek)
                {
                    stream.Position = originalPosition;
                }
            }
        }

        private static bool TryParseRar5FileEntry(Stream stream, long headerDataStart, ulong headerSize, ulong packedSize, out OverlayContainerEntry entry)
        {
            entry = null;
            if (!stream.CanSeek || headerSize == 0)
            {
                return false;
            }

            int readSize = (int)Math.Min((long)headerSize, 4096);
            if (!TrySetPosition(stream, headerDataStart, readSize))
            {
                return false;
            }

            byte[] buffer = new byte[readSize];
            ReadExactly(stream, buffer, 0, buffer.Length);
            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(buffer);

            int offset = 0;
            if (!TryReadRar5Vint(span, ref offset, out ulong fileFlags))
            {
                return false;
            }

            ulong uncompressedSize = 0;
            int tempOffset = offset;
            if (TryReadRar5Vint(span, ref tempOffset, out ulong sizeCandidate))
            {
                uncompressedSize = sizeCandidate;
                offset = tempOffset;
            }

            if (!TryFindRar5FileName(span, offset, out string name, out bool isDirectory, out string notes))
            {
                return false;
            }

            if ((fileFlags & 0x01) != 0)
            {
                isDirectory = true;
            }

            entry = new OverlayContainerEntry(
                name,
                (long)Math.Min(packedSize, (ulong)long.MaxValue),
                (long)Math.Min(uncompressedSize, (ulong)long.MaxValue),
                "RAR5",
                (ushort)Math.Min(fileFlags, ushort.MaxValue),
                isDirectory,
                notes);
            return true;
        }

        private static bool TryFindRar5FileName(ReadOnlySpan<byte> data, int startOffset, out string name, out bool isDirectory, out string notes)
        {
            name = string.Empty;
            isDirectory = false;
            notes = string.Empty;
            if (startOffset >= data.Length)
            {
                return false;
            }

            int offset = startOffset;
            if (TryReadRar5Vint(data, ref offset, out ulong length) &&
                length > 0 &&
                length <= (ulong)(data.Length - offset))
            {
                if (TryDecodeUtf8String(data.Slice(offset, (int)length), out name))
                {
                    isDirectory = name.EndsWith("/", StringComparison.Ordinal) || name.EndsWith("\\", StringComparison.Ordinal);
                    return true;
                }
            }

            int bestOffset = -1;
            ulong bestLength = 0;
            string bestName = string.Empty;
            int scan = startOffset;
            while (scan < data.Length)
            {
                int tmp = scan;
                if (!TryReadRar5Vint(data, ref tmp, out ulong candidate))
                {
                    break;
                }

                if (candidate > 0 && candidate <= (ulong)(data.Length - tmp))
                {
                    ReadOnlySpan<byte> nameBytes = data.Slice(tmp, (int)candidate);
                    if (TryDecodeUtf8String(nameBytes, out string decoded))
                    {
                        bestOffset = tmp;
                        bestLength = candidate;
                        bestName = decoded;
                        if (candidate == (ulong)(data.Length - tmp))
                        {
                            break;
                        }
                    }
                }

                scan = tmp;
            }

            if (bestOffset >= 0)
            {
                name = bestName;
                isDirectory = name.EndsWith("/", StringComparison.Ordinal) || name.EndsWith("\\", StringComparison.Ordinal);
                if (bestLength < (ulong)(data.Length - bestOffset))
                {
                    notes = "RAR5 name extracted with trailing data";
                }
                return true;
            }

            return false;
        }

        private static bool TryDecodeUtf8String(ReadOnlySpan<byte> data, out string value)
        {
            value = string.Empty;
            if (data.Length == 0)
            {
                return false;
            }

            try
            {
                value = Encoding.UTF8.GetString(data).TrimEnd('\0');
                return !string.IsNullOrWhiteSpace(value);
            }
            catch (DecoderFallbackException)
            {
                return false;
            }
        }

        private static bool TryParseSevenZipNextHeader(Stream stream, long archiveStart, ulong nextHeaderOffset, ulong nextHeaderSize, out OverlayContainerEntry[] entries, out bool truncated, out string notes)
        {
            entries = Array.Empty<OverlayContainerEntry>();
            truncated = false;
            notes = string.Empty;

            if (nextHeaderSize == 0 || nextHeaderSize > int.MaxValue)
            {
                notes = "NextHeader size unsupported";
                return false;
            }

            long headerOffset = archiveStart + 32 + (long)nextHeaderOffset;
            int size = (int)nextHeaderSize;
            int maxSize = Math.Min(size, 1024 * 512);
            if (!TrySetPosition(stream, headerOffset, maxSize))
            {
                notes = "NextHeader offset invalid";
                return false;
            }

            byte[] buffer = new byte[maxSize];
            ReadExactly(stream, buffer, 0, buffer.Length);
            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(buffer);

            if (TryParseSevenZipHeader(span, out OverlayContainerEntry[] parsedEntries, out bool parsedTruncated, out string parsedNotes))
            {
                entries = parsedEntries;
                truncated = parsedTruncated;
                notes = parsedNotes;
                return true;
            }

            if (TryDecodeSevenZipEncodedHeader(stream, archiveStart, nextHeaderOffset, nextHeaderSize, span, out byte[] decodedHeader, out string decodeNotes))
            {
                notes = AppendNote(notes, decodeNotes);
                if (TryParseSevenZipHeader(decodedHeader, out parsedEntries, out parsedTruncated, out parsedNotes))
                {
                    entries = parsedEntries;
                    truncated = parsedTruncated;
                    notes = AppendNote(notes, parsedNotes);
                    return true;
                }
            }
            else
            {
                notes = AppendNote(notes, decodeNotes);
            }

            return false;
        }

        private static bool TryParseSevenZipFilesInfo(ReadOnlySpan<byte> span, ref int offset, out OverlayContainerEntry[] entries, out bool truncated, out string notes)
        {
            entries = Array.Empty<OverlayContainerEntry>();
            truncated = false;
            notes = string.Empty;

            if (!TryRead7zUInt64(span, ref offset, out ulong numFiles) || numFiles > int.MaxValue)
            {
                return false;
            }

            int fileCount = (int)numFiles;
            string[] names = new string[fileCount];
            bool[] emptyStreams = new bool[fileCount];
            bool[] emptyFiles = new bool[fileCount];

            while (offset < span.Length)
            {
                byte propId = ReadByte(span, ref offset);
                if (propId == 0x00)
                {
                    break;
                }

                if (!TryRead7zUInt64(span, ref offset, out ulong size) || size > int.MaxValue || offset + (int)size > span.Length)
                {
                    return false;
                }

                ReadOnlySpan<byte> data = span.Slice(offset, (int)size);
                offset += (int)size;

                if (propId == 0x11)
                {
                    ParseSevenZipNames(data, fileCount, names);
                }
                else if (propId == 0x14)
                {
                    ReadSevenZipBoolVector(data, fileCount, emptyStreams);
                }
                else if (propId == 0x15)
                {
                    ReadSevenZipBoolVector(data, fileCount, emptyFiles);
                }
            }

            List<OverlayContainerEntry> results = new List<OverlayContainerEntry>();
            int maxEntries = Math.Min(fileCount, 200);
            for (int i = 0; i < maxEntries; i++)
            {
                string name = string.IsNullOrWhiteSpace(names[i]) ? $"file-{i}" : names[i];
                bool isDirectory = emptyStreams[i] && !emptyFiles[i];
                results.Add(new OverlayContainerEntry(
                    name,
                    0,
                    0,
                    string.Empty,
                    0,
                    isDirectory,
                    string.Empty));
            }

            if (fileCount > maxEntries)
            {
                truncated = true;
            }

            entries = results.ToArray();
            notes = $"Files={fileCount}";
            return true;
        }

        private static bool TryParseSevenZipHeader(ReadOnlySpan<byte> span, out OverlayContainerEntry[] entries, out bool truncated, out string notes)
        {
            entries = Array.Empty<OverlayContainerEntry>();
            truncated = false;
            notes = string.Empty;
            if (span.Length == 0)
            {
                notes = "Empty header";
                return false;
            }

            int offset = 0;
            byte id = ReadByte(span, ref offset);
            if (id == 0x17)
            {
                notes = "EncodedHeader";
                return false;
            }

            if (id != 0x01)
            {
                notes = "Unknown header";
                return false;
            }

            List<OverlayContainerEntry> parsedEntries = new List<OverlayContainerEntry>();
            bool parsedFiles = false;
            while (offset < span.Length)
            {
                byte sectionId = ReadByte(span, ref offset);
                if (sectionId == 0x00)
                {
                    break;
                }

                if (sectionId == 0x05)
                {
                    if (TryParseSevenZipFilesInfo(span, ref offset, out OverlayContainerEntry[] fileEntries, out bool filesTruncated, out string fileNotes))
                    {
                        parsedEntries.AddRange(fileEntries);
                        truncated |= filesTruncated;
                        notes = AppendNote(notes, fileNotes);
                        parsedFiles = true;
                    }
                    else
                    {
                        notes = AppendNote(notes, "FilesInfo parse failed");
                    }
                }
                else if (sectionId == 0x02)
                {
                    SkipSevenZipArchiveProperties(span, ref offset);
                }
                else if (sectionId == 0x03 || sectionId == 0x04)
                {
                    if (!SkipSevenZipStreamsInfo(span, ref offset))
                    {
                        notes = AppendNote(notes, "StreamsInfo parse failed");
                        break;
                    }
                }
                else
                {
                    notes = AppendNote(notes, "Unknown header section");
                    break;
                }
            }

            if (!parsedFiles)
            {
                notes = AppendNote(notes, "FilesInfo not found");
            }

            entries = parsedEntries.ToArray();
            return true;
        }

        private static bool TryDecodeSevenZipEncodedHeader(Stream stream, long archiveStart, ulong nextHeaderOffset, ulong nextHeaderSize, ReadOnlySpan<byte> span, out byte[] decodedHeader, out string notes)
        {
            decodedHeader = Array.Empty<byte>();
            notes = string.Empty;
            if (span.Length == 0 || span[0] != 0x17)
            {
                notes = "Not an encoded header";
                return false;
            }

            int offset = 1;
            if (!TryParseSevenZipStreamsInfoForEncodedHeader(span, ref offset, out ulong packPos, out ulong packSize, out ulong unpackSize, out byte[] methodId, out byte[] properties))
            {
                notes = "EncodedHeader StreamsInfo parse failed";
                return false;
            }

            string methodName = GetSevenZipMethodName(methodId);
            if (packSize == 0 || packSize > int.MaxValue)
            {
                notes = "EncodedHeader pack size unsupported";
                return false;
            }

            long headerOffset = archiveStart + 32 + (long)nextHeaderOffset;
            long dataOffset = headerOffset + (long)nextHeaderSize + (long)packPos;
            if (!TrySetPosition(stream, dataOffset, (int)packSize))
            {
                notes = "EncodedHeader data offset invalid";
                return false;
            }

            byte[] packed = new byte[(int)packSize];
            ReadExactly(stream, packed, 0, packed.Length);

            if (methodId.Length == 1 && methodId[0] == 0x00)
            {
                decodedHeader = packed;
                notes = string.Format(
                    CultureInfo.InvariantCulture,
                    "EncodedHeader decoded via copy (pack={0}, unpack={1})",
                    packSize,
                    unpackSize);
                return true;
            }

            if (methodId.Length == 3 && methodId[0] == 0x03 && methodId[1] == 0x01 && methodId[2] == 0x01)
            {
                if (SevenZipLzmaDecoder.TryDecodeLzma(packed, properties, unpackSize, out decodedHeader))
                {
                    notes = string.Format(
                        CultureInfo.InvariantCulture,
                        "EncodedHeader decoded via {0} (pack={1}, unpack={2})",
                        methodName,
                        packSize,
                        unpackSize);
                    return true;
                }

                notes = "EncodedHeader LZMA decode failed";
                return false;
            }

            if (methodId.Length == 1 && methodId[0] == 0x21)
            {
                if (SevenZipLzmaDecoder.TryDecodeLzma2(packed, properties, unpackSize, out decodedHeader))
                {
                    notes = string.Format(
                        CultureInfo.InvariantCulture,
                        "EncodedHeader decoded via {0} (pack={1}, unpack={2})",
                        methodName,
                        packSize,
                        unpackSize);
                    return true;
                }

                notes = "EncodedHeader LZMA2 decode failed";
                return false;
            }

            notes = "EncodedHeader method unsupported: " + methodName;
            return false;
        }

        private static bool TryParseSevenZipStreamsInfoForEncodedHeader(ReadOnlySpan<byte> span, ref int offset, out ulong packPos, out ulong packSize, out ulong unpackSize, out byte[] methodId, out byte[] properties)
        {
            packPos = 0;
            packSize = 0;
            unpackSize = 0;
            methodId = Array.Empty<byte>();
            properties = Array.Empty<byte>();

            bool hasPackInfo = false;
            bool hasUnpackInfo = false;
            while (offset < span.Length)
            {
                byte id = ReadByte(span, ref offset);
                if (id == 0x00)
                {
                    return hasPackInfo && hasUnpackInfo;
                }

                if (id == 0x06)
                {
                    if (!TryRead7zUInt64(span, ref offset, out packPos) ||
                        !TryRead7zUInt64(span, ref offset, out ulong numPack) ||
                        numPack == 0)
                    {
                        return false;
                    }

                    byte sizesId = ReadByte(span, ref offset);
                    if (sizesId != 0x09)
                    {
                        return false;
                    }

                    if (!TryRead7zUInt64(span, ref offset, out packSize))
                    {
                        return false;
                    }

                    if (numPack > 1)
                    {
                        for (ulong i = 1; i < numPack; i++)
                        {
                            if (!TryRead7zUInt64(span, ref offset, out _))
                            {
                                return false;
                            }
                        }
                    }

                    byte next = ReadByte(span, ref offset);
                    if (next == 0x0A)
                    {
                        if (!SkipSevenZipCrc(span, ref offset, numPack))
                        {
                            return false;
                        }

                        next = ReadByte(span, ref offset);
                    }

                    if (next != 0x00)
                    {
                        return false;
                    }

                    hasPackInfo = true;
                }
                else if (id == 0x07)
                {
                    byte folderId = ReadByte(span, ref offset);
                    if (folderId != 0x0B)
                    {
                        return false;
                    }

                    if (!TryRead7zUInt64(span, ref offset, out ulong numFolders) || numFolders != 1)
                    {
                        return false;
                    }

                    if (offset >= span.Length || ReadByte(span, ref offset) != 0x00)
                    {
                        return false;
                    }

                    if (!TryRead7zUInt64(span, ref offset, out ulong numCoders) || numCoders != 1)
                    {
                        return false;
                    }

                    byte coderFlags = ReadByte(span, ref offset);
                    int idSize = coderFlags & 0x0F;
                    if (idSize <= 0 || offset + idSize > span.Length)
                    {
                        return false;
                    }

                    methodId = span.Slice(offset, idSize).ToArray();
                    offset += idSize;

                    if ((coderFlags & 0x10) != 0)
                    {
                        if (!TryRead7zUInt64(span, ref offset, out _) || !TryRead7zUInt64(span, ref offset, out _))
                        {
                            return false;
                        }
                    }

                    if ((coderFlags & 0x20) != 0)
                    {
                        if (!TryRead7zUInt64(span, ref offset, out ulong propsSize) || propsSize > (ulong)(span.Length - offset))
                        {
                            return false;
                        }

                        properties = span.Slice(offset, (int)propsSize).ToArray();
                        offset += (int)propsSize;
                    }

                    byte unpackId = ReadByte(span, ref offset);
                    if (unpackId != 0x0C)
                    {
                        return false;
                    }

                    if (!TryRead7zUInt64(span, ref offset, out unpackSize))
                    {
                        return false;
                    }

                    byte next = ReadByte(span, ref offset);
                    if (next == 0x0A)
                    {
                        if (!SkipSevenZipCrc(span, ref offset, 1))
                        {
                            return false;
                        }

                        next = ReadByte(span, ref offset);
                    }

                    if (next != 0x00)
                    {
                        return false;
                    }

                    hasUnpackInfo = true;
                }
                else if (id == 0x08)
                {
                    if (!SkipSevenZipSubStreamsInfo(span, ref offset))
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }

            return false;
        }

        private static string GetSevenZipMethodName(byte[] methodId)
        {
            if (methodId == null || methodId.Length == 0)
            {
                return string.Empty;
            }

            if (methodId.Length == 1 && methodId[0] == 0x00)
            {
                return "Copy";
            }

            if (methodId.Length == 3 && methodId[0] == 0x03 && methodId[1] == 0x01 && methodId[2] == 0x01)
            {
                return "LZMA";
            }

            if (methodId.Length == 1 && methodId[0] == 0x21)
            {
                return "LZMA2";
            }

            return "Method_" + ToHex(methodId);
        }

        private static void ParseSevenZipNames(ReadOnlySpan<byte> data, int fileCount, string[] names)
        {
            if (data.Length < 2 || names == null)
            {
                return;
            }

            int offset = 0;
            byte external = data[offset++];
            if (external != 0)
            {
                return;
            }

            for (int i = 0; i < fileCount && offset + 1 < data.Length; i++)
            {
                int start = offset;
                while (offset + 1 < data.Length)
                {
                    if (data[offset] == 0 && data[offset + 1] == 0)
                    {
                        break;
                    }

                    offset += 2;
                }

                if (offset > start)
                {
                    names[i] = Encoding.Unicode.GetString(data.Slice(start, offset - start));
                }

                offset += 2;
            }
        }

        private static void ReadSevenZipBoolVector(ReadOnlySpan<byte> data, int count, bool[] target)
        {
            if (target == null || count == 0 || data.Length == 0)
            {
                return;
            }

            int needed = (count + 7) / 8;
            int offset = 0;
            bool allDefined = false;
            if (data.Length == needed + 1 && (data[0] == 0 || data[0] == 1))
            {
                allDefined = data[0] == 1;
                offset = 1;
            }

            if (allDefined)
            {
                for (int i = 0; i < count; i++)
                {
                    target[i] = true;
                }
                return;
            }

            for (int i = 0; i < count; i++)
            {
                int byteIndex = i / 8;
                int bitIndex = i % 8;
                if (offset + byteIndex >= data.Length)
                {
                    return;
                }

                int mask = 0x80 >> bitIndex;
                target[i] = (data[offset + byteIndex] & mask) != 0;
            }
        }

        private static void SkipSevenZipArchiveProperties(ReadOnlySpan<byte> span, ref int offset)
        {
            while (offset < span.Length)
            {
                byte propId = ReadByte(span, ref offset);
                if (propId == 0x00)
                {
                    return;
                }

                if (!TryRead7zUInt64(span, ref offset, out ulong size))
                {
                    return;
                }

                offset += (int)Math.Min(size, (ulong)(span.Length - offset));
            }
        }

        private static bool SkipSevenZipStreamsInfo(ReadOnlySpan<byte> span, ref int offset)
        {
            while (offset < span.Length)
            {
                byte id = ReadByte(span, ref offset);
                if (id == 0x00)
                {
                    return true;
                }

                if (id == 0x06)
                {
                    if (!TryRead7zUInt64(span, ref offset, out ulong _) ||
                        !TryRead7zUInt64(span, ref offset, out ulong numPack) ||
                        !SkipSevenZipPackInfo(span, ref offset, numPack))
                    {
                        return false;
                    }
                }
                else if (id == 0x07)
                {
                    if (!SkipSevenZipUnpackInfo(span, ref offset))
                    {
                        return false;
                    }
                }
                else if (id == 0x08)
                {
                    if (!SkipSevenZipSubStreamsInfo(span, ref offset))
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }

            return false;
        }

        private static bool SkipSevenZipPackInfo(ReadOnlySpan<byte> span, ref int offset, ulong numPackStreams)
        {
            byte id = ReadByte(span, ref offset);
            if (id != 0x09)
            {
                return false;
            }

            for (ulong i = 0; i < numPackStreams; i++)
            {
                if (!TryRead7zUInt64(span, ref offset, out _))
                {
                    return false;
                }
            }

            id = ReadByte(span, ref offset);
            if (id == 0x0A)
            {
                if (!SkipSevenZipCrc(span, ref offset, numPackStreams))
                {
                    return false;
                }

                id = ReadByte(span, ref offset);
            }

            return id == 0x00;
        }

        private static bool SkipSevenZipUnpackInfo(ReadOnlySpan<byte> span, ref int offset)
        {
            byte id = ReadByte(span, ref offset);
            if (id != 0x0B)
            {
                return false;
            }

            if (!TryRead7zUInt64(span, ref offset, out ulong numFolders))
            {
                return false;
            }

            if (offset >= span.Length)
            {
                return false;
            }

            byte external = ReadByte(span, ref offset);
            if (external != 0)
            {
                return false;
            }

            for (ulong i = 0; i < numFolders; i++)
            {
                if (!SkipSevenZipFolder(span, ref offset))
                {
                    return false;
                }
            }

            id = ReadByte(span, ref offset);
            if (id != 0x0C)
            {
                return false;
            }

            for (ulong i = 0; i < numFolders; i++)
            {
                if (!TryRead7zUInt64(span, ref offset, out _))
                {
                    return false;
                }
            }

            id = ReadByte(span, ref offset);
            if (id == 0x0A)
            {
                if (!SkipSevenZipCrc(span, ref offset, numFolders))
                {
                    return false;
                }

                id = ReadByte(span, ref offset);
            }

            return id == 0x00;
        }

        private static bool SkipSevenZipSubStreamsInfo(ReadOnlySpan<byte> span, ref int offset)
        {
            while (offset < span.Length)
            {
                byte id = ReadByte(span, ref offset);
                if (id == 0x00)
                {
                    return true;
                }

                if (id == 0x0D || id == 0x0E)
                {
                    if (!TryRead7zUInt64(span, ref offset, out ulong num) || num > int.MaxValue)
                    {
                        return false;
                    }

                    for (int i = 0; i < (int)num; i++)
                    {
                        if (!TryRead7zUInt64(span, ref offset, out _))
                        {
                            return false;
                        }
                    }
                }
                else if (id == 0x0A)
                {
                    if (!TryRead7zUInt64(span, ref offset, out ulong num) || num > int.MaxValue)
                    {
                        return false;
                    }

                    if (!SkipSevenZipCrc(span, ref offset, num))
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }

            return false;
        }

        private static bool SkipSevenZipFolder(ReadOnlySpan<byte> span, ref int offset)
        {
            if (!TryRead7zUInt64(span, ref offset, out ulong numCoders) || numCoders > 64)
            {
                return false;
            }

            ulong totalIn = 0;
            ulong totalOut = 0;
            for (ulong i = 0; i < numCoders; i++)
            {
                if (offset >= span.Length)
                {
                    return false;
                }

                byte coderFlags = ReadByte(span, ref offset);
                int idSize = coderFlags & 0x0F;
                if (offset + idSize > span.Length)
                {
                    return false;
                }

                offset += idSize;
                ulong inStreams = 1;
                ulong outStreams = 1;
                if ((coderFlags & 0x10) != 0)
                {
                    if (!TryRead7zUInt64(span, ref offset, out inStreams) ||
                        !TryRead7zUInt64(span, ref offset, out outStreams))
                    {
                        return false;
                    }
                }

                totalIn += inStreams;
                totalOut += outStreams;

                if ((coderFlags & 0x20) != 0)
                {
                    if (!TryRead7zUInt64(span, ref offset, out ulong propsSize) || propsSize > (ulong)(span.Length - offset))
                    {
                        return false;
                    }

                    offset += (int)propsSize;
                }
            }

            if (!TryRead7zUInt64(span, ref offset, out ulong bindPairs))
            {
                return false;
            }

            for (ulong i = 0; i < bindPairs; i++)
            {
                if (!TryRead7zUInt64(span, ref offset, out _) || !TryRead7zUInt64(span, ref offset, out _))
                {
                    return false;
                }
            }

            ulong numPackedStreams = totalOut > bindPairs ? totalOut - bindPairs : 0;
            for (ulong i = 0; i < numPackedStreams; i++)
            {
                if (!TryRead7zUInt64(span, ref offset, out _))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool SkipSevenZipCrc(ReadOnlySpan<byte> span, ref int offset, ulong count)
        {
            if (count == 0)
            {
                return true;
            }

            if (offset >= span.Length)
            {
                return false;
            }

            bool allDefined = ReadByte(span, ref offset) != 0;
            if (!allDefined)
            {
                int needed = (int)((count + 7) / 8);
                offset += Math.Min(needed, span.Length - offset);
            }

            int crcBytes = allDefined ? (int)Math.Min(count * 4, (ulong)(span.Length - offset)) : 0;
            offset += crcBytes;
            return true;
        }

        private static byte ReadByte(ReadOnlySpan<byte> span, ref int offset)
        {
            if (offset >= span.Length)
            {
                return 0;
            }

            return span[offset++];
        }

        private static bool TryRead7zUInt64(ReadOnlySpan<byte> span, ref int offset, out ulong value)
        {
            value = 0;
            if (offset >= span.Length)
            {
                return false;
            }

            byte first = span[offset++];
            int mask = 0x80;
            int extra = 0;
            while ((first & mask) != 0)
            {
                extra++;
                mask >>= 1;
            }

            if (extra == 0)
            {
                value = first;
                return true;
            }

            if (extra > 8 || offset + extra > span.Length)
            {
                return false;
            }

            int lowBits = 7 - extra;
            ulong result = (ulong)(first & ((1 << lowBits) - 1));
            for (int i = 0; i < extra; i++)
            {
                result |= ((ulong)span[offset++]) << (lowBits + (8 * i));
            }

            value = result;
            return true;
        }

        private static bool TryReadRar5Vint(ReadOnlySpan<byte> data, ref int offset, out ulong value)
        {
            value = 0;
            int shift = 0;
            int start = offset;
            while (offset < data.Length && shift < 64)
            {
                byte b = data[offset++];
                value |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                {
                    return true;
                }

                shift += 7;
            }

            offset = start;
            value = 0;
            return false;
        }

        private static bool TryParseRar4FileHeader(byte[] data, ushort flags, out OverlayContainerEntry entry)
        {
            entry = null;
            if (data == null || data.Length < 25)
            {
                return false;
            }

            uint packSize = ReadUInt32(data, 0);
            uint unpSize = ReadUInt32(data, 4);
            byte method = data[15];
            ushort nameSize = ReadUInt16(data, 16);
            int offset = 18;
            ulong packHigh = 0;
            ulong unpHigh = 0;
            if ((flags & 0x0100) != 0 && data.Length >= 25 + 8)
            {
                packHigh = ReadUInt32(data, 25);
                unpHigh = ReadUInt32(data, 29);
                offset = 33;
            }

            if (offset + nameSize > data.Length)
            {
                return false;
            }

            string name = Encoding.ASCII.GetString(data, offset, nameSize);
            ulong packed = packSize + (packHigh << 32);
            ulong unpacked = unpSize + (unpHigh << 32);
            string methodName = GetRarMethodName(method);
            bool isDirectory = name.EndsWith("/", StringComparison.Ordinal) || name.EndsWith("\\", StringComparison.Ordinal);
            entry = new OverlayContainerEntry(
                name,
                (long)Math.Min(packed, (ulong)long.MaxValue),
                (long)Math.Min(unpacked, (ulong)long.MaxValue),
                methodName,
                flags,
                isDirectory,
                string.Empty);
            return true;
        }

        private static string GetRarMethodName(byte method)
        {
            switch (method)
            {
                case 0x30: return "Store";
                case 0x31: return "Fastest";
                case 0x32: return "Fast";
                case 0x33: return "Normal";
                case 0x34: return "Good";
                case 0x35: return "Best";
                default: return "Method_" + method.ToString("X2", CultureInfo.InvariantCulture);
            }
        }

        private static bool TryReadZipCentralDirectoryEntry(Stream stream, out OverlayContainerEntry entry)
        {
            entry = null;
            byte[] header = new byte[46];
            if (!ReadExactlyOrFail(stream, header))
            {
                return false;
            }

            uint signature = ReadUInt32(header, 0);
            if (signature != 0x02014B50)
            {
                return false;
            }

            ushort flags = ReadUInt16(header, 8);
            ushort method = ReadUInt16(header, 10);
            uint compressedSize = ReadUInt32(header, 20);
            uint uncompressedSize = ReadUInt32(header, 24);
            ushort nameLength = ReadUInt16(header, 28);
            ushort extraLength = ReadUInt16(header, 30);
            ushort commentLength = ReadUInt16(header, 32);

            byte[] nameBytes = new byte[nameLength];
            if (nameLength > 0 && !ReadExactlyOrFail(stream, nameBytes))
            {
                return false;
            }

            string name = nameLength > 0 ? Encoding.UTF8.GetString(nameBytes) : string.Empty;
            if (extraLength > 0 && !SkipBytes(stream, extraLength))
            {
                return false;
            }

            if (commentLength > 0 && !SkipBytes(stream, commentLength))
            {
                return false;
            }

            string methodName = GetZipCompressionMethodName(method);
            bool isDirectory = name.EndsWith("/", StringComparison.Ordinal);
            string notes = string.Empty;
            if (compressedSize == 0xFFFFFFFF || uncompressedSize == 0xFFFFFFFF)
            {
                notes = "Zip64 sizes present";
            }

            entry = new OverlayContainerEntry(
                name,
                compressedSize,
                uncompressedSize,
                methodName,
                flags,
                isDirectory,
                notes);
            return true;
        }

        private static string GetZipCompressionMethodName(ushort method)
        {
            switch (method)
            {
                case 0: return "Stored";
                case 8: return "Deflate";
                case 9: return "Deflate64";
                case 12: return "BZip2";
                case 14: return "LZMA";
                default: return "Method_" + method.ToString(CultureInfo.InvariantCulture);
            }
        }

        private static int FindZipEocd(byte[] data)
        {
            if (data == null || data.Length < 22)
            {
                return -1;
            }

            for (int i = data.Length - 22; i >= 0; i--)
            {
                if (data[i] == 0x50 && data[i + 1] == 0x4B && data[i + 2] == 0x05 && data[i + 3] == 0x06)
                {
                    return i;
                }
            }

            return -1;
        }

        private static int IndexOfSignature(ReadOnlySpan<byte> data, byte[] signature)
        {
            if (signature == null || signature.Length == 0 || data.Length < signature.Length)
            {
                return -1;
            }

            for (int i = 0; i <= data.Length - signature.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < signature.Length; j++)
                {
                    if (data[i + j] != signature[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    return i;
                }
            }

            return -1;
        }

        private static bool TrySetPosition(Stream stream, long offset, int size)
        {
            if (offset < 0 || size < 0)
            {
                return false;
            }

            if (stream.Length - offset < size)
            {
                return false;
            }

            stream.Position = offset;
            return true;
        }

        private static bool ReadExactlyOrFail(Stream stream, byte[] buffer)
        {
            try
            {
                ReadExactly(stream, buffer, 0, buffer.Length);
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }

        private static bool SkipBytes(Stream stream, int bytes)
        {
            if (bytes <= 0)
            {
                return true;
            }

            if (stream.CanSeek)
            {
                if (stream.Length - stream.Position < bytes)
                {
                    return false;
                }

                stream.Position += bytes;
                return true;
            }

            byte[] buffer = new byte[Math.Min(bytes, 4096)];
            int remaining = bytes;
            while (remaining > 0)
            {
                int read = stream.Read(buffer, 0, Math.Min(buffer.Length, remaining));
                if (read <= 0)
                {
                    return false;
                }

                remaining -= read;
            }

            return true;
        }

        private static bool IsLzmaHeader(ReadOnlySpan<byte> data)
        {
            return data.Length >= 5 &&
                   data[0] == 0x5D &&
                   data[1] == 0x00 &&
                   data[2] == 0x00 &&
                   data[3] == 0x80 &&
                   data[4] == 0x00;
        }

        private static bool HasPrefix(ReadOnlySpan<byte> data, byte[] signature)
        {
            if (signature == null || data.Length < signature.Length)
            {
                return false;
            }

            for (int i = 0; i < signature.Length; i++)
            {
                if (data[i] != signature[i])
                {
                    return false;
                }
            }

            return true;
        }

        private static bool ContainsAscii(ReadOnlySpan<byte> data, string text, int maxScan)
        {
            if (string.IsNullOrEmpty(text) || data.Length == 0)
            {
                return false;
            }

            int limit = Math.Min(data.Length, Math.Max(0, maxScan));
            byte[] needle = Encoding.ASCII.GetBytes(text);
            if (needle.Length == 0 || limit < needle.Length)
            {
                return false;
            }

            for (int i = 0; i <= limit - needle.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (data[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    return true;
                }
            }

            return false;
        }

        private static double ComputeShannonEntropy(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                return 0;
            }

            Span<int> counts = stackalloc int[256];
            for (int i = 0; i < data.Length; i++)
            {
                counts[data[i]]++;
            }

            double entropy = 0;
            double length = data.Length;
            for (int i = 0; i < counts.Length; i++)
            {
                int count = counts[i];
                if (count == 0)
                {
                    continue;
                }

                double p = count / length;
                entropy -= p * Math.Log(p, 2.0);
            }

            return entropy;
        }

        private void ComputeSecurityFeatures(bool isPe32Plus)
        {
            if (_dllCharacteristicsInfo == null)
            {
                _securityFeaturesInfo = null;
                return;
            }

            bool noSeh = false;
            bool hasSeHandlerTable = false;
            if (_loadConfig != null && !isPe32Plus)
            {
                hasSeHandlerTable = _loadConfig.SeHandlerTable != 0 && _loadConfig.SeHandlerCount > 0;
            }
            noSeh = (_dllCharacteristicsInfo.Value & (ushort)DllCharacteristics.IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0;

            bool safeSeh = hasSeHandlerTable && !noSeh;
            bool hasSecurityCookie = _loadConfig != null && _loadConfig.SecurityCookie != 0;
            bool guardCf = _dllCharacteristicsInfo.GuardCf || (_loadConfig != null && _loadConfig.GuardFlags != 0);

            _securityFeaturesInfo = new SecurityFeaturesInfo(
                _dllCharacteristicsInfo.NxCompat,
                _dllCharacteristicsInfo.AslrEnabled,
                _dllCharacteristicsInfo.HighEntropyVa,
                guardCf,
                hasSecurityCookie,
                hasSeHandlerTable,
                safeSeh,
                noSeh);
        }

        private string ComputeAuthenticodeHash(HashAlgorithmName algorithm, long checksumOffset, long certTableOffset, long certTableSize)
        {
            if (PEFileStream == null || !PEFileStream.CanRead || !PEFileStream.CanSeek)
            {
                return string.Empty;
            }

            if (!TryCreateHashAlgorithm(algorithm, out HashAlgorithm hashAlgorithm))
            {
                return string.Empty;
            }

            long fileLength = PEFileStream.Length;
            if (fileLength <= 0)
            {
                hashAlgorithm.Dispose();
                return string.Empty;
            }

            long checksumStart = checksumOffset;
            long checksumEnd = checksumOffset + 4;
            long certStart = certTableOffset;
            long certEnd = certTableOffset + certTableSize;

            List<(long Start, long End, SegmentKind Kind)> segments = BuildAuthenticodeSegments(fileLength, checksumStart, checksumEnd, certStart, certEnd);

            long originalPosition = PEFileStream.Position;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                foreach ((long start, long end, SegmentKind kind) in segments)
                {
                    if (end <= start)
                    {
                        continue;
                    }

                    if (kind == SegmentKind.Skip)
                    {
                        continue;
                    }

                    if (kind == SegmentKind.Zero)
                    {
                        byte[] zeros = new byte[4];
                        hashAlgorithm.TransformBlock(zeros, 0, zeros.Length, null, 0);
                        continue;
                    }

                    long remaining = end - start;
                    PEFileStream.Position = start;
                    while (remaining > 0)
                    {
                        int toRead = remaining > buffer.Length ? buffer.Length : (int)remaining;
                        int read = PEFileStream.Read(buffer, 0, toRead);
                        if (read <= 0)
                        {
                            break;
                        }
                        hashAlgorithm.TransformBlock(buffer, 0, read, null, 0);
                        remaining -= read;
                    }
                }

                hashAlgorithm.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                byte[] hash = hashAlgorithm.Hash ?? Array.Empty<byte>();
                return ToHex(hash);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                PEFileStream.Position = originalPosition;
                hashAlgorithm.Dispose();
            }
        }

        private static bool TryCreateHashAlgorithm(HashAlgorithmName name, out HashAlgorithm algorithm)
        {
            algorithm = null;
            if (name == HashAlgorithmName.SHA1)
            {
                algorithm = SHA1.Create();
                return true;
            }

            if (name == HashAlgorithmName.SHA256)
            {
                algorithm = SHA256.Create();
                return true;
            }

            if (name == HashAlgorithmName.SHA384)
            {
                algorithm = SHA384.Create();
                return true;
            }

            if (name == HashAlgorithmName.SHA512)
            {
                algorithm = SHA512.Create();
                return true;
            }

            return false;
        }

        private enum SegmentKind
        {
            Data,
            Zero,
            Skip
        }

        private static List<(long Start, long End, SegmentKind Kind)> BuildAuthenticodeSegments(
            long fileLength,
            long checksumStart,
            long checksumEnd,
            long certStart,
            long certEnd)
        {
            List<long> points = new List<long> { 0, fileLength };

            if (checksumStart >= 0 && checksumEnd > checksumStart && checksumEnd <= fileLength)
            {
                points.Add(checksumStart);
                points.Add(checksumEnd);
            }

            if (certStart > 0 && certEnd > certStart && certEnd <= fileLength)
            {
                points.Add(certStart);
                points.Add(certEnd);
            }

            points.Sort();
            List<(long Start, long End, SegmentKind Kind)> segments = new List<(long, long, SegmentKind)>();
            for (int i = 0; i < points.Count - 1; i++)
            {
                long start = points[i];
                long end = points[i + 1];
                if (end <= start)
                {
                    continue;
                }

                if (certStart > 0 && start >= certStart && end <= certEnd && certEnd > certStart)
                {
                    segments.Add((start, end, SegmentKind.Skip));
                }
                else if (start >= checksumStart && end <= checksumEnd && checksumEnd > checksumStart)
                {
                    segments.Add((start, end, SegmentKind.Zero));
                }
                else
                {
                    segments.Add((start, end, SegmentKind.Data));
                }
            }

            return segments;
        }

        private static ushort ReadUInt16(byte[] buffer, int offset)
        {
            if (offset + 1 >= buffer.Length)
            {
                return 0;
            }

            return (ushort)(buffer[offset] | (buffer[offset + 1] << 8));
        }

        private static ushort ReadUInt16(ReadOnlySpan<byte> buffer, int offset)
        {
            if (offset + 1 >= buffer.Length)
            {
                return 0;
            }

            return (ushort)(buffer[offset] | (buffer[offset + 1] << 8));
        }

        private static uint ReadUInt32(byte[] buffer, int offset)
        {
            if (offset + 3 >= buffer.Length)
            {
                return 0;
            }

            return (uint)(buffer[offset] |
                          (buffer[offset + 1] << 8) |
                          (buffer[offset + 2] << 16) |
                          (buffer[offset + 3] << 24));
        }

        private static uint ReadUInt32(ReadOnlySpan<byte> buffer, int offset)
        {
            if (offset + 3 >= buffer.Length)
            {
                return 0;
            }

            return (uint)(buffer[offset] |
                          (buffer[offset + 1] << 8) |
                          (buffer[offset + 2] << 16) |
                          (buffer[offset + 3] << 24));
        }

        private static int ReadInt32(ReadOnlySpan<byte> buffer, int offset)
        {
            return unchecked((int)ReadUInt32(buffer, offset));
        }

        private static bool TryParseArchitectureHeader(
            ReadOnlySpan<byte> data,
            out uint magic,
            out uint majorVersion,
            out uint minorVersion,
            out uint sizeOfData,
            out uint firstEntryRva,
            out uint numberOfEntries)
        {
            magic = 0;
            majorVersion = 0;
            minorVersion = 0;
            sizeOfData = 0;
            firstEntryRva = 0;
            numberOfEntries = 0;

            if (data.Length < 24)
            {
                return false;
            }

            magic = ReadUInt32(data, 0);
            majorVersion = ReadUInt32(data, 4);
            minorVersion = ReadUInt32(data, 8);
            sizeOfData = ReadUInt32(data, 12);
            firstEntryRva = ReadUInt32(data, 16);
            numberOfEntries = ReadUInt32(data, 20);
            return true;
        }

        private void CountIatEntries(long fileOffset, uint size, uint entrySize, out uint nonZeroCount, out uint zeroCount)
        {
            nonZeroCount = 0;
            zeroCount = 0;

            if (PEFileStream == null || entrySize == 0 || size == 0)
            {
                return;
            }

            long fileLength = PEFileStream.Length;
            if (fileOffset < 0 || fileOffset >= fileLength)
            {
                return;
            }

            uint alignedSize = size - (size % entrySize);
            if (alignedSize == 0)
            {
                return;
            }

            long remaining = Math.Min(alignedSize, (uint)Math.Min(long.MaxValue, fileLength - fileOffset));
            long originalPosition = PEFileStream.CanSeek ? PEFileStream.Position : 0;
            try
            {
                byte[] buffer = new byte[8192];
                long offset = fileOffset;
                while (remaining > 0)
                {
                    int toRead = (int)Math.Min(buffer.Length, remaining);
                    if (!TrySetPosition(offset, toRead))
                    {
                        break;
                    }

                    ReadExactly(PEFileStream, buffer, 0, toRead);
                    int local = 0;
                    while (local + entrySize <= toRead)
                    {
                        ulong value = entrySize == 8
                            ? BitConverter.ToUInt64(buffer, local)
                            : BitConverter.ToUInt32(buffer, local);
                        if (value == 0)
                        {
                            zeroCount++;
                        }
                        else
                        {
                            nonZeroCount++;
                        }
                        local += (int)entrySize;
                    }

                    offset += toRead;
                    remaining -= toRead;
                }
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private void ReadIatSamples(
            long fileOffset,
            uint size,
            uint entrySize,
            List<IMAGE_SECTION_HEADER> sections,
            out List<IatEntryInfo> samples,
            out uint sampleCount,
            out bool samplesTruncated,
            out uint mappedCount)
        {
            samples = new List<IatEntryInfo>();
            sampleCount = 0;
            mappedCount = 0;
            samplesTruncated = false;

            if (PEFileStream == null || entrySize == 0 || size == 0)
            {
                return;
            }

            long fileLength = PEFileStream.Length;
            if (fileOffset < 0 || fileOffset >= fileLength)
            {
                return;
            }

            uint alignedSize = size - (size % entrySize);
            if (alignedSize == 0)
            {
                return;
            }

            uint availableEntries = alignedSize / entrySize;
            int maxSamples = 16;
            samplesTruncated = availableEntries > maxSamples;
            int readCount = (int)Math.Min(availableEntries, (uint)maxSamples);
            int toRead = readCount * (int)entrySize;
            if (!TrySetPosition(fileOffset, toRead))
            {
                return;
            }

            byte[] buffer = new byte[toRead];
            ReadExactly(PEFileStream, buffer, 0, buffer.Length);
            int offset = 0;
            for (int i = 0; i < readCount; i++)
            {
                ulong value = entrySize == 8
                    ? BitConverter.ToUInt64(buffer, offset)
                    : BitConverter.ToUInt32(buffer, offset);
                offset += (int)entrySize;

                bool isZero = value == 0;
                bool hasRva = false;
                uint rva = 0;
                string rvaKind = string.Empty;
                bool mapped = false;
                string sectionName = string.Empty;

                if (!isZero && TryComputeRvaFromPointer(value, _imageBase, _sizeOfImage, out rva, out rvaKind))
                {
                    hasRva = true;
                    if (TryGetSectionByRva(sections, rva, out IMAGE_SECTION_HEADER section))
                    {
                        mapped = true;
                        sectionName = NormalizeSectionName(section);
                        mappedCount++;
                    }
                }

                samples.Add(new IatEntryInfo((uint)i, value, isZero, hasRva, rva, rvaKind, mapped, sectionName));
                sampleCount++;
            }
        }

        private static ulong ReadUInt64(ReadOnlySpan<byte> buffer, int offset)
        {
            if (offset + 7 >= buffer.Length)
            {
                return 0;
            }

            uint lo = ReadUInt32(buffer, offset);
            uint hi = ReadUInt32(buffer, offset + 4);
            return ((ulong)hi << 32) | lo;
        }

        private static string ReadAsciiString(byte[] buffer, int offset, int length)
        {
            if (length <= 0 || offset >= buffer.Length)
            {
                return string.Empty;
            }

            int safeLength = Math.Min(length, buffer.Length - offset);
            return Encoding.ASCII.GetString(buffer, offset, safeLength).TrimEnd('\0', ' ');
        }

        private static string ReadNullTerminatedAscii(byte[] buffer, int offset, out int bytesRead)
        {
            int start = offset;
            while (offset < buffer.Length && buffer[offset] != 0)
            {
                offset++;
            }

            bytesRead = offset - start + 1;
            if (start >= buffer.Length)
            {
                return string.Empty;
            }

            int length = Math.Min(offset - start, buffer.Length - start);
            return Encoding.ASCII.GetString(buffer, start, length);
        }

        private static string ReadNullTerminatedLatin1(byte[] buffer, int offset, out int bytesRead)
        {
            int start = offset;
            while (offset < buffer.Length && buffer[offset] != 0)
            {
                offset++;
            }

            bytesRead = offset - start + 1;
            if (start >= buffer.Length)
            {
                return string.Empty;
            }

            int length = Math.Min(offset - start, buffer.Length - start);
            return Encoding.Latin1.GetString(buffer, start, length);
        }

        private static string ReadNullTerminatedAscii(ReadOnlySpan<byte> buffer, int offset, out int bytesRead)
        {
            int start = offset;
            while (offset < buffer.Length && buffer[offset] != 0)
            {
                offset++;
            }

            bytesRead = offset - start + 1;
            if (start >= buffer.Length)
            {
                return string.Empty;
            }

            int length = Math.Min(offset - start, buffer.Length - start);
            return Encoding.ASCII.GetString(buffer.Slice(start, length));
        }

        private static bool TryReadResourceName(ReadOnlySpan<byte> buffer, int offset, out string name)
        {
            name = string.Empty;
            if (offset < 0 || offset + 2 > buffer.Length)
            {
                return false;
            }

            ushort length = ReadUInt16(buffer, offset);
            if (length == 0)
            {
                return true;
            }

            int byteLength = length * 2;
            int start = offset + 2;
            if (start + byteLength > buffer.Length)
            {
                return false;
            }

            name = Encoding.Unicode.GetString(buffer.Slice(start, byteLength)).TrimEnd('\0');
            return true;
        }

        private static bool TryReadResourceDataEntry(ReadOnlySpan<byte> buffer, int offset, out uint dataRva, out uint size, out uint codePage)
        {
            dataRva = 0;
            size = 0;
            codePage = 0;

            if (offset < 0 || offset + 16 > buffer.Length)
            {
                return false;
            }

            dataRva = ReadUInt32(buffer, offset);
            size = ReadUInt32(buffer, offset + 4);
            codePage = ReadUInt32(buffer, offset + 8);
            return true;
        }

        private static string GetResourceTypeName(uint typeId)
        {
            if (Enum.IsDefined(typeof(ResourceType), (ResourceType)typeId))
            {
                return ((ResourceType)typeId).ToString();
            }

            return string.Empty;
        }

        private void ParseResourceDirectory(
            ReadOnlySpan<byte> buffer,
            int directoryOffset,
            int level,
            uint typeId,
            string typeName,
            uint nameId,
            string name,
            List<IMAGE_SECTION_HEADER> sections,
            HashSet<int> visited)
        {
            if (buffer.Length == 0)
            {
                return;
            }

            int maxDepth = _options != null && _options.EnableDeepResourceTreeParsing ? 16 : 2;
            if (level > maxDepth)
            {
                Warn(ParseIssueCategory.Resources, "Resource directory depth exceeded expected limits.");
                return;
            }

            if (directoryOffset < 0 || directoryOffset + 16 > buffer.Length)
            {
                Warn(ParseIssueCategory.Resources, "Resource directory entry offset outside section bounds.");
                return;
            }

            if (!visited.Add(directoryOffset))
            {
                Warn(ParseIssueCategory.Resources, "Resource directory contains a circular reference.");
                return;
            }

            ushort numberOfNamed = ReadUInt16(buffer, directoryOffset + 12);
            ushort numberOfId = ReadUInt16(buffer, directoryOffset + 14);
            int entryCount = numberOfNamed + numberOfId;
            int entriesOffset = directoryOffset + 16;
            int maxEntries = (buffer.Length - entriesOffset) / 8;
            if (entryCount > maxEntries)
            {
                entryCount = maxEntries;
                Warn(ParseIssueCategory.Resources, "Resource directory entry count exceeds available data.");
            }

            for (int i = 0; i < entryCount; i++)
            {
                int entryOffset = entriesOffset + (i * 8);
                if (entryOffset + 8 > buffer.Length)
                {
                    Warn(ParseIssueCategory.Resources, "Resource directory entry outside section bounds.");
                    break;
                }

                uint nameOrId = ReadUInt32(buffer, entryOffset);
                uint dataOrSubdir = ReadUInt32(buffer, entryOffset + 4);

                bool isName = (nameOrId & 0x80000000) != 0;
                uint entryId = nameOrId & 0xFFFF;
                string entryName = string.Empty;
                if (isName)
                {
                    int nameOffset = (int)(nameOrId & 0x7FFFFFFF);
                    if (!TryReadResourceName(buffer, nameOffset, out entryName))
                    {
                        Warn(ParseIssueCategory.Resources, "Resource name entry offset outside section bounds.");
                        continue;
                    }
                }

                bool isDirectory = (dataOrSubdir & 0x80000000) != 0;
                int dataOffset = (int)(dataOrSubdir & 0x7FFFFFFF);

                if (level == 0)
                {
                    uint nextTypeId = isName ? 0u : entryId;
                    string nextTypeName = isName ? entryName : GetResourceTypeName(entryId);
                    if (isDirectory)
                    {
                        ParseResourceDirectory(buffer, dataOffset, level + 1, nextTypeId, nextTypeName, nameId, name, sections, visited);
                    }
                    else
                    {
                        Warn(ParseIssueCategory.Resources, "Resource type entry points directly to data.");
                    }
                }
                else if (level == 1)
                {
                    uint nextNameId = isName ? 0u : entryId;
                    string nextName = isName ? entryName : string.Empty;
                    if (isDirectory)
                    {
                        ParseResourceDirectory(buffer, dataOffset, level + 1, typeId, typeName, nextNameId, nextName, sections, visited);
                    }
                    else
                    {
                        Warn(ParseIssueCategory.Resources, "Resource name entry points directly to data.");
                    }
                }
                else
                {
                    ushort languageId = isName ? (ushort)0 : (ushort)entryId;
                    if (isDirectory)
                    {
                        if (_options != null && _options.EnableDeepResourceTreeParsing)
                        {
                            ParseResourceDirectory(buffer, dataOffset, level + 1, typeId, typeName, nameId, name, sections, visited);
                        }
                        else
                        {
                            Warn(ParseIssueCategory.Resources, "Resource language entry points to a subdirectory.");
                        }
                        continue;
                    }

                    if (!TryReadResourceDataEntry(buffer, dataOffset, out uint dataRva, out uint size, out uint codePage))
                    {
                        Warn(ParseIssueCategory.Resources, "Resource data entry outside section bounds.");
                        continue;
                    }

                    long fileOffset = -1;
                    if (TryGetFileOffset(sections, dataRva, size, out long dataFileOffset))
                    {
                        fileOffset = dataFileOffset;
                    }

                        _resources.Add(new ResourceEntry(
                            typeId,
                            typeName,
                            nameId,
                            name,
                            languageId,
                            codePage,
                            dataRva,
                            size,
                            fileOffset));
                }
            }
        }

        private static string[] ValidateResourceDirectoryStructure(ReadOnlySpan<byte> buffer, int rootOffset, bool allowDeepTree)
        {
            List<string> issues = new List<string>();
            ValidateResourceDirectoryNode(buffer, rootOffset, 0, allowDeepTree, new HashSet<int>(), issues);
            return issues.ToArray();
        }

        private static void ValidateResourceDirectoryNode(
            ReadOnlySpan<byte> buffer,
            int directoryOffset,
            int level,
            bool allowDeepTree,
            HashSet<int> visited,
            List<string> issues)
        {
            int maxDepth = allowDeepTree ? 16 : 2;
            if (level > maxDepth)
            {
                issues.Add("Resource directory depth exceeded expected limits.");
                return;
            }

            if (directoryOffset < 0 || directoryOffset + 16 > buffer.Length)
            {
                issues.Add("Resource directory entry offset outside section bounds.");
                return;
            }

            if (!visited.Add(directoryOffset))
            {
                issues.Add("Resource directory contains a circular reference.");
                return;
            }

            try
            {
                ushort numberOfNamed = ReadUInt16(buffer, directoryOffset + 12);
                ushort numberOfId = ReadUInt16(buffer, directoryOffset + 14);
                int entryCount = numberOfNamed + numberOfId;
                int entriesOffset = directoryOffset + 16;
                int maxEntries = (buffer.Length - entriesOffset) / 8;
                if (entryCount > maxEntries)
                {
                    issues.Add("Resource directory entry count exceeds available data.");
                    entryCount = maxEntries;
                }

                string previousName = null;
                uint previousId = 0;
                bool hasPreviousId = false;

                for (int i = 0; i < entryCount; i++)
                {
                    int entryOffset = entriesOffset + (i * 8);
                    if (entryOffset + 8 > buffer.Length)
                    {
                        issues.Add("Resource directory entry outside section bounds.");
                        break;
                    }

                    uint nameOrId = ReadUInt32(buffer, entryOffset);
                    uint dataOrSubdir = ReadUInt32(buffer, entryOffset + 4);
                    bool isName = (nameOrId & 0x80000000) != 0;
                    uint entryId = nameOrId & 0xFFFF;

                    if (i < numberOfNamed && !isName)
                    {
                        issues.Add("SPEC violation: Resource directory named entries are not grouped before ID entries.");
                    }
                    else if (i >= numberOfNamed && isName)
                    {
                        issues.Add("SPEC violation: Resource directory ID entries contain name references.");
                    }

                    if (isName)
                    {
                        int nameOffset = (int)(nameOrId & 0x7FFFFFFF);
                        if (!TryReadResourceName(buffer, nameOffset, out string entryName))
                        {
                            issues.Add("Resource name entry offset outside section bounds.");
                        }
                        else
                        {
                            if (previousName != null &&
                                string.Compare(entryName, previousName, StringComparison.Ordinal) < 0)
                            {
                                issues.Add("SPEC violation: Resource directory named entries are out of order.");
                            }

                            previousName = entryName;
                        }
                    }
                    else
                    {
                        if (hasPreviousId && entryId < previousId)
                        {
                            issues.Add("SPEC violation: Resource directory ID entries are out of order.");
                        }

                        previousId = entryId;
                        hasPreviousId = true;
                    }

                    bool isDirectory = (dataOrSubdir & 0x80000000) != 0;
                    int childOffset = (int)(dataOrSubdir & 0x7FFFFFFF);
                    if (isDirectory)
                    {
                        ValidateResourceDirectoryNode(buffer, childOffset, level + 1, allowDeepTree, visited, issues);
                    }
                    else if (!TryReadResourceDataEntry(buffer, childOffset, out _, out _, out _))
                    {
                        issues.Add("Resource data entry outside section bounds.");
                    }
                }
            }
            finally
            {
                visited.Remove(directoryOffset);
            }
        }

        private bool TryGetResourceData(
            ReadOnlySpan<byte> resourceBuffer,
            uint resourceBaseRva,
            uint dataRva,
            uint dataSize,
            List<IMAGE_SECTION_HEADER> sections,
            out byte[] data)
        {
            data = Array.Empty<byte>();
            if (!TryGetIntSize(dataSize, out int size) || size <= 0)
            {
                return false;
            }

            if (resourceBuffer.Length > 0 && dataRva >= resourceBaseRva)
            {
                uint offset = dataRva - resourceBaseRva;
                if (offset <= int.MaxValue && size <= resourceBuffer.Length - (int)offset)
                {
                    data = new byte[size];
                    resourceBuffer.Slice((int)offset, size).CopyTo(data);
                    return true;
                }
            }

            if (TryGetFileOffset(sections, dataRva, dataSize, out long fileOffset) &&
                TrySetPosition(fileOffset, size))
            {
                data = new byte[size];
                ReadExactly(PEFileStream, data, 0, size);
                return true;
            }

            return false;
        }

        private bool TryGetResourceDataSpan(
            ReadOnlySpan<byte> resourceBuffer,
            uint resourceBaseRva,
            uint dataRva,
            uint dataSize,
            List<IMAGE_SECTION_HEADER> sections,
            out ReadOnlySpan<byte> dataSpan,
            out byte[] ownedBuffer)
        {
            dataSpan = ReadOnlySpan<byte>.Empty;
            ownedBuffer = Array.Empty<byte>();
            if (!TryGetIntSize(dataSize, out int size) || size <= 0)
            {
                return false;
            }

            if (resourceBuffer.Length > 0 && dataRva >= resourceBaseRva)
            {
                uint offset = dataRva - resourceBaseRva;
                if (offset <= int.MaxValue && size <= resourceBuffer.Length - (int)offset)
                {
                    dataSpan = resourceBuffer.Slice((int)offset, size);
                    return true;
                }
            }

            if (TryGetFileOffset(sections, dataRva, dataSize, out long fileOffset) &&
                TrySetPosition(fileOffset, size))
            {
                ownedBuffer = new byte[size];
                ReadExactly(PEFileStream, ownedBuffer, 0, size);
                dataSpan = ownedBuffer;
                return true;
            }

            return false;
        }

        private void DecodeResourceStringTables(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.String)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] _))
                {
                    continue;
                }

                if (!TryParseStringTable(dataSpan, out string[] strings))
                {
                    continue;
                }

                _resourceStringTables.Add(new ResourceStringTableInfo(entry.NameId, entry.LanguageId, strings));
            }
        }

        private void DecodeResourceManifests(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                bool isMui = string.Equals(entry.TypeName, "MUI", StringComparison.OrdinalIgnoreCase);
                bool isManifest = entry.TypeId == (uint)ResourceType.Manifest;
                bool isDlgInclude = entry.TypeId == (uint)ResourceType.DlgInclude;
                if (!isManifest && !isMui && !isDlgInclude)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] _))
                {
                    continue;
                }

                string content = DecodeTextResource(dataSpan);
                if (string.IsNullOrWhiteSpace(content))
                {
                    continue;
                }

                if (!isManifest && !isMui && !LooksLikeManifest(content))
                {
                    continue;
                }

                if (!isManifest && !isMui)
                {
                    isMui = true;
                }

                ManifestSchemaInfo schema = null;
                TryParseManifestSchema(content, out schema);
                _resourceManifests.Add(new ResourceManifestInfo(
                    entry.NameId,
                    entry.LanguageId,
                    entry.TypeId,
                    entry.TypeName,
                    content,
                    schema,
                    isMui));
            }
        }

        private void DecodeResourceMessageTables(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.MessageTable)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] _))
                {
                    continue;
                }

                if (!TryParseMessageTable(dataSpan, out MessageTableEntryInfo[] entries, out uint minId, out uint maxId))
                {
                    continue;
                }

                _resourceMessageTables.Add(new ResourceMessageTableInfo(entry.NameId, entry.LanguageId, minId, maxId, entries));
            }
        }

        private void DecodeResourceDialogs(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.Dialog)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] _))
                {
                    continue;
                }

                if (!TryParseDialogTemplate(dataSpan, out ResourceDialogInfo dialog))
                {
                    Warn(ParseIssueCategory.Resources, "Dialog resource could not be parsed.");
                    continue;
                }

                _resourceDialogs.Add(new ResourceDialogInfo(
                    entry.NameId,
                    entry.LanguageId,
                    dialog.IsExtended,
                    dialog.Style,
                    dialog.ExtendedStyle,
                    dialog.ControlCount,
                    dialog.X,
                    dialog.Y,
                    dialog.Cx,
                    dialog.Cy,
                    dialog.Menu,
                    dialog.WindowClass,
                    dialog.Title,
                    dialog.FontPointSize,
                    dialog.FontFace));
            }
        }

        private void DecodeResourceAccelerators(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.Accelerator)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] _))
                {
                    continue;
                }

                if (!TryParseAcceleratorTable(dataSpan, out ResourceAcceleratorEntryInfo[] entries))
                {
                    Warn(ParseIssueCategory.Resources, "Accelerator resource could not be parsed.");
                    continue;
                }

                _resourceAccelerators.Add(new ResourceAcceleratorTableInfo(entry.NameId, entry.LanguageId, entries));
            }
        }

        private void DecodeResourceMenus(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.Menu)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] _))
                {
                    continue;
                }

                if (!TryParseMenuTemplate(dataSpan, out ResourceMenuInfo menu))
                {
                    Warn(ParseIssueCategory.Resources, "Menu resource could not be parsed.");
                    continue;
                }

                _resourceMenus.Add(new ResourceMenuInfo(
                    entry.NameId,
                    entry.LanguageId,
                    menu.IsExtended,
                    menu.ItemCount,
                    menu.ItemTexts.ToArray()));
            }
        }

        private void DecodeResourceToolbars(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.Toolbar)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] _))
                {
                    continue;
                }

                if (!TryParseToolbarResource(dataSpan, out ResourceToolbarInfo toolbar))
                {
                    Warn(ParseIssueCategory.Resources, "Toolbar resource could not be parsed.");
                    continue;
                }

                _resourceToolbars.Add(new ResourceToolbarInfo(
                    entry.NameId,
                    entry.LanguageId,
                    toolbar.Version,
                    toolbar.Width,
                    toolbar.Height,
                    toolbar.ItemCount,
                    toolbar.ItemIds.ToArray()));
            }
        }

        private void DecodeResourceVersionInfo(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            ResourceEntry versionEntry = _resources.FirstOrDefault(r => r.TypeId == (uint)ResourceType.Version);
            if (versionEntry == null)
            {
                _versionInfoDetails = null;
                return;
            }

            if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, versionEntry.DataRva, versionEntry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
            {
                _versionInfoDetails = null;
                return;
            }

            byte[] data = owned.Length > 0 ? owned : dataSpan.ToArray();
            FileVersionInfo fvi = new FileVersionInfo(data);
            _versionInfoDetails = fvi.ToVersionInfoDetails();
            if (!fvi.FixedFileInfoSignatureValid && fvi.FixedFileInfoSignature != 0)
            {
                Warn(ParseIssueCategory.Resources, "VS_FIXEDFILEINFO signature is invalid.");
            }
        }

        private void DecodeResourceIconGroups(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            List<ResourceEntry> iconEntries = _resources
                .Where(r => r.TypeId == (uint)ResourceType.Icon)
                .ToList();

            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.GroupIcon)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                byte[] data = owned.Length > 0 ? owned : dataSpan.ToArray();
                if (TryParseGroupIcon(entry, data, iconEntries, resourceBuffer, resourceBaseRva, sections, out IconGroupInfo group, out bool hasMissingIcons))
                {
                    _iconGroups.Add(group);
                    if (hasMissingIcons)
                    {
                        Warn(ParseIssueCategory.Resources, "Icon group references missing icon resources.");
                    }
                }
            }
        }

        private void DecodeResourceCursorGroups(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceCursorGroups.Clear();
            List<ResourceEntry> cursorEntries = _resources
                .Where(r => r.TypeId == (uint)ResourceType.Cursor)
                .ToList();

            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.GroupCursor)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                byte[] data = owned.Length > 0 ? owned : dataSpan.ToArray();
                if (TryParseGroupCursor(entry, data, cursorEntries, resourceBuffer, resourceBaseRva, sections, out ResourceCursorGroupInfo group, out bool hasMissing))
                {
                    _resourceCursorGroups.Add(group);
                    if (hasMissing)
                    {
                        Warn(ParseIssueCategory.Resources, "Cursor group references missing cursor resources.");
                    }
                }
            }
        }

        private void DecodeResourceBitmaps(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceBitmaps.Clear();
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.Bitmap)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                ReadOnlySpan<byte> data = owned.Length > 0 ? owned : dataSpan;
                if (TryParseBitmapInfoHeader(data, out int width, out int height, out ushort bitCount, out uint compression, out uint imageSize))
                {
                    _resourceBitmaps.Add(new ResourceBitmapInfo(
                        entry.NameId,
                        entry.LanguageId,
                        width,
                        height,
                        bitCount,
                        compression,
                        GetBitmapCompressionName(compression),
                        imageSize));
                }
                else if (TryParsePngIcon(data, out uint pngWidth, out uint pngHeight))
                {
                    _resourceBitmaps.Add(new ResourceBitmapInfo(
                        entry.NameId,
                        entry.LanguageId,
                        (int)pngWidth,
                        (int)pngHeight,
                        0,
                        5,
                        "PNG",
                        (uint)data.Length));
                }
            }
        }

        private void DecodeResourceIcons(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceIcons.Clear();
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.Icon)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                ReadOnlySpan<byte> data = owned.Length > 0 ? owned : dataSpan;
                if (TryParseIconResource(data, out int width, out int height, out ushort bitCount, out bool isPng, out uint pngWidth, out uint pngHeight))
                {
                    _resourceIcons.Add(new ResourceIconInfo(
                        entry.NameId,
                        entry.LanguageId,
                        width,
                        height,
                        bitCount,
                        isPng,
                        pngWidth,
                        pngHeight,
                        entry.Size));
                }
            }
        }

        private void DecodeResourceCursors(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceCursors.Clear();
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.Cursor)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                ReadOnlySpan<byte> data = owned.Length > 0 ? owned : dataSpan;
                if (TryParseCursorResource(data, out ushort hotspotX, out ushort hotspotY, out int width, out int height, out ushort bitCount, out bool isPng, out uint pngWidth, out uint pngHeight))
                {
                    _resourceCursors.Add(new ResourceCursorInfo(
                        entry.NameId,
                        entry.LanguageId,
                        hotspotX,
                        hotspotY,
                        width,
                        height,
                        bitCount,
                        isPng,
                        pngWidth,
                        pngHeight,
                        entry.Size));
                }
            }
        }

        private void DecodeResourceFonts(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceFonts.Clear();
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.Font)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                ReadOnlySpan<byte> data = owned.Length > 0 ? owned : dataSpan;
                string format = DetectFontFormat(data);
                string faceName = TryParseFontFaceName(data, format);
                _resourceFonts.Add(new ResourceFontInfo(entry.NameId, entry.LanguageId, entry.Size, format, faceName));
            }
        }

        private void DecodeResourceFontDirectories(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceFontDirectories.Clear();
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.FontDirectory)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                ReadOnlySpan<byte> data = owned.Length > 0 ? owned : dataSpan;
                if (TryParseFontDirectory(data, out ushort count, out ResourceFontDirEntryInfo[] entries))
                {
                    _resourceFontDirectories.Add(new ResourceFontDirInfo(entry.NameId, entry.LanguageId, count, entries));
                }
            }
        }

        private void DecodeResourceDlgInit(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceDlgInit.Clear();
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.DlgInit)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                ReadOnlySpan<byte> data = owned.Length > 0 ? owned : dataSpan;
                if (TryParseDlgInit(data, out ResourceDlgInitEntryInfo[] entries))
                {
                    _resourceDlgInit.Add(new ResourceDlgInitInfo(entry.NameId, entry.LanguageId, entries));
                }
            }
        }

        private void DecodeResourceAnimatedResources(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceAnimatedCursors.Clear();
            _resourceAnimatedIcons.Clear();
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                bool isCursor = entry.TypeId == (uint)ResourceType.AnimatedCursor;
                bool isIcon = entry.TypeId == (uint)ResourceType.AnimatedIcon;
                if (!isCursor && !isIcon)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                ReadOnlySpan<byte> data = owned.Length > 0 ? owned : dataSpan;
                if (!TryParseAnimatedResource(data, out ResourceAnimatedInfo info))
                {
                    continue;
                }

                ResourceAnimatedInfo value = new ResourceAnimatedInfo(
                    entry.NameId,
                    entry.LanguageId,
                    info.Format,
                    info.FrameCount,
                    info.StepCount,
                    info.Width,
                    info.Height,
                    info.BitCount,
                    info.Planes,
                    info.JifRate,
                    info.Flags,
                    info.ChunkTypes.ToArray());
                if (isCursor)
                {
                    _resourceAnimatedCursors.Add(value);
                }
                else
                {
                    _resourceAnimatedIcons.Add(value);
                }
            }
        }

        private void DecodeResourceRcData(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceRcData.Clear();
            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)ResourceType.RcData)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                ReadOnlySpan<byte> data = owned.Length > 0 ? owned : dataSpan;
                ResourceRcDataInfo info = BuildRcDataInfo(entry, data);
                _resourceRcData.Add(info);
            }
        }

        private void DecodeResourceHtml(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceHtml.Clear();
            DecodeResourceRawType(resourceBuffer, resourceBaseRva, sections, ResourceType.HTML, _resourceHtml);
        }

        private void DecodeResourceDlgInclude(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceDlgInclude.Clear();
            DecodeResourceRawType(resourceBuffer, resourceBaseRva, sections, ResourceType.DlgInclude, _resourceDlgInclude);
        }

        private void DecodeResourcePlugAndPlay(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourcePlugAndPlay.Clear();
            DecodeResourceRawType(resourceBuffer, resourceBaseRva, sections, ResourceType.PlugAndPlay, _resourcePlugAndPlay);
        }

        private void DecodeResourceVxd(ReadOnlySpan<byte> resourceBuffer, uint resourceBaseRva, List<IMAGE_SECTION_HEADER> sections)
        {
            _resourceVxd.Clear();
            DecodeResourceRawType(resourceBuffer, resourceBaseRva, sections, ResourceType.VXD, _resourceVxd);
        }

        private void DecodeResourceRawType(
            ReadOnlySpan<byte> resourceBuffer,
            uint resourceBaseRva,
            List<IMAGE_SECTION_HEADER> sections,
            ResourceType type,
            List<ResourceRawInfo> target)
        {
            if (target == null)
            {
                return;
            }

            for (int i = 0; i < _resources.Count; i++)
            {
                ResourceEntry entry = _resources[i];
                if (entry.TypeId != (uint)type)
                {
                    continue;
                }

                if (!TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, entry.DataRva, entry.Size, sections, out ReadOnlySpan<byte> dataSpan, out byte[] owned))
                {
                    continue;
                }

                ReadOnlySpan<byte> data = owned.Length > 0 ? owned : dataSpan;
                ResourceRawInfo info = BuildResourceRawInfo(entry, data);
                target.Add(info);
            }
        }

        private void ParseResourceSection(
            ReadOnlySpan<byte> resourceSpan,
            int resourceSize,
            uint resourceDirectoryRva,
            IMAGE_SECTION_HEADER resourceSection,
            List<IMAGE_SECTION_HEADER> sections,
            byte[] resourceBuffer)
        {
            int rootOffset = 0;
            if (resourceDirectoryRva >= resourceSection.VirtualAddress)
            {
                uint delta = resourceDirectoryRva - resourceSection.VirtualAddress;
                if (delta <= int.MaxValue && delta < (uint)resourceSize)
                {
                    rootOffset = (int)delta;
                }
                else
                {
                    Warn(ParseIssueCategory.Resources, "Resource directory root offset outside section bounds.");
                }
            }
            else
            {
                Warn(ParseIssueCategory.Resources, "Resource directory RVA does not map to resource section.");
            }

            string[] resourceStructureIssues = ValidateResourceDirectoryStructure(
                resourceSpan,
                rootOffset,
                _options != null && _options.EnableDeepResourceTreeParsing);
            for (int i = 0; i < resourceStructureIssues.Length; i++)
            {
                Warn(ParseIssueCategory.Resources, resourceStructureIssues[i]);
            }

            ParseResourceDirectory(resourceSpan, rootOffset, 0, 0, string.Empty, 0, string.Empty, sections, new HashSet<int>());
            DecodeResourceStringTables(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceMessageTables(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceDialogs(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceAccelerators(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceMenus(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceToolbars(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceManifests(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceIconGroups(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceCursorGroups(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceBitmaps(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceIcons(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceCursors(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceFonts(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceFontDirectories(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceDlgInit(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceAnimatedResources(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceRcData(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceHtml(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceDlgInclude(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourcePlugAndPlay(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceVxd(resourceSpan, resourceSection.VirtualAddress, sections);
            DecodeResourceVersionInfo(resourceSpan, resourceSection.VirtualAddress, sections);

            FileVersionInfo fvi;
            ResourceEntry versionEntry = _resources.FirstOrDefault(r => r.TypeId == (uint)ResourceType.Version);
            byte[] fallbackBuffer = resourceBuffer;
            if (versionEntry != null &&
                TryGetResourceData(resourceSpan, resourceSection.VirtualAddress, versionEntry.DataRva, versionEntry.Size, sections, out byte[] versionData))
            {
                fvi = new FileVersionInfo(versionData);
                if (fvi.ProductVersion.Equals("0.0.0.0") && fvi.FileVersion.Equals("0.0.0.0"))
                {
                    if (fallbackBuffer == null)
                    {
                        fallbackBuffer = resourceSpan.ToArray();
                    }

                    FileVersionInfo fallback = new FileVersionInfo(fallbackBuffer, resourceSize);
                    if (!(fallback.ProductVersion.Equals("0.0.0.0") && fallback.FileVersion.Equals("0.0.0.0")))
                    {
                        fvi = fallback;
                    }
                }
            }
            else
            {
                if (fallbackBuffer == null)
                {
                    fallbackBuffer = resourceSpan.ToArray();
                }

                fvi = new FileVersionInfo(fallbackBuffer, resourceSize);
            }

            _versionInfoDetails = fvi.ToVersionInfoDetails();
            _fileversion = fvi.FileVersion;
            _productversion = fvi.ProductVersion;
            _companyName = fvi.CompanyName;
            _fileDescription = fvi.FileDescription;
            _internalName = fvi.InternalName;
            _originalFilename = fvi.OriginalFilename;
            _productName = fvi.ProductName;
            _comments = fvi.Comments;
            _legalCopyright = fvi.LegalCopyright;
            _legalTrademarks = fvi.LegalTrademarks;
            _privateBuild = fvi.PrivateBuild;
            _specialBuild = fvi.SpecialBuild;
            _language = fvi.Language;

            if (fvi.ProductVersion.Equals("0.0.0.0") && fvi.FileVersion.Equals("0.0.0.0"))
            {
                System.Diagnostics.FileVersionInfo versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(_filePath);
                _fileversion = versionInfo.FileVersion;
                _productversion = versionInfo.ProductVersion;
                SetIfEmpty(ref _companyName, versionInfo.CompanyName);
                SetIfEmpty(ref _fileDescription, versionInfo.FileDescription);
                SetIfEmpty(ref _internalName, versionInfo.InternalName);
                SetIfEmpty(ref _originalFilename, versionInfo.OriginalFilename);
                SetIfEmpty(ref _productName, versionInfo.ProductName);
                SetIfEmpty(ref _comments, versionInfo.Comments);
                SetIfEmpty(ref _legalCopyright, versionInfo.LegalCopyright);
                SetIfEmpty(ref _legalTrademarks, versionInfo.LegalTrademarks);
                SetIfEmpty(ref _privateBuild, versionInfo.PrivateBuild);
                SetIfEmpty(ref _specialBuild, versionInfo.SpecialBuild);
                SetIfEmpty(ref _language, versionInfo.Language);
            }

            BuildResourceStringCoverage();
            BuildResourceLocaleCoverage();
        }

        private void BuildResourceLocaleCoverage()
        {
            _resourceLocaleCoverage.Clear();
            AddResourceLocaleCoverage("StringTable", _resourceStringTables.Select(t => t.LanguageId));
            AddResourceLocaleCoverage("Manifest", _resourceManifests.Select(m => m.LanguageId));
        }

        private void BuildResourceStringCoverage()
        {
            _resourceStringCoverage.Clear();
            if (_resourceStringTables.Count == 0)
            {
                return;
            }

            List<ResourceStringCoverageInfo> coverage = ComputeResourceStringCoverage(
                _resourceStringTables,
                message => Warn(ParseIssueCategory.Resources, message));
            _resourceStringCoverage.AddRange(coverage);
        }

        internal static ResourceStringCoverageInfo[] BuildResourceStringCoverageForTest(params ResourceStringTableInfo[] tables)
        {
            List<ResourceStringCoverageInfo> coverage = ComputeResourceStringCoverage(
                tables ?? Array.Empty<ResourceStringTableInfo>(),
                null);
            return coverage.ToArray();
        }

        private static List<ResourceStringCoverageInfo> ComputeResourceStringCoverage(
            IEnumerable<ResourceStringTableInfo> tables,
            Action<string> warn)
        {
            if (tables == null)
            {
                return new List<ResourceStringCoverageInfo>();
            }

            ResourceStringTableInfo[] tableArray = tables as ResourceStringTableInfo[] ?? tables.ToArray();
            if (tableArray.Length == 0)
            {
                return new List<ResourceStringCoverageInfo>();
            }

            List<ResourceStringCoverageCandidate> candidates = new List<ResourceStringCoverageCandidate>();
            foreach (IGrouping<ushort, ResourceStringTableInfo> group in tableArray.GroupBy(t => t.LanguageId))
            {
                ushort languageId = group.Key;
                uint[] blockIds = group.Select(t => t.BlockId).Distinct().OrderBy(id => id).ToArray();
                if (blockIds.Length == 0)
                {
                    continue;
                }

                int stringCount = 0;
                foreach (ResourceStringTableInfo table in group)
                {
                    if (table.Strings == null)
                    {
                        continue;
                    }

                    for (int i = 0; i < table.Strings.Length; i++)
                    {
                        if (!string.IsNullOrWhiteSpace(table.Strings[i]))
                        {
                            stringCount++;
                        }
                    }
                }

                uint minBlock = blockIds[0];
                uint maxBlock = blockIds[blockIds.Length - 1];
                ulong range = (ulong)maxBlock - minBlock + 1;
                int missingCount = 0;
                if (range > (ulong)blockIds.Length)
                {
                    missingCount = range > int.MaxValue ? int.MaxValue : (int)(range - (ulong)blockIds.Length);
                }

                List<uint> missingBlocks = new List<uint>();
                if (missingCount > 0 && range <= 512)
                {
                    HashSet<uint> present = new HashSet<uint>(blockIds);
                    for (uint id = minBlock; id <= maxBlock; id++)
                    {
                        if (!present.Contains(id))
                        {
                            missingBlocks.Add(id);
                            if (missingBlocks.Count >= 10)
                            {
                                break;
                            }
                        }
                    }
                }

                candidates.Add(new ResourceStringCoverageCandidate(
                    languageId,
                    ResolveResourceCultureName(languageId),
                    blockIds.Length,
                    stringCount,
                    minBlock,
                    maxBlock,
                    missingCount,
                    missingBlocks.ToArray()));
            }

            if (candidates.Count == 0)
            {
                return new List<ResourceStringCoverageInfo>();
            }

            ResourceStringCoverageCandidate best = candidates
                .OrderByDescending(c => c.StringCount)
                .ThenByDescending(c => c.BlockCount)
                .First();

            List<ResourceStringCoverageInfo> coverage = new List<ResourceStringCoverageInfo>(candidates.Count);
            foreach (ResourceStringCoverageCandidate candidate in candidates)
            {
                bool isBest = candidate.LanguageId == best.LanguageId &&
                              candidate.BlockCount == best.BlockCount &&
                              candidate.StringCount == best.StringCount;
                coverage.Add(new ResourceStringCoverageInfo(
                    candidate.LanguageId,
                    candidate.CultureName,
                    candidate.BlockCount,
                    candidate.StringCount,
                    candidate.MinBlockId,
                    candidate.MaxBlockId,
                    candidate.MissingBlockCount,
                    candidate.MissingBlocks,
                    isBest));

                if (isBest && candidate.MissingBlockCount > 0 && warn != null)
                {
                    warn($"String table has {candidate.MissingBlockCount} missing block(s) for language 0x{candidate.LanguageId:X4}.");
                }
            }

            return coverage;
        }

        private sealed class ResourceStringCoverageCandidate
        {
            public ushort LanguageId { get; }
            public string CultureName { get; }
            public int BlockCount { get; }
            public int StringCount { get; }
            public uint MinBlockId { get; }
            public uint MaxBlockId { get; }
            public int MissingBlockCount { get; }
            public uint[] MissingBlocks { get; }

            public ResourceStringCoverageCandidate(
                ushort languageId,
                string cultureName,
                int blockCount,
                int stringCount,
                uint minBlockId,
                uint maxBlockId,
                int missingBlockCount,
                uint[] missingBlocks)
            {
                LanguageId = languageId;
                CultureName = cultureName ?? string.Empty;
                BlockCount = blockCount;
                StringCount = stringCount;
                MinBlockId = minBlockId;
                MaxBlockId = maxBlockId;
                MissingBlockCount = missingBlockCount;
                MissingBlocks = missingBlocks ?? Array.Empty<uint>();
            }
        }

        private static string ResolveResourceCultureName(ushort languageId)
        {
            if (languageId == 0)
            {
                return "Neutral";
            }

            try
            {
                return CultureInfo.GetCultureInfo(languageId).Name;
            }
            catch (CultureNotFoundException)
            {
                return "0x" + languageId.ToString("X4", CultureInfo.InvariantCulture);
            }
        }

        private void AddResourceLocaleCoverage(string kind, IEnumerable<ushort> languageIds)
        {
            if (languageIds == null)
            {
                return;
            }

            ushort[] unique = languageIds
                .Distinct()
                .OrderBy(id => id)
                .ToArray();

            if (unique.Length == 0)
            {
                return;
            }

            bool hasNeutral = unique.Contains((ushort)0);
            bool hasLocalized = unique.Any(id => id != 0);
            bool missingNeutral = hasLocalized && !hasNeutral;
            if (missingNeutral)
            {
                Warn(ParseIssueCategory.Resources, $"{kind} resources are localized but no neutral language fallback was found.");
            }

            _resourceLocaleCoverage.Add(new ResourceLocaleCoverageInfo(
                kind,
                unique,
                hasNeutral,
                hasLocalized,
                missingNeutral));
        }

        internal static ResourceLocaleCoverageInfo BuildResourceLocaleCoverageForTest(string kind, params ushort[] languageIds)
        {
            ushort[] unique = languageIds
                .Where(id => id >= 0)
                .Distinct()
                .OrderBy(id => id)
                .ToArray();
            bool hasNeutral = unique.Contains((ushort)0);
            bool hasLocalized = unique.Any(id => id != 0);
            bool missingNeutral = hasLocalized && !hasNeutral;
            return new ResourceLocaleCoverageInfo(kind, unique, hasNeutral, hasLocalized, missingNeutral);
        }

        internal static string[] ValidateResourceDirectoryForTest(byte[] data, bool allowDeepTree)
        {
            if (data == null)
            {
                return new[] { "Resource directory data is null." };
            }

            return ValidateResourceDirectoryStructure(new ReadOnlySpan<byte>(data), 0, allowDeepTree);
        }

        private void ParseResourceDirectoryTable(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections)
        {
            IMAGE_SECTION_HEADER resourceSection;
            if (!TryGetSectionByRva(sections, directory.VirtualAddress, out resourceSection))
            {
                resourceSection = sections.Find(
                    p => p.Section.TrimEnd('\0').Equals(".rsrc", StringComparison.OrdinalIgnoreCase));
            }

            if (resourceSection.Name == null || !TryGetIntSize(resourceSection.SizeOfRawData, out int rsrcSize))
            {
                Warn(ParseIssueCategory.Resources, "Resource section not found or invalid.");
                return;
            }

            if (!TrySetPosition(resourceSection.PointerToRawData, rsrcSize))
            {
                Warn(ParseIssueCategory.Resources, "Resource section offset outside file bounds.");
                return;
            }

            bool parsedResource = false;
            if (_memoryMappedAccessor != null)
            {
                long resourceOffset = resourceSection.PointerToRawData;
                if (TryWithMappedSpan(resourceOffset, rsrcSize, span =>
                {
                    ParseResourceSection(span, rsrcSize, directory.VirtualAddress, resourceSection, sections, null);
                }))
                {
                    parsedResource = true;
                }
            }

            if (!parsedResource)
            {
                byte[] resourceBuffer = ArrayPool<byte>.Shared.Rent(rsrcSize);
                try
                {
                    ReadExactly(PEFileStream, resourceBuffer, 0, rsrcSize);
                    ReadOnlySpan<byte> resourceSpan = new ReadOnlySpan<byte>(resourceBuffer, 0, rsrcSize);
                    ParseResourceSection(resourceSpan, rsrcSize, directory.VirtualAddress, resourceSection, sections, resourceBuffer);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(resourceBuffer);
                }
            }
        }

        private bool TryParseGroupIcon(
            ResourceEntry entry,
            byte[] groupData,
            List<ResourceEntry> iconEntries,
            ReadOnlySpan<byte> resourceBuffer,
            uint resourceBaseRva,
            List<IMAGE_SECTION_HEADER> sections,
            out IconGroupInfo group,
            out bool hasMissingIcons)
        {
            group = null;
            hasMissingIcons = false;
            if (groupData == null || groupData.Length < 6)
            {
                return false;
            }
            if (!TryReadGroupResourceHeader(groupData, 1, out ushort reserved, out ushort type, out ushort count, out int entrySize, out int parsedCount, out bool headerValid, out bool entriesTruncated))
            {
                return false;
            }

            if (!headerValid)
            {
                Warn(ParseIssueCategory.Resources, "Icon group header has unexpected reserved/type values.");
            }
            if (entriesTruncated)
            {
                Warn(ParseIssueCategory.Resources, "Icon group data is truncated.");
            }

            List<IconEntryInfo> entries = new List<IconEntryInfo>();
            List<byte[]> iconImages = new List<byte[]>();
            for (int i = 0; i < parsedCount; i++)
            {
                int offset = 6 + (i * entrySize);
                if (offset + 14 > groupData.Length)
                {
                    break;
                }

                byte width = groupData[offset];
                byte height = groupData[offset + 1];
                byte colorCount = groupData[offset + 2];
                byte reservedEntry = groupData[offset + 3];
                ushort planes = ReadUInt16(groupData, offset + 4);
                ushort bitCount = ReadUInt16(groupData, offset + 6);
                uint bytesInRes = ReadUInt32(groupData, offset + 8);
                ushort resourceId = ReadUInt16(groupData, offset + 12);
                bool isPng = false;
                uint pngWidth = 0;
                uint pngHeight = 0;
                ResourceEntry iconEntry = iconEntries.FirstOrDefault(r => r.NameId == resourceId);
                if (iconEntry != null &&
                    TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, iconEntry.DataRva, iconEntry.Size, sections, out ReadOnlySpan<byte> iconSpan, out byte[] iconOwned))
                {
                    ReadOnlySpan<byte> iconData = iconOwned.Length > 0 ? iconOwned : iconSpan;
                    if (TryParsePngIcon(iconData, out uint parsedWidth, out uint parsedHeight))
                    {
                        isPng = true;
                        pngWidth = parsedWidth;
                        pngHeight = parsedHeight;
                    }

                    iconImages.Add(iconOwned.Length > 0 ? iconOwned : iconSpan.ToArray());
                }
                else
                {
                    iconImages.Add(Array.Empty<byte>());
                    hasMissingIcons = true;
                }

                entries.Add(new IconEntryInfo(
                    width,
                    height,
                    colorCount,
                    reservedEntry,
                    planes,
                    bitCount,
                    bytesInRes,
                    resourceId,
                    isPng,
                    pngWidth,
                    pngHeight));
            }

            byte[] icoData = BuildIconFile(entries, iconImages);
            group = new IconGroupInfo(
                entry.NameId,
                entry.LanguageId,
                reserved,
                type,
                count,
                entrySize,
                headerValid,
                entriesTruncated,
                entries.ToArray(),
                icoData);
            return true;
        }

        private bool TryParseGroupCursor(
            ResourceEntry entry,
            byte[] groupData,
            List<ResourceEntry> cursorEntries,
            ReadOnlySpan<byte> resourceBuffer,
            uint resourceBaseRva,
            List<IMAGE_SECTION_HEADER> sections,
            out ResourceCursorGroupInfo group,
            out bool hasMissingCursors)
        {
            group = null;
            hasMissingCursors = false;
            if (groupData == null || groupData.Length < 6)
            {
                return false;
            }
            if (!TryReadGroupResourceHeader(groupData, 2, out ushort reserved, out ushort type, out ushort count, out int entrySize, out int parsedCount, out bool headerValid, out bool entriesTruncated))
            {
                return false;
            }

            if (!headerValid)
            {
                Warn(ParseIssueCategory.Resources, "Cursor group header has unexpected reserved/type values.");
            }
            if (entriesTruncated)
            {
                Warn(ParseIssueCategory.Resources, "Cursor group data is truncated.");
            }

            List<ResourceCursorEntryInfo> entries = new List<ResourceCursorEntryInfo>();
            for (int i = 0; i < parsedCount; i++)
            {
                int offset = 6 + (i * entrySize);
                if (offset + 14 > groupData.Length)
                {
                    break;
                }

                byte width = groupData[offset];
                byte height = groupData[offset + 1];
                ushort hotspotX = ReadUInt16(groupData, offset + 4);
                ushort hotspotY = ReadUInt16(groupData, offset + 6);
                uint bytesInRes = ReadUInt32(groupData, offset + 8);
                ushort resourceId = ReadUInt16(groupData, offset + 12);
                bool isPng = false;
                uint pngWidth = 0;
                uint pngHeight = 0;
                ResourceEntry cursorEntry = cursorEntries.FirstOrDefault(r => r.NameId == resourceId);
                if (cursorEntry != null &&
                    TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, cursorEntry.DataRva, cursorEntry.Size, sections, out ReadOnlySpan<byte> cursorSpan, out byte[] cursorOwned))
                {
                    ReadOnlySpan<byte> cursorData = cursorOwned.Length > 0 ? cursorOwned : cursorSpan;
                    if (TryParsePngIcon(cursorData, out uint parsedWidth, out uint parsedHeight))
                    {
                        isPng = true;
                        pngWidth = parsedWidth;
                        pngHeight = parsedHeight;
                    }
                }
                else
                {
                    hasMissingCursors = true;
                }

                entries.Add(new ResourceCursorEntryInfo(
                    width,
                    height,
                    hotspotX,
                    hotspotY,
                    bytesInRes,
                    resourceId,
                    isPng,
                    pngWidth,
                    pngHeight));
            }

            group = new ResourceCursorGroupInfo(
                entry.NameId,
                entry.LanguageId,
                reserved,
                type,
                count,
                entrySize,
                headerValid,
                entriesTruncated,
                entries.ToArray());
            return true;
        }

        private static bool TryReadGroupResourceHeader(
            byte[] groupData,
            ushort expectedType,
            out ushort reserved,
            out ushort type,
            out ushort count,
            out int entrySize,
            out int parsedCount,
            out bool headerValid,
            out bool entriesTruncated)
        {
            reserved = 0;
            type = 0;
            count = 0;
            entrySize = 14;
            parsedCount = 0;
            headerValid = false;
            entriesTruncated = false;

            if (groupData == null || groupData.Length < 6)
            {
                return false;
            }

            reserved = ReadUInt16(groupData, 0);
            type = ReadUInt16(groupData, 2);
            count = ReadUInt16(groupData, 4);
            headerValid = reserved == 0 && type == expectedType;

            if (count == 0)
            {
                return false;
            }

            int available = groupData.Length - 6;
            if (available < 14)
            {
                return false;
            }

            if (available % count == 0)
            {
                int candidate = available / count;
                if (candidate >= 14)
                {
                    entrySize = candidate;
                }
            }

            parsedCount = Math.Min(count, available / entrySize);
            entriesTruncated = parsedCount < count;
            return parsedCount > 0;
        }

        private static bool TryParseBitmapInfoHeader(
            ReadOnlySpan<byte> data,
            out int width,
            out int height,
            out ushort bitCount,
            out uint compression,
            out uint imageSize)
        {
            width = 0;
            height = 0;
            bitCount = 0;
            compression = 0;
            imageSize = 0;

            if (data.Length < 40)
            {
                return false;
            }

            uint headerSize = ReadUInt32(data, 0);
            if (headerSize < 40)
            {
                return false;
            }

            width = unchecked((int)ReadUInt32(data, 4));
            height = unchecked((int)ReadUInt32(data, 8));
            bitCount = ReadUInt16(data, 14);
            compression = ReadUInt32(data, 16);
            imageSize = ReadUInt32(data, 20);
            return width != 0 && height != 0;
        }

        private static bool TryParseIconResource(
            ReadOnlySpan<byte> data,
            out int width,
            out int height,
            out ushort bitCount,
            out bool isPng,
            out uint pngWidth,
            out uint pngHeight)
        {
            width = 0;
            height = 0;
            bitCount = 0;
            isPng = false;
            pngWidth = 0;
            pngHeight = 0;

            if (data.Length == 0)
            {
                return false;
            }

            if (TryParsePngIcon(data, out uint parsedWidth, out uint parsedHeight))
            {
                isPng = true;
                pngWidth = parsedWidth;
                pngHeight = parsedHeight;
                width = (int)parsedWidth;
                height = (int)parsedHeight;
                return true;
            }

            if (TryParseBitmapInfoHeader(data, out int dibWidth, out int dibHeight, out ushort dibBitCount, out uint _compression, out uint _imageSize))
            {
                width = dibWidth;
                height = (dibHeight > 0 && (dibHeight % 2) == 0) ? dibHeight / 2 : dibHeight;
                bitCount = dibBitCount;
                return true;
            }

            return false;
        }

        private static bool TryParseCursorResource(
            ReadOnlySpan<byte> data,
            out ushort hotspotX,
            out ushort hotspotY,
            out int width,
            out int height,
            out ushort bitCount,
            out bool isPng,
            out uint pngWidth,
            out uint pngHeight)
        {
            hotspotX = 0;
            hotspotY = 0;
            width = 0;
            height = 0;
            bitCount = 0;
            isPng = false;
            pngWidth = 0;
            pngHeight = 0;

            if (data.Length < 4)
            {
                return false;
            }

            hotspotX = ReadUInt16(data, 0);
            hotspotY = ReadUInt16(data, 2);
            ReadOnlySpan<byte> imageData = data.Slice(4);
            if (imageData.Length == 0)
            {
                return false;
            }

            if (TryParsePngIcon(imageData, out uint parsedWidth, out uint parsedHeight))
            {
                isPng = true;
                pngWidth = parsedWidth;
                pngHeight = parsedHeight;
                width = (int)parsedWidth;
                height = (int)parsedHeight;
                return true;
            }

            if (TryParseBitmapInfoHeader(imageData, out int dibWidth, out int dibHeight, out ushort dibBitCount, out uint _compression, out uint _imageSize))
            {
                width = dibWidth;
                height = (dibHeight > 0 && (dibHeight % 2) == 0) ? dibHeight / 2 : dibHeight;
                bitCount = dibBitCount;
                return true;
            }

            return false;
        }

        private static string GetBitmapCompressionName(uint compression)
        {
            switch (compression)
            {
                case 0: return "BI_RGB";
                case 1: return "BI_RLE8";
                case 2: return "BI_RLE4";
                case 3: return "BI_BITFIELDS";
                case 4: return "BI_JPEG";
                case 5: return "BI_PNG";
                case 6: return "BI_ALPHABITFIELDS";
                default: return string.Format(CultureInfo.InvariantCulture, "0x{0:X}", compression);
            }
        }

        private static byte[] BuildIconFile(List<IconEntryInfo> entries, List<byte[]> images)
        {
            int count = Math.Min(entries.Count, images.Count);
            if (count == 0)
            {
                return Array.Empty<byte>();
            }

            int headerSize = 6 + (count * 16);
            int imageSize = 0;
            for (int i = 0; i < count; i++)
            {
                imageSize += images[i]?.Length ?? 0;
            }

            byte[] result = new byte[headerSize + imageSize];
            WriteUInt16(result, 0, 0);
            WriteUInt16(result, 2, 1);
            WriteUInt16(result, 4, (ushort)count);

            int imageOffset = headerSize;
            for (int i = 0; i < count; i++)
            {
                IconEntryInfo entry = entries[i];
                byte[] image = images[i] ?? Array.Empty<byte>();

                int entryOffset = 6 + (i * 16);
                result[entryOffset] = entry.Width;
                result[entryOffset + 1] = entry.Height;
                result[entryOffset + 2] = entry.ColorCount;
                result[entryOffset + 3] = entry.Reserved;
                WriteUInt16(result, entryOffset + 4, entry.Planes);
                WriteUInt16(result, entryOffset + 6, entry.BitCount);
                WriteUInt32(result, entryOffset + 8, (uint)image.Length);
                WriteUInt32(result, entryOffset + 12, (uint)imageOffset);

                if (image.Length > 0)
                {
                    Buffer.BlockCopy(image, 0, result, imageOffset, image.Length);
                }

                imageOffset += image.Length;
            }

            return result;
        }

        private static bool TryParsePngIcon(ReadOnlySpan<byte> data, out uint width, out uint height)
        {
            width = 0;
            height = 0;
            ReadOnlySpan<byte> signature = new byte[]
            {
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
            };

            if (data.Length < 24 || !data.StartsWith(signature))
            {
                return false;
            }

            // PNG IHDR chunk is expected at offset 8+4 (length) +4 (type)
            int ihdrOffset = 8;
            if (ihdrOffset + 8 > data.Length)
            {
                return false;
            }

            ReadOnlySpan<byte> chunkType = data.Slice(ihdrOffset + 4, 4);
            if (!chunkType.SequenceEqual(new byte[] { (byte)'I', (byte)'H', (byte)'D', (byte)'R' }))
            {
                return false;
            }

            if (ihdrOffset + 16 > data.Length)
            {
                return false;
            }

            width = ReadUInt32BigEndian(data, ihdrOffset + 8);
            height = ReadUInt32BigEndian(data, ihdrOffset + 12);
            return width > 0 && height > 0;
        }

        private static string DetectFontFormat(ReadOnlySpan<byte> data)
        {
            if (data.Length >= 4)
            {
                if (data[0] == 0x00 && data[1] == 0x01 && data[2] == 0x00 && data[3] == 0x00)
                {
                    return "TrueType";
                }

                if (data[0] == (byte)'O' && data[1] == (byte)'T' && data[2] == (byte)'T' && data[3] == (byte)'O')
                {
                    return "OpenType";
                }

                if (data[0] == (byte)'t' && data[1] == (byte)'t' && data[2] == (byte)'c' && data[3] == (byte)'f')
                {
                    return "TrueTypeCollection";
                }

                if (data[0] == (byte)'t' && data[1] == (byte)'r' && data[2] == (byte)'u' && data[3] == (byte)'e')
                {
                    return "TrueType";
                }

                if (data[0] == (byte)'t' && data[1] == (byte)'y' && data[2] == (byte)'p' && data[3] == (byte)'1')
                {
                    return "Type1";
                }
            }

            if (data.Length >= 2)
            {
                ushort version = ReadUInt16(data, 0);
                if (version == 0x0100 || version == 0x0200)
                {
                    return "FNT";
                }
            }

            return "Unknown";
        }

        private static string TryParseFontFaceName(ReadOnlySpan<byte> data, string format)
        {
            if (!string.Equals(format, "FNT", StringComparison.OrdinalIgnoreCase))
            {
                return string.Empty;
            }

            const int faceOffsetField = 105;
            if (data.Length <= faceOffsetField + 4)
            {
                return string.Empty;
            }

            uint faceOffset = ReadUInt32(data, faceOffsetField);
            if (faceOffset == 0 || faceOffset >= data.Length)
            {
                return string.Empty;
            }

            return ReadNullTerminatedAscii(data, (int)faceOffset, out int _);
        }

        private static bool TryParseFontDirectory(ReadOnlySpan<byte> data, out ushort count, out ResourceFontDirEntryInfo[] entries)
        {
            count = 0;
            entries = Array.Empty<ResourceFontDirEntryInfo>();
            if (data.Length < 2)
            {
                return false;
            }

            count = ReadUInt16(data, 0);
            if (count == 0)
            {
                return true;
            }

            int maxEntries = Math.Min(count, (ushort)256);
            List<ResourceFontDirEntryInfo> parsed = new List<ResourceFontDirEntryInfo>(maxEntries);
            int offset = 2;
            for (int i = 0; i < maxEntries && offset + 2 <= data.Length; i++)
            {
                ushort ordinal = ReadUInt16(data, offset);
                offset += 2;
                int entryStart = offset;
                string faceName = string.Empty;
                int entryEnd = entryStart;

                if (entryStart + 109 < data.Length)
                {
                    uint faceOffset = ReadUInt32(data, entryStart + 105);
                    if (faceOffset > 0 && entryStart + (int)faceOffset < data.Length)
                    {
                        faceName = ReadNullTerminatedAscii(data, entryStart + (int)faceOffset, out int bytesRead);
                        entryEnd = entryStart + (int)faceOffset + bytesRead;
                    }
                }

                if (string.IsNullOrWhiteSpace(faceName))
                {
                    faceName = ExtractAsciiString(data, entryStart, Math.Min(64, data.Length - entryStart));
                }

                parsed.Add(new ResourceFontDirEntryInfo(ordinal, faceName));

                if (entryEnd <= entryStart)
                {
                    entryEnd = entryStart + 32;
                }

                if (entryEnd <= offset)
                {
                    break;
                }

                offset = entryEnd;
                if (offset < data.Length && (offset % 2) != 0)
                {
                    offset++;
                }
            }

            entries = parsed.ToArray();
            return true;
        }

        private static bool TryParseDlgInit(ReadOnlySpan<byte> data, out ResourceDlgInitEntryInfo[] entries)
        {
            entries = Array.Empty<ResourceDlgInitEntryInfo>();
            if (data.Length < 6)
            {
                return false;
            }

            List<ResourceDlgInitEntryInfo> parsed = new List<ResourceDlgInitEntryInfo>();
            int offset = 0;
            while (offset + 6 <= data.Length)
            {
                ushort controlId = ReadUInt16(data, offset);
                ushort message = ReadUInt16(data, offset + 2);
                ushort length = ReadUInt16(data, offset + 4);
                offset += 6;

                if (controlId == 0 && message == 0 && length == 0)
                {
                    break;
                }

                int dataLength = Math.Min(length, (ushort)Math.Max(0, data.Length - offset));
                ReadOnlySpan<byte> payload = data.Slice(offset, dataLength);
                string preview = BuildHexPreview(payload, 32);
                parsed.Add(new ResourceDlgInitEntryInfo(controlId, message, (ushort)dataLength, preview));
                offset += dataLength;

                if (offset < data.Length && (offset % 2) != 0)
                {
                    offset++;
                }
            }

            if (parsed.Count == 0)
            {
                return false;
            }

            entries = parsed.ToArray();
            return true;
        }

        private static bool TryParseAnimatedResource(ReadOnlySpan<byte> data, out ResourceAnimatedInfo info)
        {
            info = null;
            if (data.Length < 12)
            {
                return false;
            }

            if (!(data[0] == (byte)'R' && data[1] == (byte)'I' && data[2] == (byte)'F' && data[3] == (byte)'F'))
            {
                return false;
            }

            if (!(data[8] == (byte)'A' && data[9] == (byte)'C' && data[10] == (byte)'O' && data[11] == (byte)'N'))
            {
                return false;
            }

            uint frameCount = 0;
            uint stepCount = 0;
            uint width = 0;
            uint height = 0;
            uint bitCount = 0;
            uint planes = 0;
            uint jifRate = 0;
            uint flags = 0;
            List<string> chunkTypes = new List<string>();

            int offset = 12;
            while (offset + 8 <= data.Length)
            {
                string chunkType = Encoding.ASCII.GetString(data.Slice(offset, 4));
                uint chunkSize = ReadUInt32(data, offset + 4);
                int chunkDataOffset = offset + 8;
                int next = chunkDataOffset + (int)chunkSize;
                if (next < chunkDataOffset || next > data.Length)
                {
                    break;
                }

                if (!chunkTypes.Contains(chunkType))
                {
                    chunkTypes.Add(chunkType);
                }

                if (string.Equals(chunkType, "anih", StringComparison.Ordinal) && chunkSize >= 36 && chunkDataOffset + 36 <= data.Length)
                {
                    frameCount = ReadUInt32(data, chunkDataOffset + 4);
                    stepCount = ReadUInt32(data, chunkDataOffset + 8);
                    width = ReadUInt32(data, chunkDataOffset + 12);
                    height = ReadUInt32(data, chunkDataOffset + 16);
                    bitCount = ReadUInt32(data, chunkDataOffset + 20);
                    planes = ReadUInt32(data, chunkDataOffset + 24);
                    jifRate = ReadUInt32(data, chunkDataOffset + 28);
                    flags = ReadUInt32(data, chunkDataOffset + 32);
                }

                offset = next;
                if ((offset % 2) != 0)
                {
                    offset++;
                }
            }

            info = new ResourceAnimatedInfo(
                0,
                0,
                "RIFF/ACON",
                frameCount,
                stepCount,
                width,
                height,
                bitCount,
                planes,
                jifRate,
                flags,
                chunkTypes.ToArray());
            return true;
        }

        private ResourceRcDataInfo BuildRcDataInfo(ResourceEntry entry, ReadOnlySpan<byte> data)
        {
            string text = DecodeTextResource(data);
            bool isText = IsLikelyText(text);
            string preview = isText ? BuildPreviewText(text, 160) : BuildHexPreview(data, 48);
            double entropy = ComputeShannonEntropy(data);
            RcDataFormatInfo formatInfo = DetectRcDataFormat(data, text);
            return new ResourceRcDataInfo(
                entry.NameId,
                entry.LanguageId,
                entry.Size,
                isText,
                formatInfo.Format,
                formatInfo.Details,
                preview,
                entropy);
        }

        private sealed class RcDataFormatInfo
        {
            public string Format { get; }
            public string Details { get; }

            public RcDataFormatInfo(string format, string details)
            {
                Format = format ?? string.Empty;
                Details = details ?? string.Empty;
            }
        }

        private static RcDataFormatInfo DetectRcDataFormat(ReadOnlySpan<byte> data, string text)
        {
            if (data.Length >= 2 && data[0] == 0x4D && data[1] == 0x5A)
            {
                return new RcDataFormatInfo("EmbeddedPE", "MZ header");
            }

            if (HasPrefix(data, new byte[] { 0x50, 0x4B, 0x03, 0x04 }))
            {
                return new RcDataFormatInfo("Zip", "Local file header");
            }

            if (HasPrefix(data, new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 }))
            {
                return new RcDataFormatInfo("Rar", "RAR signature");
            }

            if (HasPrefix(data, new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }))
            {
                return new RcDataFormatInfo("7-Zip", "7z signature");
            }

            if (HasPrefix(data, new byte[] { 0x1F, 0x8B }))
            {
                return new RcDataFormatInfo("GZip", string.Empty);
            }

            if (HasPrefix(data, new byte[] { 0x42, 0x5A, 0x68 }))
            {
                return new RcDataFormatInfo("BZip2", string.Empty);
            }

            if (HasPrefix(data, new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }))
            {
                return new RcDataFormatInfo("XZ", string.Empty);
            }

            if (HasPrefix(data, new byte[] { 0x89, 0x50, 0x4E, 0x47 }))
            {
                return new RcDataFormatInfo("PNG", string.Empty);
            }

            if (HasPrefix(data, new byte[] { 0x47, 0x49, 0x46, 0x38 }))
            {
                return new RcDataFormatInfo("GIF", string.Empty);
            }

            if (HasPrefix(data, new byte[] { 0x42, 0x4D }))
            {
                return new RcDataFormatInfo("BMP", string.Empty);
            }

            if (HasPrefix(data, new byte[] { 0x7F, 0x45, 0x4C, 0x46 }))
            {
                return new RcDataFormatInfo("ELF", string.Empty);
            }

            if (HasPrefix(data, new byte[] { 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00 }))
            {
                return new RcDataFormatInfo("SQLite", string.Empty);
            }

            if (HasPrefix(data, new byte[] { 0x4D, 0x53, 0x43, 0x46 }))
            {
                return new RcDataFormatInfo("CAB", "MSCF header");
            }

            if (TryDetectUnityBundle(data, out string unityFormat, out string unityDetails))
            {
                return new RcDataFormatInfo(unityFormat, unityDetails);
            }

            if (TryDetectFlatBuffers(data, out string flatDetails))
            {
                return new RcDataFormatInfo("FlatBuffers", flatDetails);
            }

            if (TryDetectProtobuf(data, out string protoDetails))
            {
                return new RcDataFormatInfo("Protobuf", protoDetails);
            }

            if (!string.IsNullOrWhiteSpace(text))
            {
                string trimmed = text.TrimStart();
                if (trimmed.StartsWith("{", StringComparison.Ordinal) || trimmed.StartsWith("[", StringComparison.Ordinal))
                {
                    if (TryParseJsonDetails(trimmed, out string format, out string details))
                    {
                        return new RcDataFormatInfo(format, details);
                    }

                    return new RcDataFormatInfo("JSON", string.Empty);
                }

                if (trimmed.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("<", StringComparison.Ordinal))
                {
                    if (TryParseManifestSchema(trimmed, out ManifestSchemaInfo schema))
                    {
                        string details = BuildManifestDetails(schema);
                        return new RcDataFormatInfo("XML-Manifest", details);
                    }

                    return new RcDataFormatInfo("XML", string.Empty);
                }

                return new RcDataFormatInfo("Text", string.Empty);
            }

            return new RcDataFormatInfo("Unknown", string.Empty);
        }

        private static bool TryDetectUnityBundle(ReadOnlySpan<byte> data, out string format, out string details)
        {
            format = string.Empty;
            details = string.Empty;

            if (data.Length < 7)
            {
                return false;
            }

            if (data[0] == 0x55 && data[1] == 0x6E && data[2] == 0x69 &&
                data[3] == 0x74 && data[4] == 0x79 && data[5] == 0x46 && data[6] == 0x53)
            {
                format = "UnityFS";
                details = TryParseUnityFsHeader(data);
                return true;
            }

            if (data[0] == 0x55 && data[1] == 0x6E && data[2] == 0x69 &&
                data[3] == 0x74 && data[4] == 0x79 && data[5] == 0x52 && data[6] == 0x61)
            {
                format = "UnityRaw";
                return true;
            }

            if (data[0] == 0x55 && data[1] == 0x6E && data[2] == 0x69 &&
                data[3] == 0x74 && data[4] == 0x79 && data[5] == 0x57 && data[6] == 0x65)
            {
                format = "UnityWeb";
                return true;
            }

            return false;
        }

        private static string TryParseUnityFsHeader(ReadOnlySpan<byte> data)
        {
            int offset = 7;
            if (offset < data.Length && data[offset] == 0)
            {
                offset++;
            }

            if (offset + 4 > data.Length)
            {
                return string.Empty;
            }

            uint version = ReadUInt32(data, offset);
            offset += 4;

            string unityVersion = ReadNullTerminatedAscii(data, offset, out int bytesRead);
            offset += bytesRead;
            string unityRevision = ReadNullTerminatedAscii(data, offset, out int bytesRead2);
            offset += bytesRead2;

            string details = "ver=" + version.ToString(CultureInfo.InvariantCulture);
            if (!string.IsNullOrWhiteSpace(unityVersion))
            {
                details = AppendNote(details, "unity=" + unityVersion);
            }
            if (!string.IsNullOrWhiteSpace(unityRevision))
            {
                details = AppendNote(details, "rev=" + unityRevision);
            }

            return details;
        }

        private static bool TryDetectFlatBuffers(ReadOnlySpan<byte> data, out string details)
        {
            details = string.Empty;
            if (data.Length < 8)
            {
                return false;
            }

            int rootOffset = unchecked((int)ReadUInt32(data, 0));
            if (rootOffset < 4 || rootOffset > data.Length - 4)
            {
                return false;
            }

            int vtableOffset = unchecked((int)ReadUInt32(data, rootOffset));
            if (vtableOffset >= 0)
            {
                return false;
            }

            int vtablePos = rootOffset - vtableOffset;
            if (vtablePos < 0 || vtablePos + 4 > data.Length)
            {
                return false;
            }

            ushort vtableLength = ReadUInt16(data, vtablePos);
            ushort objectSize = ReadUInt16(data, vtablePos + 2);
            if (vtableLength < 4 || objectSize < 4)
            {
                return false;
            }

            if (rootOffset + objectSize > data.Length)
            {
                return false;
            }

            string fileId = string.Empty;
            if (data.Length >= 8)
            {
                ReadOnlySpan<byte> idBytes = data.Slice(4, 4);
                if (IsAsciiIdentifier(idBytes))
                {
                    fileId = Encoding.ASCII.GetString(idBytes);
                }
            }

            details = "root=0x" + rootOffset.ToString("X", CultureInfo.InvariantCulture) +
                      " vtbl=" + vtableLength.ToString(CultureInfo.InvariantCulture) +
                      " obj=" + objectSize.ToString(CultureInfo.InvariantCulture);
            if (!string.IsNullOrWhiteSpace(fileId))
            {
                details = AppendNote(details, "id=" + fileId);
            }

            return true;
        }

        private static bool TryDetectProtobuf(ReadOnlySpan<byte> data, out string details)
        {
            details = string.Empty;
            if (data.Length < 2)
            {
                return false;
            }

            int offset = 0;
            int fields = 0;
            while (offset < data.Length && fields < 4)
            {
                if (!TryReadVarint(data, ref offset, out ulong tag))
                {
                    break;
                }

                if (tag == 0)
                {
                    break;
                }

                int wireType = (int)(tag & 0x7);
                if (wireType > 5 || wireType == 3 || wireType == 4)
                {
                    break;
                }

                fields++;
                switch (wireType)
                {
                    case 0:
                        if (!TryReadVarint(data, ref offset, out _))
                        {
                            return false;
                        }
                        break;
                    case 1:
                        offset += 8;
                        break;
                    case 2:
                        if (!TryReadVarint(data, ref offset, out ulong length))
                        {
                            return false;
                        }
                        if (length > (ulong)(data.Length - offset))
                        {
                            return false;
                        }
                        offset += (int)length;
                        break;
                    case 5:
                        offset += 4;
                        break;
                }

                if (offset > data.Length)
                {
                    return false;
                }
            }

            if (fields >= 2)
            {
                details = "fields=" + fields.ToString(CultureInfo.InvariantCulture) + " (heuristic)";
                return true;
            }

            return false;
        }

        private static bool TryReadVarint(ReadOnlySpan<byte> data, ref int offset, out ulong value)
        {
            value = 0;
            int shift = 0;
            while (offset < data.Length && shift <= 63)
            {
                byte b = data[offset++];
                value |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                {
                    return true;
                }
                shift += 7;
            }

            return false;
        }

        private static bool IsAsciiIdentifier(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                return false;
            }

            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                bool isAlpha = (b >= (byte)'A' && b <= (byte)'Z') ||
                               (b >= (byte)'a' && b <= (byte)'z');
                bool isDigit = b >= (byte)'0' && b <= (byte)'9';
                if (!isAlpha && !isDigit && b != (byte)'_')
                {
                    return false;
                }
            }

            return true;
        }

        private static bool TryParseJsonDetails(string text, out string format, out string details)
        {
            format = string.Empty;
            details = string.Empty;
            if (string.IsNullOrWhiteSpace(text) || text.Length > 65536)
            {
                return false;
            }

            try
            {
                using JsonDocument doc = JsonDocument.Parse(text, new JsonDocumentOptions { AllowTrailingCommas = true });
                JsonElement root = doc.RootElement;
                if (root.ValueKind == JsonValueKind.Object)
                {
                    if (root.TryGetProperty("$schema", out JsonElement schema))
                    {
                        format = "JSON-Schema";
                        details = "$schema=" + SafeJsonValue(schema);
                        if (root.TryGetProperty("title", out JsonElement title))
                        {
                            details = AppendNote(details, "title=" + SafeJsonValue(title));
                        }
                        if (root.TryGetProperty("type", out JsonElement type))
                        {
                            details = AppendNote(details, "type=" + SafeJsonValue(type));
                        }
                        if (root.TryGetProperty("properties", out JsonElement props) && props.ValueKind == JsonValueKind.Object)
                        {
                            details = AppendNote(details, "properties=" + props.EnumerateObject().Count().ToString(CultureInfo.InvariantCulture));
                        }
                        return true;
                    }

                    format = "JSON";
                    details = "keys=" + root.EnumerateObject().Count().ToString(CultureInfo.InvariantCulture);
                    return true;
                }

                if (root.ValueKind == JsonValueKind.Array)
                {
                    format = "JSON";
                    details = "arrayLength=" + root.GetArrayLength().ToString(CultureInfo.InvariantCulture);
                    return true;
                }
            }
            catch (JsonException)
            {
                return false;
            }

            return false;
        }

        private static string SafeJsonValue(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.String:
                    return element.GetString() ?? string.Empty;
                case JsonValueKind.Number:
                case JsonValueKind.True:
                case JsonValueKind.False:
                    return element.ToString();
                default:
                    return element.ValueKind.ToString();
            }
        }

        private static string BuildManifestDetails(ManifestSchemaInfo schema)
        {
            string details = string.Empty;
            if (!string.IsNullOrWhiteSpace(schema.RequestedExecutionLevel))
            {
                details = AppendNote(details, "requestedExecutionLevel=" + schema.RequestedExecutionLevel);
            }
            if (!string.IsNullOrWhiteSpace(schema.UiAccess))
            {
                details = AppendNote(details, "uiAccess=" + schema.UiAccess);
            }
            if (!string.IsNullOrWhiteSpace(schema.DpiAware))
            {
                details = AppendNote(details, "dpiAware=" + schema.DpiAware);
            }
            if (!string.IsNullOrWhiteSpace(schema.DpiAwareness))
            {
                details = AppendNote(details, "dpiAwareness=" + schema.DpiAwareness);
            }
            if (!string.IsNullOrWhiteSpace(schema.UiLanguage))
            {
                details = AppendNote(details, "uiLanguage=" + schema.UiLanguage);
            }
            if (!string.IsNullOrWhiteSpace(schema.LongPathAware))
            {
                details = AppendNote(details, "longPathAware=" + schema.LongPathAware);
            }
            if (!string.IsNullOrWhiteSpace(schema.ActiveCodePage))
            {
                details = AppendNote(details, "activeCodePage=" + schema.ActiveCodePage);
            }
            if (schema.SupportedOsGuids.Count > 0)
            {
                details = AppendNote(details, "supportedOS=" + string.Join(",", schema.SupportedOsGuids));
            }
            if (!string.IsNullOrWhiteSpace(schema.AssemblyIdentityName))
            {
                details = AppendNote(details, "assembly=" + schema.AssemblyIdentityName);
            }
            if (!string.IsNullOrWhiteSpace(schema.AssemblyIdentityVersion))
            {
                details = AppendNote(details, "version=" + schema.AssemblyIdentityVersion);
            }

            if (string.IsNullOrWhiteSpace(details))
            {
                details = schema.IsValid ? "valid" : "invalid";
            }

            return details;
        }

        private static ResourceRawInfo BuildResourceRawInfo(ResourceEntry entry, ReadOnlySpan<byte> data)
        {
            string text = DecodeTextResource(data);
            bool isText = IsLikelyText(text);
            string preview = isText ? BuildPreviewText(text, 160) : BuildHexPreview(data, 48);
            string hash = data.Length > 0 ? ToHex(SHA256.HashData(data)) : string.Empty;
            return new ResourceRawInfo(entry.NameId, entry.LanguageId, entry.Size, hash, isText, preview);
        }

        internal static string DetectRcDataFormatForTest(byte[] data)
        {
            if (data == null)
            {
                return string.Empty;
            }

            string text = DecodeTextResource(data);
            return DetectRcDataFormat(data, text).Format;
        }

        internal static bool TryDetectRcDataFormatForTest(byte[] data, out string format, out string details)
        {
            format = string.Empty;
            details = string.Empty;
            if (data == null)
            {
                return false;
            }

            string text = DecodeTextResource(data);
            RcDataFormatInfo info = DetectRcDataFormat(data, text);
            format = info.Format;
            details = info.Details;
            return true;
        }

        internal static bool TryParseArchitectureHeaderForTest(
            byte[] data,
            out uint magic,
            out uint majorVersion,
            out uint minorVersion,
            out uint sizeOfData,
            out uint firstEntryRva,
            out uint numberOfEntries)
        {
            if (data == null)
            {
                magic = 0;
                majorVersion = 0;
                minorVersion = 0;
                sizeOfData = 0;
                firstEntryRva = 0;
                numberOfEntries = 0;
                return false;
            }

            return TryParseArchitectureHeader(
                data,
                out magic,
                out majorVersion,
                out minorVersion,
                out sizeOfData,
                out firstEntryRva,
                out numberOfEntries);
        }

        internal static bool TryParseGlobalPtrValueForTest(byte[] data, bool isPe32Plus, out ulong value)
        {
            value = 0;
            if (data == null)
            {
                return false;
            }

            int pointerSize = isPe32Plus ? 8 : 4;
            if (data.Length < pointerSize)
            {
                return false;
            }

            value = isPe32Plus ? BitConverter.ToUInt64(data, 0) : BitConverter.ToUInt32(data, 0);
            return true;
        }

        internal static bool TryCountIatEntriesForTest(byte[] data, bool isPe32Plus, out uint nonZero, out uint zero)
        {
            nonZero = 0;
            zero = 0;
            if (data == null)
            {
                return false;
            }

            uint entrySize = isPe32Plus ? 8u : 4u;
            if (data.Length < entrySize)
            {
                return false;
            }

            uint alignedSize = (uint)data.Length - ((uint)data.Length % entrySize);
            int offset = 0;
            while (offset + entrySize <= alignedSize)
            {
                ulong value = entrySize == 8
                    ? BitConverter.ToUInt64(data, offset)
                    : BitConverter.ToUInt32(data, offset);
                if (value == 0)
                {
                    zero++;
                }
                else
                {
                    nonZero++;
                }
                offset += (int)entrySize;
            }

            return true;
        }

        internal static bool TryComputeTlsRawDataInfoForTest(
            byte[] data,
            out string hash,
            out bool isText,
            out string preview)
        {
            hash = string.Empty;
            preview = string.Empty;
            isText = false;

            if (data == null || data.Length == 0)
            {
                return false;
            }

            BuildRawDataPreview(data, out isText, out preview);
            hash = ToHex(SHA256.HashData(data));
            return true;
        }

        internal static TlsTemplateInfo BuildTlsTemplateInfoForTest(
            ulong startRaw,
            ulong endRaw,
            uint rawDataSize,
            uint zeroFill,
            int alignmentBytes,
            bool rawDataMapped,
            string rawDataHash,
            bool rawDataPreviewIsText,
            string rawDataPreview)
        {
            return BuildTlsTemplateInfo(
                startRaw,
                endRaw,
                rawDataSize,
                zeroFill,
                alignmentBytes,
                rawDataMapped,
                rawDataHash,
                rawDataPreviewIsText,
                rawDataPreview);
        }

        internal static TlsIndexInfo BuildTlsIndexInfoForTest(
            ulong address,
            uint rva,
            bool hasRva,
            bool isMapped,
            string sectionName,
            uint sectionRva,
            uint sectionOffset,
            bool hasValue,
            uint value)
        {
            return BuildTlsIndexInfoCore(
                address,
                rva,
                hasRva,
                isMapped,
                sectionName,
                sectionRva,
                sectionOffset,
                hasValue,
                value);
        }

        internal static string GetRelocationTypeNameForTest(ushort machine, int type)
        {
            return GetRelocationTypeName((MachineTypes)machine, type);
        }

        internal static string GetCoffRelocationTypeNameForTest(ushort machine, ushort type)
        {
            return GetCoffRelocationTypeName((MachineTypes)machine, type);
        }

        internal static string GetMachineNameForTest(ushort machine)
        {
            return GetMachineName(machine);
        }

        internal static bool IsRelocationTypeReservedForTest(ushort machine, int type)
        {
            return IsRelocationTypeReserved((MachineTypes)machine, type);
        }

        internal static string GetRelocationTypeNameForTest(int type)
        {
            return GetRelocationTypeName(MachineTypes.IMAGE_FILE_MACHINE_UNKNOWN, type);
        }

        internal static bool IsRelocationTypeReservedForTest(int type)
        {
            return IsRelocationTypeReserved(MachineTypes.IMAGE_FILE_MACHINE_UNKNOWN, type);
        }

        internal static RelocationAnomalySummary BuildRelocationAnomalySummaryForTest(
            BaseRelocationBlockInfo[] blocks,
            int zeroSizedBlocks,
            int emptyBlocks,
            int invalidBlocks,
            int orphanedBlocks,
            int discardableBlocks)
        {
            int reservedTypeCount = 0;
            int outOfRangeEntryCount = 0;
            int unmappedEntryCount = 0;
            if (blocks != null)
            {
                foreach (BaseRelocationBlockInfo block in blocks)
                {
                    reservedTypeCount += block.ReservedTypeCount;
                    outOfRangeEntryCount += block.OutOfRangeCount;
                    unmappedEntryCount += block.UnmappedCount;
                }
            }

            return BuildRelocationAnomalySummary(
                zeroSizedBlocks,
                emptyBlocks,
                invalidBlocks,
                orphanedBlocks,
                discardableBlocks,
                reservedTypeCount,
                outOfRangeEntryCount,
                unmappedEntryCount);
        }

        internal static CoffAuxSymbolInfo[] DecodeCoffAuxSymbolsForTest(
            string name,
            ushort type,
            byte storageClass,
            byte auxCount,
            byte[] auxData,
            short sectionNumber = 0,
            uint symbolValue = 0)
        {
            return DecodeCoffAuxSymbols(name ?? string.Empty, type, storageClass, auxCount, auxData, sectionNumber, symbolValue);
        }

        internal static string GetCoffStorageClassNameForTest(byte storageClass)
        {
            return GetCoffStorageClassName(storageClass);
        }

        internal static SubsystemInfo BuildSubsystemInfoForTest(ushort subsystem)
        {
            return BuildSubsystemInfo((Subsystem)subsystem);
        }

        internal static string GetCoffSymbolScopeNameForTest(short sectionNumber, byte storageClass)
        {
            return GetCoffSymbolScopeName(sectionNumber, storageClass);
        }

        private static bool IsLikelyText(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            int total = 0;
            int printable = 0;
            int limit = Math.Min(text.Length, 256);
            for (int i = 0; i < limit; i++)
            {
                char c = text[i];
                total++;
                if (!char.IsControl(c) || c == '\r' || c == '\n' || c == '\t')
                {
                    printable++;
                }
            }

            return total > 0 && printable >= (total * 0.75);
        }

        private static string BuildPreviewText(string text, int maxLength)
        {
            if (string.IsNullOrEmpty(text))
            {
                return string.Empty;
            }

            string normalized = text.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ").Trim();
            if (normalized.Length <= maxLength)
            {
                return normalized;
            }

            return normalized.Substring(0, maxLength) + "...";
        }

        private static string BuildHexPreview(ReadOnlySpan<byte> data, int maxBytes)
        {
            if (data.Length == 0)
            {
                return string.Empty;
            }

            int length = Math.Min(data.Length, maxBytes);
            StringBuilder sb = new StringBuilder(length * 2);
            for (int i = 0; i < length; i++)
            {
                sb.Append(data[i].ToString("X2", CultureInfo.InvariantCulture));
            }
            if (data.Length > length)
            {
                sb.Append("...");
            }

            return sb.ToString();
        }

        private static void BuildRawDataPreview(ReadOnlySpan<byte> data, out bool isText, out string preview)
        {
            string text = DecodeTextResource(data);
            isText = IsLikelyText(text);
            preview = isText ? BuildPreviewText(text, 160) : BuildHexPreview(data, 48);
        }

        private static string ExtractAsciiString(ReadOnlySpan<byte> data, int offset, int maxLength)
        {
            if (offset < 0 || offset >= data.Length || maxLength <= 0)
            {
                return string.Empty;
            }

            int length = Math.Min(maxLength, data.Length - offset);
            int end = offset;
            while (end < offset + length && data[end] != 0)
            {
                end++;
            }

            if (end == offset)
            {
                return string.Empty;
            }

            return Encoding.ASCII.GetString(data.Slice(offset, end - offset)).TrimEnd('\0', ' ');
        }

        internal static bool TryParsePngIconForTest(byte[] data, out uint width, out uint height)
        {
            return TryParsePngIcon(data, out width, out height);
        }

        internal static string DetectFontFormatForTest(byte[] data)
        {
            return DetectFontFormat(data);
        }

        internal static bool TryParseFontDirectoryForTest(byte[] data, out ushort count, out ResourceFontDirEntryInfo[] entries)
        {
            return TryParseFontDirectory(data, out count, out entries);
        }

        internal static bool TryParseDlgInitForTest(byte[] data, out ResourceDlgInitEntryInfo[] entries)
        {
            return TryParseDlgInit(data, out entries);
        }

        internal static bool TryParseAnimatedResourceForTest(byte[] data, out ResourceAnimatedInfo info)
        {
            return TryParseAnimatedResource(data, out info);
        }

        internal static bool TryParsePogoDataForTest(byte[] data, out DebugPogoInfo info)
        {
            return TryParsePogoData(data, out info);
        }

        internal static bool TryParseDebugCoffDataForTest(byte[] data, out DebugCoffInfo info)
        {
            return TryParseDebugCoffData(data, out info);
        }

        internal static bool TryParseDebugClsidDataForTest(byte[] data, out DebugClsidInfo info)
        {
            return TryParseDebugClsidData(data, out info);
        }

        internal static bool TryParseDebugMiscDataForTest(byte[] data, out DebugMiscInfo info)
        {
            return TryParseDebugMiscData(data, out info);
        }

        internal static bool TryParseOmapDataForTest(byte[] data, out DebugOmapInfo info)
        {
            return TryParseOmapData(data, out info);
        }

        internal static bool TryParseReproDataForTest(byte[] data, out DebugReproInfo info)
        {
            return TryParseReproData(data, out info);
        }

        internal static ResourceRawInfo BuildResourceRawInfoForTest(ResourceEntry entry, byte[] data)
        {
            if (entry == null || data == null)
            {
                return null;
            }

            return BuildResourceRawInfo(entry, data);
        }

        internal static EnclaveImportInfo ParseEnclaveImportForTest(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(data);
            uint matchType = ReadUInt32Safe(span, 0);
            uint minimumSecurityVersion = ReadUInt32Safe(span, 4);
            string uniqueOrAuthorId = ReadBytesHexSafe(span, 8, 32);
            string familyId = ReadBytesHexSafe(span, 40, 16);
            string imageId = ReadBytesHexSafe(span, 56, 16);
            uint importNameRva = ReadUInt32Safe(span, 72);
            uint reserved = ReadUInt32Safe(span, 76);

            return new EnclaveImportInfo(
                0,
                matchType,
                GetEnclaveImportMatchTypeName(matchType),
                minimumSecurityVersion,
                uniqueOrAuthorId,
                familyId,
                imageId,
                importNameRva,
                string.Empty,
                reserved);
        }

        internal static bool TryParseVcFeatureDataForTest(byte[] data, out DebugVcFeatureInfo info)
        {
            return TryParseVcFeatureData(data, out info);
        }

        internal static bool TryParseExDllCharacteristicsDataForTest(byte[] data, out DebugExDllCharacteristicsInfo info)
        {
            return TryParseExDllCharacteristicsData(data, out info);
        }

        internal static bool TryParseFpoDataForTest(byte[] data, out DebugFpoInfo info)
        {
            return TryParseFpoData(data, out info);
        }

        internal static bool TryParseDebugBorlandDataForTest(byte[] data, out DebugBorlandInfo info)
        {
            return TryParseDebugBorlandData(data, out info);
        }

        internal static bool TryParseDebugReservedDataForTest(byte[] data, out DebugReservedInfo info)
        {
            return TryParseDebugReservedData(data, out info);
        }

        internal static bool TryParseDebugEmbeddedPortablePdbDataForTest(byte[] data, out DebugEmbeddedPortablePdbInfo info)
        {
            return TryParseDebugEmbeddedPortablePdbData(data, out info);
        }

        internal static bool TryParseDebugSpgoDataForTest(byte[] data, out DebugSpgoInfo info)
        {
            return TryParseDebugSpgoData(data, out info);
        }

        internal static bool TryParseDebugPdbHashDataForTest(byte[] data, out DebugPdbHashInfo info)
        {
            return TryParseDebugPdbHashData(data, out info);
        }

        internal static DebugRawInfo BuildDebugRawInfoForTest(byte[] data)
        {
            return BuildDebugRawInfo(data);
        }

        internal static bool TryParseDosRelocationsForTest(byte[] data, out DosRelocationInfo info)
        {
            info = null;
            if (data == null)
            {
                return false;
            }

            int headerSize = Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));
            if (data.Length < headerSize)
            {
                return false;
            }

            byte[] headerBytes = new byte[headerSize];
            Array.Copy(data, 0, headerBytes, 0, headerBytes.Length);
            IMAGE_DOS_HEADER header = headerBytes.ToStructure<IMAGE_DOS_HEADER>();
            return TryParseDosRelocationsFromBuffer(header, data, out info);
        }

        internal static bool TryComputeRvaFromPointerForTest(ulong value, ulong imageBase, uint sizeOfImage, out uint rva, out string kind)
        {
            return TryComputeRvaFromPointer(value, imageBase, sizeOfImage, out rva, out kind);
        }

        internal static bool TryParseArchitectureDirectoryDataForTest(byte[] data, out ArchitectureDirectoryInfo info)
        {
            info = null;
            if (data == null || data.Length < 24)
            {
                return false;
            }

            if (!TryParseArchitectureHeader(data, out uint magic, out uint major, out uint minor, out uint sizeOfData, out uint firstEntryRva, out uint numberOfEntries))
            {
                return false;
            }

            List<ArchitectureDirectoryEntryInfo> entries = new List<ArchitectureDirectoryEntryInfo>();
            int parsedCount = 0;
            bool truncated = false;
            uint entrySize = 8;
            if (numberOfEntries > 0 && firstEntryRva < data.Length)
            {
                uint maxEntriesBySize = sizeOfData > 0 ? sizeOfData / entrySize : 0;
                uint toRead = maxEntriesBySize > 0 ? Math.Min(numberOfEntries, maxEntriesBySize) : numberOfEntries;
                int maxEntries = 64;
                truncated = toRead > maxEntries;
                int readCount = (int)Math.Min(toRead, (uint)maxEntries);
                int offset = (int)firstEntryRva;
                for (int i = 0; i < readCount && offset + entrySize <= data.Length; i++)
                {
                    uint fixupRva = ReadUInt32(data, offset);
                    uint newInst = ReadUInt32(data, offset + 4);
                    entries.Add(new ArchitectureDirectoryEntryInfo(fixupRva, newInst, false, string.Empty));
                    offset += (int)entrySize;
                }
                parsedCount = entries.Count;
            }

            info = new ArchitectureDirectoryInfo(
                0,
                (uint)data.Length,
                true,
                string.Empty,
                true,
                magic,
                major,
                minor,
                sizeOfData,
                firstEntryRva,
                numberOfEntries,
                parsedCount,
                truncated,
                entries.ToArray());
            return true;
        }

        internal static bool TryParseIatSamplesForTest(byte[] data, bool isPe32Plus, ulong imageBase, uint sizeOfImage, out IatEntryInfo[] samples, out uint mappedCount)
        {
            samples = Array.Empty<IatEntryInfo>();
            mappedCount = 0;
            if (data == null)
            {
                return false;
            }

            uint entrySize = isPe32Plus ? 8u : 4u;
            if (data.Length < entrySize)
            {
                return false;
            }

            uint alignedSize = (uint)data.Length - ((uint)data.Length % entrySize);
            int maxSamples = 16;
            int readCount = (int)Math.Min(alignedSize / entrySize, (uint)maxSamples);
            List<IatEntryInfo> local = new List<IatEntryInfo>(readCount);
            int offset = 0;
            for (int i = 0; i < readCount; i++)
            {
                ulong value = entrySize == 8
                    ? BitConverter.ToUInt64(data, offset)
                    : BitConverter.ToUInt32(data, offset);
                offset += (int)entrySize;

                bool isZero = value == 0;
                bool hasRva = false;
                uint rva = 0;
                string kind = string.Empty;
                if (!isZero && TryComputeRvaFromPointer(value, imageBase, sizeOfImage, out rva, out kind))
                {
                    hasRva = true;
                    mappedCount++;
                }

                local.Add(new IatEntryInfo((uint)i, value, isZero, hasRva, rva, kind, false, string.Empty));
            }

            samples = local.ToArray();
            return true;
        }

        internal static bool TryParsePdbInfoForTest(string path, out PdbInfo info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return false;
            }

            try
            {
                using FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                return TryParseMsf(path, stream, out info);
            }
            catch (Exception)
            {
                return false;
            }
        }

        internal static bool TryParsePdbDbiStreamForTest(byte[] data, out PdbDbiInfo info)
        {
            info = null;
            if (data == null)
            {
                return false;
            }

            return TryParseDbiStream(data, out info, out _);
        }

        internal static bool TryParsePdbTpiStreamForTest(byte[] data, bool isIpi, out PdbTpiInfo info)
        {
            info = null;
            if (data == null)
            {
                return false;
            }

            return TryParseTpiStream(data, isIpi, out info, out _);
        }

        internal static bool TryParsePdbGsiStreamForTest(byte[] data, out PdbGsiInfo info)
        {
            info = null;
            if (data == null)
            {
                return false;
            }

            List<string> names = new List<string>();
            info = TryParseGsiStream(data, "Publics", 0, (uint)data.Length, out _, names);
            return info != null;
        }

        internal static bool TryParsePdbSymbolRecordsForTest(byte[] data, out int totalCount, out PdbSymbolRecordInfo[] records, out string note)
        {
            totalCount = 0;
            records = Array.Empty<PdbSymbolRecordInfo>();
            note = string.Empty;
            if (data == null)
            {
                return false;
            }

            return TryParsePdbSymbolRecords(data, out totalCount, out records, out note);
        }

        internal static bool TryParseMethodBodySummaryForTest(byte[] data, out ClrMethodBodySummaryInfo summary)
        {
            summary = null;
            if (data == null)
            {
                return false;
            }

            if (!TryParseMethodBodyInfoFromSpan(data, out MethodBodyInfo info))
            {
                return false;
            }

            int tiny = info.IsTiny ? 1 : 0;
            int fat = info.IsFat ? 1 : 0;
            summary = new ClrMethodBodySummaryInfo(
                1,
                1,
                tiny,
                fat,
                0,
                info.CodeSize,
                info.CodeSize,
                info.CodeSize,
                info.ExceptionClauseCount,
                info.ExceptionClauseCatchCount,
                info.ExceptionClauseFinallyCount,
                info.ExceptionClauseFaultCount,
                info.ExceptionClauseFilterCount,
                info.ExceptionClauseInvalidCount);
            return true;
        }

        internal static bool TryReadCodeIntegrityForTest(byte[] data, out LoadConfigCodeIntegrityInfo info)
        {
            info = null;
            if (data == null)
            {
                return false;
            }

            int offset = 0;
            return TryReadCodeIntegrity(data, ref offset, data.Length, out info);
        }

        internal static DynamicRelocationMetadataInfo ParseDynamicRelocationMetadataForTest(byte[] data)
        {
            return ParseDynamicRelocationMetadataBlob(
                data ?? Array.Empty<byte>(),
                0,
                true,
                "Test",
                0,
                string.Empty);
        }

        internal static ChpeMetadataInfo ParseChpeMetadataForTest(byte[] data)
        {
            return ParseChpeMetadataBlob(
                data ?? Array.Empty<byte>(),
                0,
                true,
                "Test",
                0,
                string.Empty);
        }

        internal static VolatileMetadataInfo ParseVolatileMetadataForTest(byte[] data)
        {
            return ParseVolatileMetadataBlob(
                data ?? Array.Empty<byte>(),
                0,
                true,
                "Test",
                0,
                string.Empty);
        }

        internal static bool TryParseLoadConfigVersionInfoForTest(byte[] data, bool isPe32Plus, out LoadConfigVersionInfo info)
        {
            info = null;
            if (data == null || data.Length < 4)
            {
                return false;
            }

            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(data);
            int offset = 0;
            uint size = ReadUInt32(span, offset);
            offset += 4;

            int limit = span.Length;
            if (size > 0 && size < (uint)limit)
            {
                limit = (int)size;
            }

            if (!TryAdvance(ref offset, limit, 4)) return false; // TimeDateStamp
            if (!TryAdvance(ref offset, limit, 2)) return false; // Major
            if (!TryAdvance(ref offset, limit, 2)) return false; // Minor
            if (!TryAdvance(ref offset, limit, 4)) return false; // GlobalFlagsClear
            if (!TryAdvance(ref offset, limit, 4)) return false; // GlobalFlagsSet
            if (!TryAdvance(ref offset, limit, 4)) return false; // CriticalSectionDefaultTimeout

            int pointerSize = isPe32Plus ? 8 : 4;
            if (!TryAdvance(ref offset, limit, pointerSize * 5)) return false; // DeCommit/LockPrefix/MaxAlloc/VMThreshold
            if (!TryAdvance(ref offset, limit, 4)) return false; // ProcessHeapFlags
            if (!TryAdvance(ref offset, limit, pointerSize)) return false; // ProcessAffinityMask
            if (!TryAdvance(ref offset, limit, 2)) return false; // CsdVersion
            if (!TryAdvance(ref offset, limit, 2)) return false; // DependentLoadFlags
            if (!TryAdvance(ref offset, limit, pointerSize)) return false; // EditList
            if (!TryAdvance(ref offset, limit, pointerSize)) return false; // SecurityCookie
            if (!TryAdvance(ref offset, limit, pointerSize)) return false; // SEHandlerTable
            if (!TryAdvance(ref offset, limit, pointerSize)) return false; // SEHandlerCount
            if (!TryAdvance(ref offset, limit, pointerSize)) return false; // GuardCfCheck
            if (!TryAdvance(ref offset, limit, pointerSize)) return false; // GuardCfDispatch
            if (!TryAdvance(ref offset, limit, pointerSize)) return false; // GuardCfTable
            if (!TryAdvance(ref offset, limit, pointerSize)) return false; // GuardCfCount
            if (!TryAdvance(ref offset, limit, 4)) return false; // GuardFlags

            LoadConfigCodeIntegrityInfo codeIntegrityInfo = null;
            bool readCodeIntegrity = TryReadCodeIntegrity(span, ref offset, limit, out codeIntegrityInfo);
            bool readGuardIat = false;
            bool readDynamicReloc = false;
            bool readChpe = false;
            bool readGuardRf = false;
            bool readHotPatch = false;
            bool readEnclave = false;
            bool readVolatile = false;
            bool readEhContinuation = false;
            bool readXfg = false;

            if (readCodeIntegrity &&
                TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _))
            {
                readGuardIat = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _) &&
                               TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _) &&
                               TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                if (readGuardIat)
                {
                    readDynamicReloc = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                    readChpe = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                }
            }

            if (readChpe)
            {
                readGuardRf = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                if (TryReadUInt32Value(span, ref offset, limit, out _))
                {
                    TryReadUInt16Value(span, ref offset, limit, out _);
                    TryReadUInt16Value(span, ref offset, limit, out _);
                }

                TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                readHotPatch = TryReadUInt32Value(span, ref offset, limit, out _);
                if (readHotPatch)
                {
                    TryReadUInt32Value(span, ref offset, limit, out _);
                }

                readEnclave = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                readVolatile = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                if (TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _))
                {
                    readEhContinuation = true;
                    TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                    readXfg = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _) ||
                              TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _) ||
                              TryReadPointerValue(span, ref offset, limit, isPe32Plus, out _);
                }
            }

            info = BuildLoadConfigVersionInfo(
                size,
                (uint)limit,
                (uint)Math.Min(offset, limit),
                readCodeIntegrity,
                readGuardIat,
                readDynamicReloc,
                readChpe,
                readGuardRf,
                readHotPatch,
                readEnclave,
                readVolatile,
                readEhContinuation,
                readXfg,
                span);
            return info != null;
        }

        internal static bool TryParseBitmapInfoHeaderForTest(
            byte[] data,
            out int width,
            out int height,
            out ushort bitCount,
            out uint compression,
            out uint imageSize)
        {
            return TryParseBitmapInfoHeader(data, out width, out height, out bitCount, out compression, out imageSize);
        }

        internal static ResourceIconInfo TryParseIconResourceForTest(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            return TryParseIconResource(data, out int width, out int height, out ushort bitCount, out bool isPng, out uint pngWidth, out uint pngHeight)
                ? new ResourceIconInfo(0, 0, width, height, bitCount, isPng, pngWidth, pngHeight, (uint)data.Length)
                : null;
        }

        internal static ResourceCursorInfo TryParseCursorResourceForTest(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            return TryParseCursorResource(data, out ushort hotspotX, out ushort hotspotY, out int width, out int height, out ushort bitCount, out bool isPng, out uint pngWidth, out uint pngHeight)
                ? new ResourceCursorInfo(0, 0, hotspotX, hotspotY, width, height, bitCount, isPng, pngWidth, pngHeight, (uint)data.Length)
                : null;
        }

        internal static bool TryParseCursorGroupForTest(byte[] groupData, out ResourceCursorGroupInfo group)
        {
            group = null;
            if (!TryReadGroupResourceHeader(groupData, 2, out ushort reserved, out ushort type, out ushort count, out int entrySize, out int parsedCount, out bool headerValid, out bool entriesTruncated))
            {
                return false;
            }

            List<ResourceCursorEntryInfo> entries = new List<ResourceCursorEntryInfo>();
            for (int i = 0; i < parsedCount; i++)
            {
                int offset = 6 + (i * entrySize);
                if (offset + 14 > groupData.Length)
                {
                    break;
                }

                byte width = groupData[offset];
                byte height = groupData[offset + 1];
                ushort hotspotX = ReadUInt16(groupData, offset + 4);
                ushort hotspotY = ReadUInt16(groupData, offset + 6);
                uint bytesInRes = ReadUInt32(groupData, offset + 8);
                ushort resourceId = ReadUInt16(groupData, offset + 12);
                entries.Add(new ResourceCursorEntryInfo(
                    width,
                    height,
                    hotspotX,
                    hotspotY,
                    bytesInRes,
                    resourceId,
                    false,
                    0,
                    0));
            }

            group = new ResourceCursorGroupInfo(1, 0, reserved, type, count, entrySize, headerValid, entriesTruncated, entries.ToArray());
            return true;
        }

        internal static bool TryParseIconGroupForTest(byte[] groupData, out IconGroupInfo group)
        {
            group = null;
            if (!TryReadGroupResourceHeader(groupData, 1, out ushort reserved, out ushort type, out ushort count, out int entrySize, out int parsedCount, out bool headerValid, out bool entriesTruncated))
            {
                return false;
            }

            List<IconEntryInfo> entries = new List<IconEntryInfo>();
            for (int i = 0; i < parsedCount; i++)
            {
                int offset = 6 + (i * entrySize);
                if (offset + 14 > groupData.Length)
                {
                    break;
                }

                byte width = groupData[offset];
                byte height = groupData[offset + 1];
                byte colorCount = groupData[offset + 2];
                byte reservedEntry = groupData[offset + 3];
                ushort planes = ReadUInt16(groupData, offset + 4);
                ushort bitCount = ReadUInt16(groupData, offset + 6);
                uint bytesInRes = ReadUInt32(groupData, offset + 8);
                ushort resourceId = ReadUInt16(groupData, offset + 12);
                entries.Add(new IconEntryInfo(width, height, colorCount, reservedEntry, planes, bitCount, bytesInRes, resourceId, false, 0, 0));
            }

            group = new IconGroupInfo(1, 0, reserved, type, count, entrySize, headerValid, entriesTruncated, entries.ToArray(), Array.Empty<byte>());
            return true;
        }

        private static uint ReadUInt32BigEndian(ReadOnlySpan<byte> data, int offset)
        {
            return ((uint)data[offset] << 24) |
                   ((uint)data[offset + 1] << 16) |
                   ((uint)data[offset + 2] << 8) |
                   data[offset + 3];
        }

        private static ushort ReadUInt16BigEndian(ReadOnlySpan<byte> data, int offset)
        {
            return (ushort)(((uint)data[offset] << 8) | data[offset + 1]);
        }

        private static ulong ReadUInt64BigEndian(ReadOnlySpan<byte> data, int offset)
        {
            return ((ulong)data[offset] << 56) |
                   ((ulong)data[offset + 1] << 48) |
                   ((ulong)data[offset + 2] << 40) |
                   ((ulong)data[offset + 3] << 32) |
                   ((ulong)data[offset + 4] << 24) |
                   ((ulong)data[offset + 5] << 16) |
                   ((ulong)data[offset + 6] << 8) |
                   data[offset + 7];
        }

        private static void WriteUInt16(byte[] buffer, int offset, ushort value)
        {
            if (buffer == null || offset + 1 >= buffer.Length)
            {
                return;
            }

            buffer[offset] = (byte)(value & 0xFF);
            buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        }

        private static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            if (buffer == null || offset + 3 >= buffer.Length)
            {
                return;
            }

            buffer[offset] = (byte)(value & 0xFF);
            buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
            buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
            buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        private static bool TryParseStringTable(byte[] data, out string[] strings)
        {
            if (data == null)
            {
                strings = Array.Empty<string>();
                return false;
            }

            return TryParseStringTable(new ReadOnlySpan<byte>(data), out strings);
        }

        private static bool TryParseStringTable(ReadOnlySpan<byte> data, out string[] strings)
        {
            strings = Array.Empty<string>();
            if (data.Length < 2)
            {
                return false;
            }

            List<string> result = new List<string>(16);
            int offset = 0;
            for (int i = 0; i < 16 && offset + 2 <= data.Length; i++)
            {
                ushort length = ReadUInt16(data, offset);
                offset += 2;

                if (length == 0)
                {
                    result.Add(string.Empty);
                    continue;
                }

                int byteLength = length * 2;
                if (offset + byteLength > data.Length)
                {
                    break;
                }

                string value = Encoding.Unicode.GetString(data.Slice(offset, byteLength));
                result.Add(value);
                offset += byteLength;
            }

            if (result.Count == 0)
            {
                return false;
            }

            while (result.Count < 16)
            {
                result.Add(string.Empty);
            }

            strings = result.ToArray();
            return true;
        }

        private static string DecodeTextResource(byte[] data)
        {
            if (data == null)
            {
                return string.Empty;
            }

            return DecodeTextResource(new ReadOnlySpan<byte>(data));
        }

        private static string DecodeTextResource(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                return string.Empty;
            }

            if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            {
                return Encoding.UTF8.GetString(data.Slice(3)).TrimEnd('\0');
            }

            if (data.Length >= 2)
            {
                if (data[0] == 0xFF && data[1] == 0xFE)
                {
                    return Encoding.Unicode.GetString(data.Slice(2)).TrimEnd('\0');
                }

                if (data[0] == 0xFE && data[1] == 0xFF)
                {
                    return Encoding.BigEndianUnicode.GetString(data.Slice(2)).TrimEnd('\0');
                }
            }

            int sample = Math.Min(data.Length, 64);
            int zeroCount = 0;
            for (int i = 1; i < sample; i += 2)
            {
                if (data[i] == 0)
                {
                    zeroCount++;
                }
            }

            if (zeroCount > sample / 4)
            {
                return Encoding.Unicode.GetString(data).TrimEnd('\0');
            }

            return Encoding.UTF8.GetString(data).TrimEnd('\0');
        }

        private static bool TryParseMessageTable(ReadOnlySpan<byte> data, out MessageTableEntryInfo[] entries, out uint minId, out uint maxId)
        {
            entries = Array.Empty<MessageTableEntryInfo>();
            minId = 0;
            maxId = 0;
            if (data.Length < 4)
            {
                return false;
            }

            uint blockCountValue = ReadUInt32(data, 0);
            if (blockCountValue == 0 || blockCountValue > 4096)
            {
                return false;
            }

            int blockCount = (int)blockCountValue;
            int headerSize = 4 + (blockCount * 12);
            if (headerSize > data.Length)
            {
                return false;
            }

            List<MessageTableEntryInfo> results = new List<MessageTableEntryInfo>();
            uint localMin = uint.MaxValue;
            uint localMax = 0;
            for (int i = 0; i < blockCount; i++)
            {
                int blockOffset = 4 + (i * 12);
                uint lowId = ReadUInt32(data, blockOffset);
                uint highId = ReadUInt32(data, blockOffset + 4);
                uint offsetToEntries = ReadUInt32(data, blockOffset + 8);

                if (highId < lowId)
                {
                    continue;
                }

                if (offsetToEntries > int.MaxValue || offsetToEntries >= data.Length)
                {
                    continue;
                }

                uint id = lowId;
                int cursor = (int)offsetToEntries;
                while (id <= highId && cursor + 4 <= data.Length)
                {
                    ushort length = ReadUInt16(data, cursor);
                    ushort flags = ReadUInt16(data, cursor + 2);
                    if (length < 4)
                    {
                        break;
                    }

                    int entryLength = length;
                    if (cursor + entryLength > data.Length)
                    {
                        break;
                    }

                    ReadOnlySpan<byte> textSpan = data.Slice(cursor + 4, entryLength - 4);
                    bool isUnicode = (flags & 0x0001) != 0;
                    string text = isUnicode
                        ? Encoding.Unicode.GetString(textSpan)
                        : Encoding.ASCII.GetString(textSpan);
                    text = text.TrimEnd('\0');
                    results.Add(new MessageTableEntryInfo(id, text, isUnicode, length, flags));
                    if (id < localMin)
                    {
                        localMin = id;
                    }
                    if (id > localMax)
                    {
                        localMax = id;
                    }

                    cursor += entryLength;
                    id++;
                }
            }

            if (results.Count == 0)
            {
                return false;
            }

            entries = results.ToArray();
            if (localMin != uint.MaxValue)
            {
                minId = localMin;
                maxId = localMax;
            }
            return true;
        }

        internal static bool TryParseMessageTableForTest(byte[] data, out MessageTableEntryInfo[] entries, out uint minId, out uint maxId)
        {
            if (data == null)
            {
                entries = Array.Empty<MessageTableEntryInfo>();
                minId = 0;
                maxId = 0;
                return false;
            }

            return TryParseMessageTable(new ReadOnlySpan<byte>(data), out entries, out minId, out maxId);
        }

        private static bool TryParseDialogTemplate(ReadOnlySpan<byte> data, out ResourceDialogInfo dialog)
        {
            dialog = null;
            if (data.Length < 18)
            {
                return false;
            }

            int offset = 0;
            bool isExtended = false;
            uint style;
            uint exStyle;
            ushort controlCount;
            short x;
            short y;
            short cx;
            short cy;

            if (data.Length >= 4)
            {
                ushort dlgVer = ReadUInt16(data, 0);
                ushort signature = ReadUInt16(data, 2);
                if (dlgVer == 1 && signature == 0xFFFF)
                {
                    isExtended = true;
                }
            }

            if (isExtended)
            {
                if (data.Length < 26)
                {
                    return false;
                }

                offset = 4; // dlgVer + signature
                offset += 4; // helpID
                exStyle = ReadUInt32(data, offset);
                offset += 4;
                style = ReadUInt32(data, offset);
                offset += 4;
                controlCount = ReadUInt16(data, offset);
                offset += 2;
                x = unchecked((short)ReadUInt16(data, offset));
                offset += 2;
                y = unchecked((short)ReadUInt16(data, offset));
                offset += 2;
                cx = unchecked((short)ReadUInt16(data, offset));
                offset += 2;
                cy = unchecked((short)ReadUInt16(data, offset));
                offset += 2;
            }
            else
            {
                style = ReadUInt32(data, offset);
                offset += 4;
                exStyle = ReadUInt32(data, offset);
                offset += 4;
                controlCount = ReadUInt16(data, offset);
                offset += 2;
                x = unchecked((short)ReadUInt16(data, offset));
                offset += 2;
                y = unchecked((short)ReadUInt16(data, offset));
                offset += 2;
                cx = unchecked((short)ReadUInt16(data, offset));
                offset += 2;
                cy = unchecked((short)ReadUInt16(data, offset));
                offset += 2;
            }

            if (!TryReadResourceIdOrString(data, ref offset, out string menu))
            {
                return false;
            }

            if (!TryReadResourceIdOrString(data, ref offset, out string windowClass))
            {
                return false;
            }

            if (!TryReadResourceIdOrString(data, ref offset, out string title))
            {
                return false;
            }

            ushort? fontPointSize = null;
            string fontFace = string.Empty;
            const uint DS_SETFONT = 0x00000040;
            if ((style & DS_SETFONT) != 0)
            {
                if (offset + 2 > data.Length)
                {
                    return false;
                }

                fontPointSize = ReadUInt16(data, offset);
                offset += 2;
                if (isExtended)
                {
                    if (offset + 4 > data.Length)
                    {
                        return false;
                    }

                    offset += 2; // weight
                    offset += 2; // italic + charset
                }

                if (!TryReadResourceUnicodeString(data, ref offset, out fontFace))
                {
                    return false;
                }
            }

            dialog = new ResourceDialogInfo(
                0,
                0,
                isExtended,
                style,
                exStyle,
                controlCount,
                x,
                y,
                cx,
                cy,
                menu,
                windowClass,
                title,
                fontPointSize,
                fontFace);
            return true;
        }

        private static bool TryParseAcceleratorTable(ReadOnlySpan<byte> data, out ResourceAcceleratorEntryInfo[] entries)
        {
            entries = Array.Empty<ResourceAcceleratorEntryInfo>();
            if (data.Length < 6)
            {
                return false;
            }

            List<ResourceAcceleratorEntryInfo> results = new List<ResourceAcceleratorEntryInfo>();
            int offset = 0;
            int entrySize = 6;
            int maxEntries = Math.Min(4096, data.Length / entrySize);
            for (int i = 0; i < maxEntries; i++)
            {
                if (offset + entrySize > data.Length)
                {
                    break;
                }

                byte flags = data[offset];
                ushort key = ReadUInt16(data, offset + 2);
                ushort command = ReadUInt16(data, offset + 4);
                bool isLast = (flags & 0x80) != 0;
                string[] flagNames = DecodeAcceleratorFlags(flags);
                results.Add(new ResourceAcceleratorEntryInfo(flags, key, command, isLast, flagNames));
                offset += entrySize;
                if (isLast)
                {
                    break;
                }
            }

            entries = results.ToArray();
            return entries.Length > 0;
        }

        private static bool TryParseMenuTemplate(ReadOnlySpan<byte> data, out ResourceMenuInfo menu)
        {
            menu = null;
            if (data.Length < 4)
            {
                return false;
            }

            bool isExtended = ReadUInt16(data, 0) == 1 && ReadUInt16(data, 2) == 4;
            List<string> items = new List<string>();
            int itemCount = 0;

            if (!TryParseMenuTemplateStandard(data, items, out itemCount))
            {
                items.Clear();
                if (!TryParseMenuStrings(data, items))
                {
                    return false;
                }

                itemCount = items.Count;
            }

            menu = new ResourceMenuInfo(0, 0, isExtended, itemCount, items.ToArray());
            return true;
        }

        private static bool TryParseMenuTemplateStandard(ReadOnlySpan<byte> data, List<string> items, out int itemCount)
        {
            itemCount = 0;
            int offset = 0;
            int depth = 0;
            int maxItems = 1024;

            while (offset + 2 <= data.Length && itemCount < maxItems)
            {
                ushort flags = ReadUInt16(data, offset);
                offset += 2;

                bool isPopup = (flags & 0x0010) != 0;
                bool isEnd = (flags & 0x0080) != 0;

                if (!isPopup)
                {
                    if (offset + 2 > data.Length)
                    {
                        break;
                    }

                    offset += 2; // id
                }

                if (!TryReadResourceUnicodeString(data, ref offset, out string text))
                {
                    return itemCount > 0;
                }

                if (!string.IsNullOrWhiteSpace(text))
                {
                    items.Add(text);
                }

                itemCount++;

                if (isPopup)
                {
                    depth++;
                }

                if (isEnd)
                {
                    if (depth == 0)
                    {
                        break;
                    }

                    depth--;
                }
            }

            return itemCount > 0;
        }

        private static bool TryParseMenuStrings(ReadOnlySpan<byte> data, List<string> items)
        {
            int maxItems = 256;
            int maxChars = 128;
            StringBuilder sb = new StringBuilder();

            for (int offset = 0; offset + 1 < data.Length; offset += 2)
            {
                ushort ch = ReadUInt16(data, offset);
                if (ch == 0)
                {
                    if (sb.Length > 0)
                    {
                        string text = sb.ToString();
                        if (!string.IsNullOrWhiteSpace(text))
                        {
                            items.Add(text);
                            if (items.Count >= maxItems)
                            {
                                break;
                            }
                        }
                        sb.Clear();
                    }
                    continue;
                }

                if (ch < 0x20 && ch != 0x09)
                {
                    if (sb.Length > 0)
                    {
                        sb.Clear();
                    }
                    continue;
                }

                if (sb.Length < maxChars)
                {
                    sb.Append((char)ch);
                }
            }

            return items.Count > 0;
        }

        private static bool TryParseToolbarResource(ReadOnlySpan<byte> data, out ResourceToolbarInfo toolbar)
        {
            toolbar = null;
            if (data.Length < 8)
            {
                return false;
            }

            ushort version = ReadUInt16(data, 0);
            ushort width = ReadUInt16(data, 2);
            ushort height = ReadUInt16(data, 4);
            ushort itemCount = ReadUInt16(data, 6);

            int available = (data.Length - 8) / 2;
            int cappedCount = Math.Min(itemCount, (ushort)Math.Min(available, 1024));
            if (cappedCount <= 0)
            {
                return false;
            }

            ushort[] items = new ushort[cappedCount];
            int offset = 8;
            for (int i = 0; i < cappedCount; i++)
            {
                items[i] = ReadUInt16(data, offset);
                offset += 2;
            }

            toolbar = new ResourceToolbarInfo(0, 0, version, width, height, (ushort)cappedCount, items);
            return true;
        }

        internal static bool TryParseMenuTemplateBytes(byte[] data, out ResourceMenuInfo menu)
        {
            if (data == null)
            {
                menu = null;
                return false;
            }

            return TryParseMenuTemplate(data, out menu);
        }

        internal static bool TryParseToolbarResourceBytes(byte[] data, out ResourceToolbarInfo toolbar)
        {
            if (data == null)
            {
                toolbar = null;
                return false;
            }

            return TryParseToolbarResource(data, out toolbar);
        }

        private static string[] DecodeAcceleratorFlags(byte flags)
        {
            List<string> names = new List<string>();
            if ((flags & 0x01) != 0)
            {
                names.Add("FVIRTKEY");
            }
            if ((flags & 0x02) != 0)
            {
                names.Add("FNOINVERT");
            }
            if ((flags & 0x04) != 0)
            {
                names.Add("FSHIFT");
            }
            if ((flags & 0x08) != 0)
            {
                names.Add("FCONTROL");
            }
            if ((flags & 0x10) != 0)
            {
                names.Add("FALT");
            }
            if ((flags & 0x80) != 0)
            {
                names.Add("FEND");
            }
            return names.ToArray();
        }

        private static bool TryReadResourceIdOrString(ReadOnlySpan<byte> data, ref int offset, out string value)
        {
            value = string.Empty;
            if (offset + 2 > data.Length)
            {
                return false;
            }

            ushort marker = ReadUInt16(data, offset);
            offset += 2;
            if (marker == 0x0000)
            {
                return true;
            }

            if (marker == 0xFFFF)
            {
                if (offset + 2 > data.Length)
                {
                    return false;
                }

                ushort ordinal = ReadUInt16(data, offset);
                offset += 2;
                value = "#" + ordinal.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return true;
            }

            int start = offset - 2;
            int cursor = start;
            while (cursor + 1 < data.Length)
            {
                if (ReadUInt16(data, cursor) == 0)
                {
                    break;
                }

                cursor += 2;
            }

            if (cursor + 1 >= data.Length)
            {
                return false;
            }

            int byteLength = cursor - start;
            value = Encoding.Unicode.GetString(data.Slice(start, byteLength));
            offset = cursor + 2;
            return true;
        }

        private static bool TryReadResourceUnicodeString(ReadOnlySpan<byte> data, ref int offset, out string value)
        {
            value = string.Empty;
            if (offset >= data.Length)
            {
                return false;
            }

            int start = offset;
            int cursor = start;
            while (cursor + 1 < data.Length)
            {
                if (ReadUInt16(data, cursor) == 0)
                {
                    break;
                }

                cursor += 2;
            }

            if (cursor + 1 >= data.Length)
            {
                return false;
            }

            int byteLength = cursor - start;
            value = Encoding.Unicode.GetString(data.Slice(start, byteLength));
            offset = cursor + 2;
            return true;
        }

        private static bool TryParseManifestSchema(string content, out ManifestSchemaInfo schema)
        {
            schema = null;
            if (string.IsNullOrWhiteSpace(content))
            {
                return false;
            }

            try
            {
                XDocument doc = XDocument.Parse(content, LoadOptions.PreserveWhitespace);
                XElement root = doc.Root;
                if (root == null)
                {
                    return false;
                }

                string rootElement = root.Name.LocalName;
                string ns = root.Name.NamespaceName;
                string manifestVersion = root.Attribute("manifestVersion")?.Value ?? string.Empty;

                XElement assemblyIdentity = FindFirstElement(root, "assemblyIdentity");
                string identityName = assemblyIdentity?.Attribute("name")?.Value ?? string.Empty;
                string identityVersion = assemblyIdentity?.Attribute("version")?.Value ?? string.Empty;
                string identityArch = assemblyIdentity?.Attribute("processorArchitecture")?.Value ?? string.Empty;
                string identityType = assemblyIdentity?.Attribute("type")?.Value ?? string.Empty;
                string identityLanguage = assemblyIdentity?.Attribute("language")?.Value ?? string.Empty;

                XElement requestedExecutionLevel = FindFirstElement(root, "requestedExecutionLevel");
                string uiAccess = requestedExecutionLevel?.Attribute("uiAccess")?.Value ?? string.Empty;
                string requestedLevel = requestedExecutionLevel?.Attribute("level")?.Value ?? string.Empty;

                XElement dpiAwareElement = FindFirstElement(root, "dpiAware");
                string dpiAware = dpiAwareElement?.Value ?? string.Empty;
                XElement dpiAwarenessElement = FindFirstElement(root, "dpiAwareness");
                string dpiAwareness = dpiAwarenessElement?.Value ?? string.Empty;
                XElement uiLanguageElement = FindFirstElement(root, "uiLanguage");
                string uiLanguage = uiLanguageElement?.Value ?? string.Empty;
                XElement longPathAwareElement = FindFirstElement(root, "longPathAware");
                string longPathAware = longPathAwareElement?.Value ?? string.Empty;
                XElement activeCodePageElement = FindFirstElement(root, "activeCodePage");
                string activeCodePage = activeCodePageElement?.Value ?? string.Empty;

                string[] supportedOs = root
                    .Descendants()
                    .Where(element => string.Equals(element.Name.LocalName, "supportedOS", StringComparison.OrdinalIgnoreCase))
                    .Select(element => element.Attribute("Id")?.Value ?? element.Attribute("id")?.Value ?? string.Empty)
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                dpiAware = dpiAware?.Trim() ?? string.Empty;
                dpiAwareness = dpiAwareness?.Trim() ?? string.Empty;
                uiLanguage = uiLanguage?.Trim() ?? string.Empty;
                longPathAware = longPathAware?.Trim() ?? string.Empty;
                activeCodePage = activeCodePage?.Trim() ?? string.Empty;

                List<string> validationMessages = new List<string>();
                if (!string.Equals(rootElement, "assembly", StringComparison.OrdinalIgnoreCase))
                {
                    validationMessages.Add("Root element is not <assembly>.");
                }
                if (string.IsNullOrWhiteSpace(identityName))
                {
                    validationMessages.Add("assemblyIdentity name is missing.");
                }
                if (string.IsNullOrWhiteSpace(identityVersion))
                {
                    validationMessages.Add("assemblyIdentity version is missing.");
                }
                if (!string.IsNullOrWhiteSpace(uiAccess) &&
                    !string.Equals(uiAccess, "true", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(uiAccess, "false", StringComparison.OrdinalIgnoreCase))
                {
                    validationMessages.Add("requestedExecutionLevel uiAccess is not 'true' or 'false'.");
                }

                schema = new ManifestSchemaInfo(
                    rootElement,
                    ns,
                    manifestVersion,
                    identityName,
                    identityVersion,
                    identityArch,
                    identityType,
                    identityLanguage,
                    requestedLevel,
                    uiAccess,
                    dpiAware,
                    dpiAwareness,
                    uiLanguage,
                    supportedOs,
                    longPathAware,
                    activeCodePage,
                    validationMessages.Count == 0,
                    validationMessages.ToArray());
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        internal static bool TryParseManifestSchemaForTest(string content, out ManifestSchemaInfo schema)
        {
            return TryParseManifestSchema(content, out schema);
        }

        private static bool LooksLikeManifest(string content)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                return false;
            }

            string trimmed = content.TrimStart();
            if (trimmed.StartsWith("<assembly", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (trimmed.IndexOf("urn:schemas-microsoft-com:asm", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            return false;
        }

        private static XElement FindFirstElement(XElement root, string localName)
        {
            if (root == null || string.IsNullOrWhiteSpace(localName))
            {
                return null;
            }

            if (string.Equals(root.Name.LocalName, localName, StringComparison.OrdinalIgnoreCase))
            {
                return root;
            }

            foreach (XElement element in root.Descendants())
            {
                if (string.Equals(element.Name.LocalName, localName, StringComparison.OrdinalIgnoreCase))
                {
                    return element;
                }
            }

            return null;
        }

        private void ParseRichHeader(IMAGE_DOS_HEADER header)
        {
            if (PEFileStream == null || header.e_lfanew <= 0)
            {
                return;
            }

            long maxLength = Math.Min(header.e_lfanew, (uint)PEFileStream.Length);
            if (maxLength <= 0 || maxLength > int.MaxValue)
            {
                return;
            }

            if (!TrySetPosition(0, (int)maxLength))
            {
                return;
            }

            byte[] buffer = new byte[(int)maxLength];
            ReadExactly(PEFileStream, buffer, 0, buffer.Length);
            if (TryParseRichHeader(buffer, buffer.Length, out RichHeaderInfo info))
            {
                _richHeader = info;
            }
        }

        private void ParseDosRelocations(IMAGE_DOS_HEADER header)
        {
            _dosRelocationInfo = null;
            if (header.e_crlc == 0)
            {
                return;
            }

            uint count = header.e_crlc;
            uint tableOffset = header.e_lfarlc;
            if (tableOffset == 0)
            {
                Warn(ParseIssueCategory.Header, "DOS relocation table offset is zero but relocation count is non-zero.");
                return;
            }

            ulong totalBytes = (ulong)count * 4UL;
            if (totalBytes > int.MaxValue)
            {
                Warn(ParseIssueCategory.Header, "DOS relocation table size exceeds supported limits.");
                return;
            }

            if (!TrySetPosition(tableOffset, (int)totalBytes))
            {
                Warn(ParseIssueCategory.Header, "DOS relocation table exceeds file bounds.");
                return;
            }

            int maxEntries = 256;
            int entriesToRead = (int)Math.Min(count, (uint)maxEntries);
            List<DosRelocationEntry> entries = new List<DosRelocationEntry>(entriesToRead);
            for (int i = 0; i < entriesToRead; i++)
            {
                ushort offset = PEFile.ReadUInt16();
                ushort segment = PEFile.ReadUInt16();
                entries.Add(new DosRelocationEntry(offset, segment));
            }

            _dosRelocationInfo = new DosRelocationInfo(
                (int)count,
                tableOffset,
                count > maxEntries,
                entries.ToArray());
        }

        private static bool TryParseDosRelocationsFromBuffer(IMAGE_DOS_HEADER header, byte[] data, out DosRelocationInfo info)
        {
            info = null;
            if (data == null || header.e_crlc == 0)
            {
                return false;
            }

            uint count = header.e_crlc;
            uint tableOffset = header.e_lfarlc;
            if (tableOffset == 0)
            {
                return false;
            }

            ulong totalBytes = (ulong)count * 4UL;
            if (totalBytes > int.MaxValue)
            {
                return false;
            }

            if (tableOffset + totalBytes > (ulong)data.Length)
            {
                return false;
            }

            int maxEntries = 256;
            int entriesToRead = (int)Math.Min(count, (uint)maxEntries);
            List<DosRelocationEntry> entries = new List<DosRelocationEntry>(entriesToRead);
            int cursor = (int)tableOffset;
            for (int i = 0; i < entriesToRead; i++)
            {
                ushort offset = ReadUInt16(data, cursor);
                ushort segment = ReadUInt16(data, cursor + 2);
                entries.Add(new DosRelocationEntry(offset, segment));
                cursor += 4;
            }

            info = new DosRelocationInfo((int)count, tableOffset, count > maxEntries, entries.ToArray());
            return true;
        }

        private static bool TryParseRichHeader(byte[] buffer, int length, out RichHeaderInfo info)
        {
            info = null;
            if (buffer == null || length < 16)
            {
                return false;
            }

            int richOffset = FindPattern(buffer, length, new byte[] { 0x52, 0x69, 0x63, 0x68 }); // "Rich"
            if (richOffset < 0 || richOffset + 8 > length)
            {
                return false;
            }

            uint key = ReadUInt32(buffer, richOffset + 4);
            int start = -1;
            for (int i = richOffset - 4; i >= 0; i -= 4)
            {
                uint value = ReadUInt32(buffer, i) ^ key;
                if (value == 0x536E6144) // "DanS"
                {
                    start = i;
                    break;
                }
            }

            if (start < 0)
            {
                return false;
            }

            int entryStart = start + 16; // skip DanS + 3 padding dwords
            if (entryStart >= richOffset)
            {
                return false;
            }

            List<RichHeaderEntry> entries = new List<RichHeaderEntry>();
            for (int offset = entryStart; offset + 8 <= richOffset; offset += 8)
            {
                uint compid = ReadUInt32(buffer, offset) ^ key;
                uint count = ReadUInt32(buffer, offset + 4) ^ key;
                if (compid == 0 && count == 0)
                {
                    continue;
                }

                ushort build = (ushort)(compid & 0xFFFF);
                ushort product = (ushort)((compid >> 16) & 0xFFFF);
                string productName = DecodeRichProductName(product);
                string toolchainVersion = build.ToString(CultureInfo.InvariantCulture);
                entries.Add(new RichHeaderEntry(product, build, count, compid, productName, toolchainVersion));
            }

            RichToolchainInfo[] toolchains = BuildRichToolchainHints(entries);
            info = new RichHeaderInfo(key, entries.ToArray(), toolchains);
            return true;
        }

        private static string DecodeRichProductName(ushort productId)
        {
            if (RichProductNameMap.TryGetValue(productId, out string name))
            {
                return name;
            }

            return $"ToolId 0x{productId:X4}";
        }

        internal static string DecodeRichProductNameForTest(ushort productId)
        {
            return DecodeRichProductName(productId);
        }

        internal static RichToolchainInfo[] BuildRichToolchainHintsForTest(RichHeaderEntry[] entries)
        {
            if (entries == null || entries.Length == 0)
            {
                return Array.Empty<RichToolchainInfo>();
            }

            return BuildRichToolchainHints(entries.ToList());
        }

        private static RichToolchainInfo[] BuildRichToolchainHints(List<RichHeaderEntry> entries)
        {
            if (entries == null || entries.Count == 0)
            {
                return Array.Empty<RichToolchainInfo>();
            }

            Dictionary<string, (HashSet<string> Tools, uint TotalCount)> grouped =
                new Dictionary<string, (HashSet<string>, uint)>(StringComparer.OrdinalIgnoreCase);

            foreach (RichHeaderEntry entry in entries)
            {
                if (entry == null || string.IsNullOrWhiteSpace(entry.ProductName))
                {
                    continue;
                }

                if (!TryExtractRichToolchainVersion(entry.ProductName, out string version, out string toolName))
                {
                    version = "Unknown";
                    toolName = entry.ProductName.Trim();
                }

                if (!grouped.TryGetValue(version, out var info))
                {
                    info = (new HashSet<string>(StringComparer.OrdinalIgnoreCase), 0);
                }

                if (!string.IsNullOrWhiteSpace(toolName))
                {
                    info.Tools.Add(toolName);
                }

                info.TotalCount += entry.Count;
                grouped[version] = info;
            }

            List<RichToolchainInfo> results = new List<RichToolchainInfo>();
            foreach (KeyValuePair<string, (HashSet<string> Tools, uint TotalCount)> pair in grouped)
            {
                string version = pair.Key;
                string name = version == "Unknown" ? "Unknown" : "MSVC " + version;
                string[] tools = pair.Value.Tools.OrderBy(t => t, StringComparer.OrdinalIgnoreCase).ToArray();
                results.Add(new RichToolchainInfo(version, name, pair.Value.TotalCount, tools));
            }

            return results
                .OrderByDescending(info => info.TotalCount)
                .ThenBy(info => info.Version, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private static bool TryExtractRichToolchainVersion(string productName, out string version, out string toolName)
        {
            version = string.Empty;
            toolName = productName?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(productName))
            {
                return false;
            }

            int open = productName.LastIndexOf('(');
            int close = productName.LastIndexOf(')');
            if (open >= 0 && close > open + 1)
            {
                version = productName.Substring(open + 1, close - open - 1).Trim();
                toolName = productName.Substring(0, open).Trim();
                return !string.IsNullOrWhiteSpace(version);
            }

            return false;
        }

        private static int FindPattern(byte[] buffer, int length, byte[] pattern)
        {
            if (buffer == null || pattern == null || pattern.Length == 0 || length < pattern.Length)
            {
                return -1;
            }

            int max = Math.Min(length, buffer.Length) - pattern.Length;
            for (int i = 0; i <= max; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    return i;
                }
            }

            return -1;
        }

        private void ValidateSections(IMAGE_DOS_HEADER dosHeader, IMAGE_NT_HEADERS peHeader, List<IMAGE_SECTION_HEADER> sections, IMAGE_DATA_DIRECTORY[] dataDirectories)
        {
            uint fileAlignment = peHeader.FileAlignment;
            uint sectionAlignment = peHeader.SectionAlignment;
            uint sizeOfHeaders = peHeader.SizeOfHeaders;
            uint sizeOfImage = peHeader.SizeOfImage;
            uint sizeOfCode = peHeader.SizeOfCode;
            uint sizeOfInitializedData = peHeader.SizeOfInitializedData;

            if (peHeader.Win32VersionValue != 0)
            {
                Warn(ParseIssueCategory.OptionalHeader, $"SPEC violation: OptionalHeader.Win32VersionValue must be 0 (found 0x{peHeader.Win32VersionValue:X8}).");
            }

            if (peHeader.LoaderFlags != 0)
            {
                Warn(ParseIssueCategory.OptionalHeader, $"SPEC violation: OptionalHeader.LoaderFlags must be 0 (found 0x{peHeader.LoaderFlags:X8}).");
            }

            if (dataDirectories != null)
            {
                if (dataDirectories.Length > 7 &&
                    (dataDirectories[7].VirtualAddress != 0 || dataDirectories[7].Size != 0))
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SPEC violation: DataDirectory[7] (Architecture) is reserved and must be zero.");
                }

                if (dataDirectories.Length > 8 && dataDirectories[8].Size != 0)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SPEC violation: DataDirectory[8] (GlobalPtr) Size must be zero.");
                }

                if (dataDirectories.Length > 15 &&
                    (dataDirectories[15].VirtualAddress != 0 || dataDirectories[15].Size != 0))
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SPEC violation: DataDirectory[15] is reserved and must be zero.");
                }
            }

            if (fileAlignment == 0)
            {
                Warn(ParseIssueCategory.OptionalHeader, "FileAlignment is zero.");
            }
            else
            {
                if (!IsPowerOfTwo(fileAlignment) || fileAlignment < 512 || fileAlignment > 65536)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "FileAlignment is not a valid power of two.");
                }
            }

            if (sectionAlignment == 0)
            {
                Warn(ParseIssueCategory.OptionalHeader, "SectionAlignment is zero.");
            }
            else
            {
                if (!IsPowerOfTwo(sectionAlignment))
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SectionAlignment is not a power of two.");
                }

                if (fileAlignment != 0 && sectionAlignment < fileAlignment)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SectionAlignment is smaller than FileAlignment.");
                }
            }

            long minHeaderSize = dosHeader.e_lfanew +
                                 sizeof(uint) +
                                 Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) +
                                 peHeader.FileHeader.SizeOfOptionalHeader +
                                 (sections.Count * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));

            if (sizeOfHeaders != 0)
            {
                if (sizeOfHeaders < minHeaderSize)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SizeOfHeaders is smaller than the minimum header size.");
                }

                if (fileAlignment != 0 && sizeOfHeaders % fileAlignment != 0)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SizeOfHeaders is not aligned to FileAlignment.");
                }

                if (sizeOfHeaders > PEFileStream.Length)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SizeOfHeaders exceeds file size.");
                }
            }

            List<(long Start, long End, string Name)> ranges = new List<(long, long, string)>();
            uint maxVirtualEnd = 0;
            uint sumCode = 0;
            uint sumInitData = 0;
            foreach (IMAGE_SECTION_HEADER section in sections)
            {
                string name = section.Section.TrimEnd('\0');
                bool isCode = (section.Characteristics & SectionCharacteristics.IMAGE_SCN_CNT_CODE) != 0;
                bool isInitData = (section.Characteristics & SectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
                bool isUninitData = (section.Characteristics & SectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
                bool isExecutable = (section.Characteristics & SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0;
                bool isReadable = (section.Characteristics & SectionCharacteristics.IMAGE_SCN_MEM_READ) != 0;
                bool isWritable = (section.Characteristics & SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0;
                if (section.SizeOfRawData == 0)
                {
                    if ((isCode || isInitData) && section.VirtualSize > 0)
                    {
                        Warn(ParseIssueCategory.Sections, $"Section {name} has VirtualSize but no raw data for code/initialized data.");
                    }
                    continue;
                }

                long start = section.PointerToRawData;
                long end = start + section.SizeOfRawData;

                if (fileAlignment != 0)
                {
                    if (section.PointerToRawData % fileAlignment != 0)
                    {
                        Warn(ParseIssueCategory.Sections, $"Section {name} PointerToRawData is not aligned to FileAlignment.");
                    }

                    if (section.SizeOfRawData % fileAlignment != 0)
                    {
                        Warn(ParseIssueCategory.Sections, $"Section {name} SizeOfRawData is not aligned to FileAlignment.");
                    }
                }

                if (sectionAlignment != 0 && section.VirtualAddress % sectionAlignment != 0)
                {
                    Warn(ParseIssueCategory.Sections, $"Section {name} VirtualAddress is not aligned to SectionAlignment.");
                }

                if (end > PEFileStream.Length)
                {
                    Warn(ParseIssueCategory.Sections, $"Section {name} raw data extends beyond end of file.");
                }

                bool skipRatioWarning = string.Equals(name, ".reloc", StringComparison.OrdinalIgnoreCase);
                if (section.VirtualSize > 0 && section.SizeOfRawData > 0 && !skipRatioWarning)
                {
                    if (section.VirtualSize > section.SizeOfRawData * 4)
                    {
                        Warn(ParseIssueCategory.Sections, $"Section {name} VirtualSize is much larger than SizeOfRawData.");
                    }

                    if (section.SizeOfRawData > section.VirtualSize * 4)
                    {
                        Warn(ParseIssueCategory.Sections, $"Section {name} SizeOfRawData is much larger than VirtualSize.");
                    }
                }

                if (isExecutable && isWritable)
                {
                    Warn(ParseIssueCategory.Sections, $"Section {name} is marked executable and writable (RWX).");
                }

                if (isCode && !isExecutable)
                {
                    Warn(ParseIssueCategory.Sections, $"Section {name} is marked as code but not executable.");
                }

                if (isInitData && isExecutable)
                {
                    Warn(ParseIssueCategory.Sections, $"Section {name} is marked as initialized data but executable.");
                }

                if (!isReadable && !isWritable && !isExecutable && !isUninitData)
                {
                    Warn(ParseIssueCategory.Sections, $"Section {name} has no readable/writeable/executable permissions.");
                }

                uint virtualSize = Math.Max(section.VirtualSize, section.SizeOfRawData);
                uint virtualEnd = section.VirtualAddress + AlignUp(virtualSize, sectionAlignment == 0 ? 1u : sectionAlignment);
                if (virtualEnd > maxVirtualEnd)
                {
                    maxVirtualEnd = virtualEnd;
                }

                if (isCode)
                {
                    sumCode += section.SizeOfRawData;
                }

                if (isInitData)
                {
                    sumInitData += section.SizeOfRawData;
                }

                ranges.Add((start, end, name));
            }

            if (ranges.Count > 0)
            {
                ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
                long minStart = ranges[0].Start;
                if (sizeOfHeaders != 0 && sizeOfHeaders > minStart)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SizeOfHeaders exceeds the first section raw data pointer.");
                }

                for (int i = 1; i < ranges.Count; i++)
                {
                    if (ranges[i].Start < ranges[i - 1].End)
                    {
                        Warn(ParseIssueCategory.Sections, $"Section {ranges[i].Name} overlaps section {ranges[i - 1].Name} in the file.");
                    }
                }
            }

            if (sectionAlignment != 0 && sizeOfImage != 0)
            {
                if (sizeOfImage % sectionAlignment != 0)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SizeOfImage is not aligned to SectionAlignment.");
                }

                if (maxVirtualEnd != 0 && sizeOfImage < maxVirtualEnd)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SizeOfImage is smaller than the last section end.");
                }

                if (maxVirtualEnd != 0 && sizeOfImage > maxVirtualEnd + sectionAlignment)
                {
                    Warn(ParseIssueCategory.OptionalHeader, "SizeOfImage exceeds expected size by more than one alignment block.");
                }
            }

            if (sizeOfCode != 0 && sizeOfImage != 0 && sizeOfCode > sizeOfImage)
            {
                Warn(ParseIssueCategory.OptionalHeader, "SizeOfCode exceeds SizeOfImage.");
            }

            if (sizeOfInitializedData != 0 && sizeOfImage != 0 && sizeOfInitializedData > sizeOfImage)
            {
                Warn(ParseIssueCategory.OptionalHeader, "SizeOfInitializedData exceeds SizeOfImage.");
            }

            if (sumCode > 0 && sizeOfCode == 0)
            {
                Warn(ParseIssueCategory.OptionalHeader, "SizeOfCode is zero but code sections are present.");
            }

            if (sumInitData > 0 && sizeOfInitializedData == 0)
            {
                Warn(ParseIssueCategory.OptionalHeader, "SizeOfInitializedData is zero but initialized data sections are present.");
            }

            if (peHeader.NumberOfRvaAndSizes < dataDirectories.Length)
            {
                for (int i = (int)peHeader.NumberOfRvaAndSizes; i < dataDirectories.Length; i++)
                {
                    if (dataDirectories[i].Size != 0 || dataDirectories[i].VirtualAddress != 0)
                    {
                        Warn(ParseIssueCategory.OptionalHeader, "Data directory entries exceed NumberOfRvaAndSizes.");
                        break;
                    }
                }
            }

            AnalyzeSectionPadding(sections, sizeOfHeaders);
        }

        private void ValidateImageCoffDeprecation(IMAGE_FILE_HEADER fileHeader, IReadOnlyList<IMAGE_SECTION_HEADER> sections)
        {
            if (fileHeader.PointerToSymbolTable != 0 || fileHeader.NumberOfSymbols != 0)
            {
                Warn(
                    ParseIssueCategory.Header,
                    $"SPEC violation: PE images should have COFF symbol table pointers cleared (PointerToSymbolTable=0x{fileHeader.PointerToSymbolTable:X8}, NumberOfSymbols={fileHeader.NumberOfSymbols}).");
            }

            if (sections == null || sections.Count == 0)
            {
                return;
            }

            for (int i = 0; i < sections.Count; i++)
            {
                IMAGE_SECTION_HEADER section = sections[i];
                if (section.PointerToLinenumbers != 0 || section.NumberOfLinenumbers != 0)
                {
                    Warn(
                        ParseIssueCategory.Header,
                        $"SPEC violation: PE image section {NormalizeSectionName(section)} should not use COFF line numbers (PointerToLinenumbers=0x{section.PointerToLinenumbers:X8}, NumberOfLinenumbers={section.NumberOfLinenumbers}).");
                }
            }
        }

        private void AnalyzeSectionPadding(List<IMAGE_SECTION_HEADER> sections, uint sizeOfHeaders)
        {
            _sectionSlacks.Clear();
            _sectionGaps.Clear();

            if (PEFileStream == null || sections == null || sections.Count == 0)
            {
                return;
            }

            SectionRange[] ranges = BuildSectionRanges(sections);
            AnalyzeSectionPaddingCore(
                ranges,
                sizeOfHeaders,
                PEFileStream.Length,
                CountNonZeroBytes,
                _sectionGaps,
                _sectionSlacks);

            foreach (SectionSlackInfo slack in _sectionSlacks)
            {
                if (slack.NonZeroCount > 0)
                {
                    Warn(ParseIssueCategory.Sections, $"Section {slack.SectionName} contains non-zero padding in trailing slack.");
                }
            }

            foreach (SectionGapInfo gap in _sectionGaps)
            {
                if (gap.NonZeroCount > 0)
                {
                    Warn(ParseIssueCategory.Sections, $"Gap between {gap.PreviousSection} and {gap.NextSection} contains non-zero padding.");
                }
            }
        }

        private void BuildSectionPermissionInfos(List<IMAGE_SECTION_HEADER> sections)
        {
            _sectionPermissions.Clear();
            Dictionary<uint, string> coffStringTable = BuildCoffStringTableMap();
            foreach (IMAGE_SECTION_HEADER section in sections)
            {
                string name = ResolveSectionName(section, coffStringTable);
                uint characteristics = (uint)section.Characteristics;
                bool isReadable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_READ) != 0;
                bool isWritable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0;
                bool isExecutable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0;
                bool isCode = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_CODE) != 0;
                bool isInitData = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
                bool isUninitData = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
                bool isDiscardable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_DISCARDABLE) != 0;
                bool isShared = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_SHARED) != 0;
                bool hasSuspicious = isExecutable && isWritable;
                bool hasMismatch = (isCode && !isExecutable) || (isInitData && isExecutable);

                string[] flags = DecodeSectionFlags(characteristics);
                _sectionPermissions.Add(new SectionPermissionInfo(
                    name,
                    characteristics,
                    flags,
                    isReadable,
                    isWritable,
                    isExecutable,
                    isCode,
                    isInitData,
                    isUninitData,
                    isDiscardable,
                    isShared,
                    hasSuspicious,
                    hasMismatch));
            }
        }

        private void BuildSectionHeaderInfos(List<IMAGE_SECTION_HEADER> sections)
        {
            _sectionHeaders.Clear();
            if (sections == null)
            {
                return;
            }

            long fileLength = PEFileStream?.Length ?? 0;
            Dictionary<uint, string> coffStringTable = BuildCoffStringTableMap();
            for (int i = 0; i < sections.Count; i++)
            {
                IMAGE_SECTION_HEADER section = sections[i];
                string name = ResolveSectionName(section, coffStringTable);
                uint characteristics = (uint)section.Characteristics;
                bool isReadable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_READ) != 0;
                bool isWritable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0;
                bool isExecutable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0;
                bool isCode = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_CODE) != 0;
                bool isInitData = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
                bool isUninitData = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
                bool isDiscardable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_DISCARDABLE) != 0;
                bool isShared = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_SHARED) != 0;
                bool hasSuspicious = isExecutable && isWritable;
                bool hasMismatch = (isCode && !isExecutable) || (isInitData && isExecutable);
                uint virtualPadding = section.VirtualSize > section.SizeOfRawData ? section.VirtualSize - section.SizeOfRawData : 0;
                uint rawPadding = section.SizeOfRawData > section.VirtualSize ? section.SizeOfRawData - section.VirtualSize : 0;
                bool sizeMismatch = virtualPadding > 0 || rawPadding > 0;
                bool hasRawData = section.SizeOfRawData > 0;
                bool hasVirtualData = section.VirtualSize > 0;
                bool rawPointerAligned = _fileAlignment == 0 || (section.PointerToRawData % _fileAlignment) == 0;
                bool rawSizeAligned = _fileAlignment == 0 || (section.SizeOfRawData % _fileAlignment) == 0;
                bool virtualAligned = _sectionAlignment == 0 || (section.VirtualAddress % _sectionAlignment) == 0;
                bool rawInBounds = fileLength <= 0 ||
                                   (section.PointerToRawData == 0 && section.SizeOfRawData == 0) ||
                                   (section.PointerToRawData + section.SizeOfRawData <= fileLength);
                string[] flags = DecodeSectionFlags(characteristics);
                _sectionHeaders.Add(new SectionHeaderInfo(
                    name,
                    i,
                    section.VirtualAddress,
                    section.VirtualSize,
                    section.PointerToRawData,
                    section.SizeOfRawData,
                    characteristics,
                    flags,
                    isReadable,
                    isWritable,
                    isExecutable,
                    isCode,
                    isInitData,
                    isUninitData,
                    isDiscardable,
                    isShared,
                    rawPointerAligned,
                    rawSizeAligned,
                    virtualAligned,
                    rawInBounds,
                    hasRawData,
                    hasVirtualData,
                    virtualPadding,
                    rawPadding,
                    sizeMismatch,
                    hasSuspicious,
                    hasMismatch,
                    section.NumberOfRelocations,
                    section.NumberOfLinenumbers));
            }
        }

        private void BuildSectionDirectoryCoverage(DataDirectoryInfo[] directories, List<IMAGE_SECTION_HEADER> sections)
        {
            _sectionDirectoryCoverage.Clear();
            _unmappedDataDirectories.Clear();
            if (directories == null)
            {
                return;
            }

            Dictionary<string, List<string>> map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            List<string> sectionNames = new List<string>();
            if (sections != null)
            {
                Dictionary<uint, string> coffStringTable = BuildCoffStringTableMap();
                foreach (IMAGE_SECTION_HEADER section in sections)
                {
                    string sectionName = ResolveSectionName(section, coffStringTable);
                    sectionNames.Add(sectionName);
                    if (!map.ContainsKey(sectionName))
                    {
                        map[sectionName] = new List<string>();
                        sectionNames.Add(sectionName);
                    }
                }
            }

            foreach (DataDirectoryInfo directory in directories)
            {
                if (directory == null || !directory.IsPresent)
                {
                    continue;
                }

                if (!directory.IsMapped || string.IsNullOrWhiteSpace(directory.SectionName))
                {
                    _unmappedDataDirectories.Add(directory.Name);
                    continue;
                }

                if (!map.TryGetValue(directory.SectionName, out List<string> list))
                {
                    list = new List<string>();
                    map[directory.SectionName] = list;
                    sectionNames.Add(directory.SectionName);
                }

                if (!list.Any(name => string.Equals(name, directory.Name, StringComparison.OrdinalIgnoreCase)))
                {
                    list.Add(directory.Name);
                }
            }

            foreach (string sectionName in sectionNames.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!map.TryGetValue(sectionName, out List<string> dirs))
                {
                    _sectionDirectoryCoverage.Add(new SectionDirectoryInfo(sectionName, Array.Empty<string>()));
                    continue;
                }

                dirs.Sort(StringComparer.OrdinalIgnoreCase);
                _sectionDirectoryCoverage.Add(new SectionDirectoryInfo(sectionName, dirs.ToArray()));
            }
        }

        private string ResolveSectionName(IMAGE_SECTION_HEADER section)
        {
            return ResolveSectionName(section, BuildCoffStringTableMap());
        }

        private void ResolveCoffObjectSectionLongNames(List<IMAGE_SECTION_HEADER> sections)
        {
            if (sections == null || sections.Count == 0)
            {
                return;
            }

            Dictionary<uint, string> coffStringTable = BuildCoffStringTableMap();
            for (int i = 0; i < sections.Count; i++)
            {
                IMAGE_SECTION_HEADER section = sections[i];
                string currentName = NormalizeSectionName(section);
                if (string.IsNullOrEmpty(currentName) || currentName[0] != '/')
                {
                    continue;
                }

                if (currentName.Length == 1 ||
                    !uint.TryParse(currentName.Substring(1), NumberStyles.None, CultureInfo.InvariantCulture, out uint offset))
                {
                    Warn(
                        ParseIssueCategory.Header,
                        string.Format(
                            CultureInfo.InvariantCulture,
                            "SPEC violation: COFF section header name for section #{0} uses non-numeric long-name offset ({1}).",
                            i + 1,
                            currentName));
                    continue;
                }

                if (offset == 0 || !coffStringTable.TryGetValue(offset, out string resolvedName) || string.IsNullOrWhiteSpace(resolvedName))
                {
                    Warn(
                        ParseIssueCategory.Header,
                        string.Format(
                            CultureInfo.InvariantCulture,
                            "SPEC violation: COFF section header long-name offset /{0} for section #{1} is not present in the COFF string table.",
                            offset,
                            i + 1));
                    continue;
                }

                section.Name = Encoding.UTF8.GetBytes(resolvedName);
                sections[i] = section;
            }

            RefreshCoffSymbolSectionNames(sections);
        }

        private void RefreshCoffSymbolSectionNames(IReadOnlyList<IMAGE_SECTION_HEADER> sections)
        {
            if (sections == null || sections.Count == 0 || _coffSymbols.Count == 0)
            {
                return;
            }

            string[] sectionNames = sections.Select(section => NormalizeSectionName(section)).ToArray();
            CoffSymbolInfo[] updated = new CoffSymbolInfo[_coffSymbols.Count];
            bool anyUpdated = false;
            for (int i = 0; i < _coffSymbols.Count; i++)
            {
                CoffSymbolInfo symbol = _coffSymbols[i];
                string sectionName = symbol.SectionName;
                if (symbol.SectionNumber > 0 && symbol.SectionNumber <= sectionNames.Length)
                {
                    sectionName = sectionNames[symbol.SectionNumber - 1] ?? string.Empty;
                }

                if (!string.Equals(symbol.SectionName, sectionName, StringComparison.Ordinal))
                {
                    updated[i] = new CoffSymbolInfo(
                        symbol.Index,
                        symbol.Name,
                        symbol.Value,
                        symbol.SectionNumber,
                        sectionName,
                        symbol.Type,
                        symbol.TypeName,
                        symbol.StorageClass,
                        symbol.StorageClassName,
                        symbol.ScopeName,
                        symbol.AuxSymbolCount,
                        symbol.AuxData,
                        symbol.AuxSymbols?.ToArray() ?? Array.Empty<CoffAuxSymbolInfo>());
                    anyUpdated = true;
                }
                else
                {
                    updated[i] = symbol;
                }
            }

            if (!anyUpdated)
            {
                return;
            }

            _coffSymbols.Clear();
            _coffSymbols.AddRange(updated);
        }

        private string ResolveSectionName(IMAGE_SECTION_HEADER section, Dictionary<uint, string> coffStringTable)
        {
            string name = NormalizeSectionName(section);
            if (string.IsNullOrWhiteSpace(name))
            {
                return string.Empty;
            }

            if (name.Length > 1 &&
                name[0] == '/' &&
                uint.TryParse(name.Substring(1), NumberStyles.None, CultureInfo.InvariantCulture, out uint offset))
            {
                if (offset > 0 && coffStringTable != null && coffStringTable.TryGetValue(offset, out string resolved))
                {
                    return resolved;
                }
            }

            return name;
        }

        private Dictionary<uint, string> BuildCoffStringTableMap()
        {
            if (_coffStringTable.Count == 0)
            {
                return new Dictionary<uint, string>();
            }

            Dictionary<uint, string> map = new Dictionary<uint, string>();
            foreach (CoffStringTableEntry entry in _coffStringTable)
            {
                if (entry != null && !map.ContainsKey(entry.Offset))
                {
                    map[entry.Offset] = entry.Value ?? string.Empty;
                }
            }

            return map;
        }

        private static string[] DecodeSectionFlags(uint characteristics)
        {
            List<string> flags = new List<string>();
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_TYPE_NO_PAD) != 0)
            {
                flags.Add("TYPE_NO_PAD");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_CODE) != 0)
            {
                flags.Add("CNT_CODE");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)
            {
                flags.Add("CNT_INITIALIZED_DATA");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
            {
                flags.Add("CNT_UNINITIALIZED_DATA");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_LNK_OTHER) != 0)
            {
                flags.Add("LNK_OTHER");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_LNK_INFO) != 0)
            {
                flags.Add("LNK_INFO");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_LNK_REMOVE) != 0)
            {
                flags.Add("LNK_REMOVE");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_LNK_COMDAT) != 0)
            {
                flags.Add("LNK_COMDAT");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_GPREL) != 0)
            {
                flags.Add("GPREL");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_LNK_NRELOC_OVFL) != 0)
            {
                flags.Add("LNK_NRELOC_OVFL");
            }
            string alignment = DecodeSectionAlignment(characteristics);
            if (!string.IsNullOrEmpty(alignment))
            {
                flags.Add(alignment);
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_READ) != 0)
            {
                flags.Add("MEM_READ");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0)
            {
                flags.Add("MEM_WRITE");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0)
            {
                flags.Add("MEM_EXECUTE");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_DISCARDABLE) != 0)
            {
                flags.Add("MEM_DISCARDABLE");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_NOT_CACHED) != 0)
            {
                flags.Add("MEM_NOT_CACHED");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_NOT_PAGED) != 0)
            {
                flags.Add("MEM_NOT_PAGED");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_SHARED) != 0)
            {
                flags.Add("MEM_SHARED");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_LOCKED) != 0)
            {
                flags.Add("MEM_LOCKED");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_PRELOAD) != 0)
            {
                flags.Add("MEM_PRELOAD");
            }
            if ((characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_PURGEABLE) != 0)
            {
                flags.Add("MEM_PURGEABLE");
            }

            return flags.ToArray();
        }

        private static string DecodeSectionAlignment(uint characteristics)
        {
            uint alignBits = characteristics & 0x00F00000;
            switch (alignBits)
            {
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_1BYTES: return "ALIGN_1";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_2BYTES: return "ALIGN_2";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_4BYTES: return "ALIGN_4";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_8BYTES: return "ALIGN_8";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_16BYTES: return "ALIGN_16";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_32BYTES: return "ALIGN_32";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_64BYTES: return "ALIGN_64";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_128BYTES: return "ALIGN_128";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_256BYTES: return "ALIGN_256";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_512BYTES: return "ALIGN_512";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_1024BYTES: return "ALIGN_1024";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_2048BYTES: return "ALIGN_2048";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_4096BYTES: return "ALIGN_4096";
                case (uint)SectionCharacteristics.IMAGE_SCN_ALIGN_8192BYTES: return "ALIGN_8192";
                default: return string.Empty;
            }
        }

        internal static SectionPermissionInfo DecodeSectionPermissionsForTest(uint characteristics)
        {
            string[] flags = DecodeSectionFlags(characteristics);
            bool isReadable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_READ) != 0;
            bool isWritable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0;
            bool isExecutable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isCode = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_CODE) != 0;
            bool isInitData = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
            bool isUninitData = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
            bool isDiscardable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_DISCARDABLE) != 0;
            bool isShared = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_SHARED) != 0;
            bool hasSuspicious = isExecutable && isWritable;
            bool hasMismatch = (isCode && !isExecutable) || (isInitData && isExecutable);

            return new SectionPermissionInfo(
                "test",
                characteristics,
                flags,
                isReadable,
                isWritable,
                isExecutable,
                isCode,
                isInitData,
                isUninitData,
                isDiscardable,
                isShared,
                hasSuspicious,
                hasMismatch);
        }

        internal static SectionHeaderInfo BuildSectionHeaderInfoForTest(
            string name,
            int index,
            uint virtualAddress,
            uint virtualSize,
            uint rawPointer,
            uint rawSize,
            uint characteristics,
            uint fileAlignment,
            uint sectionAlignment,
            long fileLength)
        {
            bool isReadable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_READ) != 0;
            bool isWritable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0;
            bool isExecutable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isCode = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_CODE) != 0;
            bool isInitData = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
            bool isUninitData = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
            bool isDiscardable = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_DISCARDABLE) != 0;
            bool isShared = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_SHARED) != 0;
            bool hasSuspicious = isExecutable && isWritable;
            bool hasMismatch = (isCode && !isExecutable) || (isInitData && isExecutable);
            uint virtualPadding = virtualSize > rawSize ? virtualSize - rawSize : 0;
            uint rawPadding = rawSize > virtualSize ? rawSize - virtualSize : 0;
            bool sizeMismatch = virtualPadding > 0 || rawPadding > 0;
            bool hasRawData = rawSize > 0;
            bool hasVirtualData = virtualSize > 0;
            bool rawPointerAligned = fileAlignment == 0 || (rawPointer % fileAlignment) == 0;
            bool rawSizeAligned = fileAlignment == 0 || (rawSize % fileAlignment) == 0;
            bool virtualAligned = sectionAlignment == 0 || (virtualAddress % sectionAlignment) == 0;
            bool rawInBounds = fileLength <= 0 ||
                               (rawPointer == 0 && rawSize == 0) ||
                               (rawPointer + rawSize <= fileLength);
            string[] flags = DecodeSectionFlags(characteristics);
            return new SectionHeaderInfo(
                name,
                index,
                virtualAddress,
                virtualSize,
                rawPointer,
                rawSize,
                characteristics,
                flags,
                isReadable,
                isWritable,
                isExecutable,
                isCode,
                isInitData,
                isUninitData,
                isDiscardable,
                isShared,
                rawPointerAligned,
                rawSizeAligned,
                virtualAligned,
                rawInBounds,
                hasRawData,
                hasVirtualData,
                virtualPadding,
                rawPadding,
                sizeMismatch,
                hasSuspicious,
                hasMismatch,
                0,
                0);
        }

        internal static SectionDirectoryInfo[] BuildSectionDirectoryCoverageForTest(
            DataDirectoryInfo[] directories,
            string[] sectionNames,
            out string[] unmapped)
        {
            List<SectionDirectoryInfo> coverage = new List<SectionDirectoryInfo>();
            List<string> unmappedList = new List<string>();
            Dictionary<string, List<string>> map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            List<string> sectionOrder = new List<string>();

            if (sectionNames != null)
            {
                foreach (string sectionName in sectionNames)
                {
                    if (string.IsNullOrWhiteSpace(sectionName))
                    {
                        continue;
                    }
                    if (!map.ContainsKey(sectionName))
                    {
                        map[sectionName] = new List<string>();
                        sectionOrder.Add(sectionName);
                    }
                }
            }

            if (directories != null)
            {
                foreach (DataDirectoryInfo directory in directories)
                {
                    if (directory == null || !directory.IsPresent)
                    {
                        continue;
                    }

                    if (!directory.IsMapped || string.IsNullOrWhiteSpace(directory.SectionName))
                    {
                        unmappedList.Add(directory.Name);
                        continue;
                    }

                    if (!map.TryGetValue(directory.SectionName, out List<string> list))
                    {
                        list = new List<string>();
                        map[directory.SectionName] = list;
                        sectionOrder.Add(directory.SectionName);
                    }

                    if (!list.Any(name => string.Equals(name, directory.Name, StringComparison.OrdinalIgnoreCase)))
                    {
                        list.Add(directory.Name);
                    }
                }
            }

            foreach (string sectionName in sectionOrder.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                map.TryGetValue(sectionName, out List<string> list);
                string[] dirs = list == null ? Array.Empty<string>() : list.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToArray();
                coverage.Add(new SectionDirectoryInfo(sectionName, dirs));
            }

            unmapped = unmappedList.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToArray();
            return coverage.ToArray();
        }

        private static SectionRange[] BuildSectionRanges(List<IMAGE_SECTION_HEADER> sections)
        {
            if (sections == null || sections.Count == 0)
            {
                return Array.Empty<SectionRange>();
            }

            SectionRange[] ranges = new SectionRange[sections.Count];
            for (int i = 0; i < sections.Count; i++)
            {
                IMAGE_SECTION_HEADER section = sections[i];
                string name = section.Section.TrimEnd('\0');
                ranges[i] = new SectionRange(
                    name,
                    section.VirtualAddress,
                    section.VirtualSize,
                    section.PointerToRawData,
                    section.SizeOfRawData);
            }

            return ranges;
        }

        private const int PaddingScanLimit = 256 * 1024;

        private (int NonZero, int Sampled) CountNonZeroBytes(long offset, int size)
        {
            if (PEFileStream == null || size <= 0)
            {
                return (0, 0);
            }

            if (offset < 0 || offset >= PEFileStream.Length)
            {
                return (0, 0);
            }

            int toScan = Math.Min(size, PaddingScanLimit);
            long available = PEFileStream.Length - offset;
            if (available <= 0)
            {
                return (0, 0);
            }

            if (toScan > available)
            {
                toScan = (int)Math.Min(available, int.MaxValue);
            }

            if (toScan <= 0)
            {
                return (0, 0);
            }

            long originalPosition = PEFileStream.Position;
            int nonZero = 0;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Min(8192, toScan));
            try
            {
                if (!TrySetPosition(offset, toScan))
                {
                    return (0, 0);
                }

                int remaining = toScan;
                while (remaining > 0)
                {
                    int chunk = Math.Min(buffer.Length, remaining);
                    int read = PEFileStream.Read(buffer, 0, chunk);
                    if (read <= 0)
                    {
                        break;
                    }

                    for (int i = 0; i < read; i++)
                    {
                        if (buffer[i] != 0)
                        {
                            nonZero++;
                        }
                    }

                    remaining -= read;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }

            return (nonZero, toScan);
        }

        private static void AnalyzeSectionPaddingCore(
            IReadOnlyList<SectionRange> sections,
            uint sizeOfHeaders,
            long fileLength,
            Func<long, int, (int NonZero, int Sampled)> countNonZero,
            List<SectionGapInfo> gaps,
            List<SectionSlackInfo> slacks)
        {
            if (sections == null || sections.Count == 0)
            {
                return;
            }

            List<SectionRange> ordered = sections
                .Where(section => section.RawSize > 0)
                .OrderBy(section => section.RawPointer)
                .ToList();

            if (ordered.Count == 0)
            {
                return;
            }

            if (sizeOfHeaders > 0 && ordered[0].RawPointer > sizeOfHeaders)
            {
                long gapOffset = sizeOfHeaders;
                int gapSize = (int)Math.Min(ordered[0].RawPointer - sizeOfHeaders, int.MaxValue);
                if (gapSize > 0)
                {
                    if (fileLength > 0 && gapOffset + gapSize > fileLength)
                    {
                        gapSize = (int)Math.Max(0, fileLength - gapOffset);
                    }

                    (int nonZero, int sampled) = countNonZero(gapOffset, gapSize);
                    gaps.Add(new SectionGapInfo("Headers", ordered[0].Name, gapOffset, gapSize, nonZero, sampled));
                }
            }

            foreach (SectionRange section in ordered)
            {
                if (section.VirtualSize == 0 || section.RawSize <= section.VirtualSize)
                {
                    continue;
                }

                long slackOffset = section.RawPointer + section.VirtualSize;
                int slackSize = (int)Math.Min(section.RawSize - section.VirtualSize, int.MaxValue);
                if (slackSize <= 0)
                {
                    continue;
                }

                if (fileLength > 0 && slackOffset + slackSize > fileLength)
                {
                    slackSize = (int)Math.Max(0, fileLength - slackOffset);
                }

                if (slackSize <= 0)
                {
                    continue;
                }

                (int nonZero, int sampled) = countNonZero(slackOffset, slackSize);
                slacks.Add(new SectionSlackInfo(section.Name, slackOffset, slackSize, nonZero, sampled));
            }

            for (int i = 1; i < ordered.Count; i++)
            {
                SectionRange previous = ordered[i - 1];
                SectionRange current = ordered[i];
                long previousEnd = previous.RawPointer + previous.RawSize;
                if (current.RawPointer <= previousEnd)
                {
                    continue;
                }

                long gapOffset = previousEnd;
                int gapSize = (int)Math.Min(current.RawPointer - previousEnd, int.MaxValue);
                if (gapSize <= 0)
                {
                    continue;
                }

                if (fileLength > 0 && gapOffset + gapSize > fileLength)
                {
                    gapSize = (int)Math.Max(0, fileLength - gapOffset);
                }

                if (gapSize <= 0)
                {
                    continue;
                }

                (int nonZero, int sampled) = countNonZero(gapOffset, gapSize);
                gaps.Add(new SectionGapInfo(previous.Name, current.Name, gapOffset, gapSize, nonZero, sampled));
            }
        }

        internal static void AnalyzeSectionPaddingForTest(
            byte[] data,
            SectionRange[] sections,
            uint sizeOfHeaders,
            out SectionGapInfo[] gaps,
            out SectionSlackInfo[] slacks)
        {
            List<SectionGapInfo> gapList = new List<SectionGapInfo>();
            List<SectionSlackInfo> slackList = new List<SectionSlackInfo>();
            long length = data == null ? 0 : data.Length;

            (int NonZero, int Sampled) CountFromBuffer(long offset, int size)
            {
                if (data == null || size <= 0)
                {
                    return (0, 0);
                }

                if (offset < 0 || offset >= data.Length)
                {
                    return (0, 0);
                }

                int toScan = Math.Min(size, PaddingScanLimit);
                int available = (int)Math.Min(data.Length - offset, int.MaxValue);
                if (toScan > available)
                {
                    toScan = available;
                }

                if (toScan <= 0)
                {
                    return (0, 0);
                }

                int nonZero = 0;
                for (int i = 0; i < toScan; i++)
                {
                    if (data[(int)offset + i] != 0)
                    {
                        nonZero++;
                    }
                }

                return (nonZero, toScan);
            }

            AnalyzeSectionPaddingCore(sections ?? Array.Empty<SectionRange>(), sizeOfHeaders, length, CountFromBuffer, gapList, slackList);
            gaps = gapList.ToArray();
            slacks = slackList.ToArray();
        }

        private bool TryReadImportByName(List<IMAGE_SECTION_HEADER> sections, uint nameRva, out ushort hint, out string name)
        {
            hint = 0;
            name = string.Empty;

            if (!TryGetFileOffset(sections, nameRva, 2, out long fileOffset))
            {
                return false;
            }

            if (!TrySetPosition(fileOffset, 2))
            {
                return false;
            }

            hint = PEFile.ReadUInt16();
            if (!TryReadNullTerminatedString(fileOffset + 2, out string importName, 512))
            {
                return false;
            }

            name = importName;
            return true;
        }

        private static bool IsLikelyImportNameSection(IMAGE_SECTION_HEADER section)
        {
            return (section.Characteristics & SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) == 0;
        }

        private static bool IsLikelyImportName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 512)
            {
                return false;
            }

            for (int i = 0; i < name.Length; i++)
            {
                char ch = name[i];
                if (ch < 0x21 || ch > 0x7E)
                {
                    return false;
                }
            }

            return true;
        }

        private ImportThunkParseStats ParseImportThunks(
            string dllName,
            uint thunkTableRva,
            ImportThunkSource source,
            List<IMAGE_SECTION_HEADER> sections,
            bool isPe32Plus,
            List<ImportEntry> targetList)
        {
            if (thunkTableRva == 0)
            {
                return new ImportThunkParseStats(0, 0, true);
            }

            if (!TryGetFileOffset(sections, thunkTableRva, out long thunkOffset))
            {
                Warn(ParseIssueCategory.Imports, "Import thunk RVA not mapped to a section.");
                return new ImportThunkParseStats(0, 0, false);
            }

            int thunkSize = isPe32Plus ? 8 : 4;
            int maxIterations = 65536;
            bool terminated = false;
            bool warnedNullThunks = false;
            bool warnedUnmappedThunkEntry = false;
            bool warnedUnmappedNameRva = false;
            bool warnedExecutableNameRva = false;
            bool warnedInvalidName = false;
            int nullThunkCount = 0;
            int entryCount = 0;
            for (int index = 0; index < maxIterations; index++)
            {
                long entryOffset = thunkOffset + (index * thunkSize);
                if (!TrySetPosition(entryOffset, thunkSize))
                {
                    Warn(ParseIssueCategory.Imports, "Import thunk entry outside file bounds.");
                    break;
                }

                ulong value = isPe32Plus ? PEFile.ReadUInt64() : PEFile.ReadUInt32();
                if (value == 0)
                {
                    bool foundNonZero = false;
                    for (int lookahead = 1; lookahead <= 8; lookahead++)
                    {
                        long peekOffset = entryOffset + (lookahead * thunkSize);
                        if (!TrySetPosition(peekOffset, thunkSize))
                        {
                            break;
                        }

                        ulong peek = isPe32Plus ? PEFile.ReadUInt64() : PEFile.ReadUInt32();
                        if (peek != 0)
                        {
                            foundNonZero = true;
                            break;
                        }
                    }

                    if (!foundNonZero)
                    {
                        terminated = true;
                        break;
                    }

                    if (!warnedNullThunks)
                    {
                        Warn(ParseIssueCategory.Imports, $"Null thunk entry encountered in {dllName} before list terminator.");
                        warnedNullThunks = true;
                    }

                    nullThunkCount++;
                    continue;
                }

                ulong entryRva = (ulong)thunkTableRva + (ulong)(index * thunkSize);
                if (entryRva > uint.MaxValue)
                {
                    Warn(ParseIssueCategory.Imports, "Import thunk RVA exceeds supported limits.");
                    break;
                }

                uint thunkEntryRva = (uint)entryRva;
                if (!warnedUnmappedThunkEntry && !TryGetSectionByRvaRange(sections, thunkEntryRva, (uint)thunkSize, out _))
                {
                    Warn(ParseIssueCategory.Imports, $"Import thunk entry RVA not mapped to a section for {dllName}.");
                    warnedUnmappedThunkEntry = true;
                }

                bool isOrdinal = isPe32Plus
                    ? (value & 0x8000000000000000UL) != 0
                    : (value & 0x80000000UL) != 0;

                if (isOrdinal)
                {
                    ushort ordinal = (ushort)(value & 0xFFFF);
                    targetList.Add(new ImportEntry(dllName, string.Empty, 0, ordinal, true, source, thunkEntryRva));
                    entryCount++;
                    continue;
                }

                uint nameRva = (uint)value;
                entryCount++;

                if (!TryGetSectionByRvaRange(sections, nameRva, 2, out IMAGE_SECTION_HEADER nameSection))
                {
                    if (source == ImportThunkSource.ImportNameTable && !warnedUnmappedNameRva)
                    {
                        Warn(ParseIssueCategory.Imports, $"Import name RVA not mapped to a section for {dllName}.");
                        warnedUnmappedNameRva = true;
                    }
                    continue;
                }

                if (!IsLikelyImportNameSection(nameSection))
                {
                    if (source == ImportThunkSource.ImportNameTable && !warnedExecutableNameRva)
                    {
                        Warn(ParseIssueCategory.Imports, $"Import name RVA points to executable section for {dllName}.");
                        warnedExecutableNameRva = true;
                    }
                    continue;
                }

                if (TryReadImportByName(sections, nameRva, out ushort hint, out string importName) &&
                    IsLikelyImportName(importName))
                {
                    targetList.Add(new ImportEntry(dllName, importName, hint, 0, false, source, thunkEntryRva));
                }
                else if (source == ImportThunkSource.ImportNameTable)
                {
                    if (!warnedInvalidName)
                    {
                        Warn(ParseIssueCategory.Imports, "Import name entry could not be read.");
                        warnedInvalidName = true;
                    }
                }
            }

            if (!terminated)
            {
                Warn(ParseIssueCategory.Imports, $"Import thunk list for {dllName} did not terminate.");
            }

            return new ImportThunkParseStats(entryCount, nullThunkCount, terminated);
        }

        private void ParseDelayImportTable(
            IMAGE_DATA_DIRECTORY directory,
            List<IMAGE_SECTION_HEADER> sections,
            bool isPe32Plus,
            ulong imageBase)
        {
            if (!TryGetFileOffset(sections, directory.VirtualAddress, out long tableOffset))
            {
                Warn(ParseIssueCategory.Imports, "Delay import table RVA not mapped to a section.");
                return;
            }

            if (!TryGetIntSize(directory.Size, out int tableSize))
            {
                Warn(ParseIssueCategory.Imports, "Delay import table size exceeds supported limits.");
                return;
            }

            int descriptorSize = Marshal.SizeOf(typeof(IMAGE_DELAY_IMPORT_DESCRIPTOR));
            int descriptorCount = tableSize / descriptorSize;
            for (int i = 0; i < descriptorCount; i++)
            {
                long entryOffset = tableOffset + (i * descriptorSize);
                if (!TrySetPosition(entryOffset, descriptorSize))
                {
                    Warn(ParseIssueCategory.Imports, "Delay import descriptor outside file bounds.");
                    break;
                }

                byte[] buffer = new byte[descriptorSize];
                ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                IMAGE_DELAY_IMPORT_DESCRIPTOR descriptor = ByteArrayToStructure<IMAGE_DELAY_IMPORT_DESCRIPTOR>(buffer);

                if (descriptor.Attributes == 0 &&
                    descriptor.NameRVA == 0 &&
                    descriptor.ModuleHandleRVA == 0 &&
                    descriptor.ImportAddressTableRVA == 0 &&
                    descriptor.ImportNameTableRVA == 0)
                {
                    break;
                }

                bool usesRva = (descriptor.Attributes & 0x1) != 0;
                bool isBound = descriptor.TimeDateStamp != 0;
                uint nameRva = ConvertDelayImportRva(descriptor.NameRVA, usesRva, imageBase);
                uint moduleHandleRva = ConvertDelayImportRva(descriptor.ModuleHandleRVA, usesRva, imageBase);
                uint importAddressTableRva = ConvertDelayImportRva(descriptor.ImportAddressTableRVA, usesRva, imageBase);
                uint importNameTableRva = ConvertDelayImportRva(descriptor.ImportNameTableRVA, usesRva, imageBase);
                uint boundImportAddressTableRva = ConvertDelayImportRva(descriptor.BoundImportAddressTableRVA, usesRva, imageBase);
                uint unloadInformationTableRva = ConvertDelayImportRva(descriptor.UnloadInformationTableRVA, usesRva, imageBase);

                string dllName = string.Empty;
                if (nameRva != 0 && TryGetFileOffset(sections, nameRva, out long nameOffset))
                {
                    if (TryReadNullTerminatedString(nameOffset, out string name))
                    {
                        dllName = name;
                    }
                }

                if (string.IsNullOrWhiteSpace(dllName))
                {
                    dllName = "delayimport";
                }

                if (!imports.Contains(dllName))
                {
                    imports.Add(dllName);
                }

                ApiSetResolutionInfo apiSetResolution = ResolveApiSetResolution(dllName);
                _delayImportDescriptors.Add(new DelayImportDescriptorInfo(
                    dllName,
                    descriptor.Attributes,
                    usesRva,
                    isBound,
                    descriptor.TimeDateStamp,
                    moduleHandleRva,
                    importAddressTableRva,
                    importNameTableRva,
                    boundImportAddressTableRva,
                    unloadInformationTableRva,
                    apiSetResolution));

                if (importNameTableRva != 0)
                {
                    ParseImportThunks(dllName, importNameTableRva, ImportThunkSource.ImportNameTable, sections, isPe32Plus, _delayImportEntries);
                }

                if (importAddressTableRva != 0 && importAddressTableRva != importNameTableRva)
                {
                    ParseImportThunks(dllName, importAddressTableRva, ImportThunkSource.ImportAddressTable, sections, isPe32Plus, _delayImportEntries);
                }
            }
        }

        private uint ConvertDelayImportRva(uint value, bool usesRva, ulong imageBase)
        {
            if (value == 0)
            {
                return 0;
            }

            if (usesRva)
            {
                return value;
            }

            if (imageBase == 0)
            {
                Warn(ParseIssueCategory.Imports, "Delay import descriptor uses VA addresses without image base.");
                return 0;
            }

            if (!TryVaToRva(value, imageBase, out uint rva))
            {
                return 0;
            }

            return rva;
        }

        private void ParseBoundImportTable(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections)
        {
            if (!TryGetFileOffset(sections, directory.VirtualAddress, out long tableOffset))
            {
                Warn(ParseIssueCategory.Imports, "Bound import table RVA not mapped to a section.");
                return;
            }

            if (!TryGetIntSize(directory.Size, out int tableSize))
            {
                Warn(ParseIssueCategory.Imports, "Bound import table size exceeds supported limits.");
                return;
            }

            long tableEnd = tableOffset + tableSize;
            if (tableEnd < tableOffset || tableEnd > PEFileStream.Length)
            {
                Warn(ParseIssueCategory.Imports, "Bound import table exceeds file bounds.");
                return;
            }

            int descriptorSize = Marshal.SizeOf(typeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
            int forwarderSize = Marshal.SizeOf(typeof(IMAGE_BOUND_FORWARDER_REF));
            int maxEntries = 4096;
            long cursor = tableOffset;

            for (int i = 0; i < maxEntries && cursor + descriptorSize <= tableEnd; i++)
            {
                if (!TrySetPosition(cursor, descriptorSize))
                {
                    Warn(ParseIssueCategory.Imports, "Bound import descriptor outside file bounds.");
                    break;
                }

                byte[] buffer = new byte[descriptorSize];
                ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                IMAGE_BOUND_IMPORT_DESCRIPTOR descriptor = ByteArrayToStructure<IMAGE_BOUND_IMPORT_DESCRIPTOR>(buffer);

                if (descriptor.TimeDateStamp == 0 &&
                    descriptor.OffsetModuleName == 0 &&
                    descriptor.NumberOfModuleForwarderRefs == 0)
                {
                    break;
                }

                string dllName = "boundimport";
                if (descriptor.OffsetModuleName != 0)
                {
                    long nameOffset = tableOffset + descriptor.OffsetModuleName;
                    if (nameOffset >= tableOffset && nameOffset < tableEnd &&
                        TryReadNullTerminatedString(nameOffset, out string name) &&
                        !string.IsNullOrWhiteSpace(name))
                    {
                        dllName = name;
                    }
                }

                cursor += descriptorSize;
                List<BoundForwarderRef> forwarders = new List<BoundForwarderRef>();
                for (int j = 0; j < descriptor.NumberOfModuleForwarderRefs; j++)
                {
                    if (cursor + forwarderSize > tableEnd)
                    {
                        Warn(ParseIssueCategory.Imports, "Bound import forwarder entry exceeds table bounds.");
                        break;
                    }

                    if (!TrySetPosition(cursor, forwarderSize))
                    {
                        Warn(ParseIssueCategory.Imports, "Bound import forwarder entry outside file bounds.");
                        break;
                    }

                    byte[] fwdBuffer = new byte[forwarderSize];
                    ReadExactly(PEFileStream, fwdBuffer, 0, fwdBuffer.Length);
                    IMAGE_BOUND_FORWARDER_REF forwarder = ByteArrayToStructure<IMAGE_BOUND_FORWARDER_REF>(fwdBuffer);

                    string forwarderName = "forwarder";
                    if (forwarder.OffsetModuleName != 0)
                    {
                        long forwarderNameOffset = tableOffset + forwarder.OffsetModuleName;
                        if (forwarderNameOffset >= tableOffset && forwarderNameOffset < tableEnd &&
                            TryReadNullTerminatedString(forwarderNameOffset, out string name) &&
                            !string.IsNullOrWhiteSpace(name))
                        {
                            forwarderName = name;
                        }
                    }

                    forwarders.Add(new BoundForwarderRef(forwarderName, forwarder.TimeDateStamp));
                    cursor += forwarderSize;
                }

                _boundImports.Add(new BoundImportEntry(dllName, descriptor.TimeDateStamp, forwarders.ToArray()));
                if (!imports.Contains(dllName))
                {
                    imports.Add(dllName);
                }
            }
        }

        private void ParseBaseRelocationTable(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections)
        {
            _relocationAnomalies = new RelocationAnomalySummary(0, 0, 0, 0, 0, 0, 0, 0);
            if (!TryGetFileOffset(sections, directory.VirtualAddress, out long tableOffset))
            {
                Warn(ParseIssueCategory.Relocations, "Base relocation table RVA not mapped to a section.");
                return;
            }

            if (!TryGetIntSize(directory.Size, out int tableSize))
            {
                Warn(ParseIssueCategory.Relocations, "Base relocation table size exceeds supported limits.");
                return;
            }

            long end = tableOffset + tableSize;
            if (end < tableOffset || end > PEFileStream.Length)
            {
                Warn(ParseIssueCategory.Relocations, "Base relocation table exceeds file bounds.");
                return;
            }

            _baseRelocationSections.Clear();
            Dictionary<string, BaseRelocationSectionAccumulator> summaries = new Dictionary<string, BaseRelocationSectionAccumulator>(StringComparer.OrdinalIgnoreCase);
            int zeroSizedBlocks = 0;
            int emptyBlocks = 0;
            int invalidBlocks = 0;
            int orphanedBlocks = 0;
            int discardableBlocks = 0;
            int reservedTypeTotal = 0;
            int outOfRangeTotal = 0;
            int unmappedTotal = 0;

            int headerSize = Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION));
            long cursor = tableOffset;
            while (cursor + headerSize <= end)
            {
                if (!TrySetPosition(cursor, headerSize))
                {
                    WarnAt(ParseIssueCategory.Relocations, "Base relocation header outside file bounds.", cursor);
                    break;
                }

                byte[] buffer = new byte[headerSize];
                ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                IMAGE_BASE_RELOCATION header = ByteArrayToStructure<IMAGE_BASE_RELOCATION>(buffer);

                if (header.SizeOfBlock < headerSize)
                {
                    Warn(ParseIssueCategory.Relocations, "Base relocation block size is invalid.");
                    invalidBlocks++;
                    if (header.SizeOfBlock == 0)
                    {
                        zeroSizedBlocks++;
                    }
                    break;
                }

                if ((header.SizeOfBlock - headerSize) % 2 != 0)
                {
                    Warn(ParseIssueCategory.Relocations, "Base relocation block size is not aligned to 16-bit entries.");
                }

                long blockEnd = cursor + header.SizeOfBlock;
                if (blockEnd > end)
                {
                    Warn(ParseIssueCategory.Relocations, "Base relocation block exceeds table size.");
                    invalidBlocks++;
                    break;
                }

                int entryCount = (int)((header.SizeOfBlock - headerSize) / 2);
                if (entryCount == 0)
                {
                    emptyBlocks++;
                    Warn(ParseIssueCategory.Relocations, $"Base relocation block at 0x{header.VirtualAddress:X} contains no entries.");
                }
                int[] typeCounts = new int[16];
                int reservedTypeCount = 0;
                int outOfRangeCount = 0;
                int unmappedCount = 0;
                bool isPageAligned = _sectionAlignment > 0
                    ? (header.VirtualAddress % _sectionAlignment) == 0
                    : (header.VirtualAddress % 0x1000) == 0;
                if (!isPageAligned)
                {
                    Warn(ParseIssueCategory.Relocations, $"Base relocation page RVA 0x{header.VirtualAddress:X} is not aligned.");
                }

                bool blockMapped = TryGetSectionByRva(sections, header.VirtualAddress, out IMAGE_SECTION_HEADER blockSection);
                string blockSectionName = blockMapped ? NormalizeSectionName(blockSection.Section) : "(unmapped)";
                uint blockSectionRva = blockMapped ? blockSection.VirtualAddress : 0;
                uint blockSectionSize = blockMapped ? Math.Max(blockSection.VirtualSize, blockSection.SizeOfRawData) : 0;
                bool isDiscardable = blockMapped &&
                                     (blockSection.Characteristics & SectionCharacteristics.IMAGE_SCN_MEM_DISCARDABLE) != 0;
                if (isDiscardable)
                {
                    discardableBlocks++;
                }

                if (!blockMapped)
                {
                    orphanedBlocks++;
                }
                BaseRelocationSectionAccumulator accumulator = GetOrCreateRelocationSummary(summaries, blockSectionName, blockSectionRva, blockSectionSize);

                for (int i = 0; i < entryCount; i++)
                {
                    if (!TrySetPosition(cursor + headerSize + (i * 2), 2))
                    {
                        WarnAt(ParseIssueCategory.Relocations, "Base relocation entry outside file bounds.", cursor + headerSize + (i * 2));
                        break;
                    }

                    ushort entry = PEFile.ReadUInt16();
                    int type = (entry >> 12) & 0xF;
                    if (type >= 0 && type < typeCounts.Length)
                    {
                        typeCounts[type]++;
                    }

                    if (IsRelocationTypeReserved(_machineType, type))
                    {
                        reservedTypeCount++;
                    }

                    uint entryRva = header.VirtualAddress + (uint)(entry & 0x0FFF);
                    if (_sizeOfImage != 0 && entryRva >= _sizeOfImage)
                    {
                        outOfRangeCount++;
                    }
                    if (blockMapped && !TryGetSectionByRvaRange(sections, entryRva, 1, out _))
                    {
                        unmappedCount++;
                    }
                    if (accumulator.Samples.Count < 5)
                    {
                        accumulator.Samples.Add(new RelocationSampleInfo(entryRva, type, GetRelocationTypeName(_machineType, type)));
                    }
                }

                if (!blockMapped)
                {
                    unmappedCount = entryCount;
                }

                if (reservedTypeCount > 0)
                {
                    Warn(ParseIssueCategory.Relocations, $"Base relocation block at 0x{header.VirtualAddress:X} contains reserved relocation types.");
                }

                if (outOfRangeCount > 0)
                {
                    Warn(ParseIssueCategory.Relocations, $"Base relocation block at 0x{header.VirtualAddress:X} contains entries outside SizeOfImage.");
                }

                _baseRelocations.Add(new BaseRelocationBlockInfo(
                    header.VirtualAddress,
                    header.SizeOfBlock,
                    entryCount,
                    typeCounts,
                    reservedTypeCount,
                    outOfRangeCount,
                    unmappedCount,
                    isPageAligned));

                reservedTypeTotal += reservedTypeCount;
                outOfRangeTotal += outOfRangeCount;
                unmappedTotal += unmappedCount;

                accumulator.BlockCount++;
                accumulator.EntryCount += entryCount;
                accumulator.ReservedTypeCount += reservedTypeCount;
                accumulator.OutOfRangeCount += outOfRangeCount;
                accumulator.UnmappedCount += unmappedCount;
                for (int i = 0; i < typeCounts.Length; i++)
                {
                    accumulator.TypeCounts[i] += typeCounts[i];
                }
                cursor = blockEnd;
            }

            if (summaries.Count > 0)
            {
                foreach (BaseRelocationSectionAccumulator accumulator in summaries.Values)
                {
                    RelocationTypeSummary[] topTypes = BuildTopRelocationTypes(_machineType, accumulator.TypeCounts, 3);
                    _baseRelocationSections.Add(new BaseRelocationSectionSummary(
                        accumulator.SectionName,
                        accumulator.SectionRva,
                        accumulator.SectionSize,
                        accumulator.BlockCount,
                        accumulator.EntryCount,
                        accumulator.TypeCounts,
                        accumulator.ReservedTypeCount,
                        accumulator.OutOfRangeCount,
                        accumulator.UnmappedCount,
                        topTypes,
                        accumulator.Samples.ToArray()));
                }
            }

            if (orphanedBlocks > 0)
            {
                Warn(ParseIssueCategory.Relocations, $"Base relocation blocks reference unmapped sections: {orphanedBlocks}.");
            }

            if (discardableBlocks > 0)
            {
                Warn(ParseIssueCategory.Relocations, $"Base relocation blocks reside in discardable sections: {discardableBlocks}.");
            }

            _relocationAnomalies = BuildRelocationAnomalySummary(
                zeroSizedBlocks,
                emptyBlocks,
                invalidBlocks,
                orphanedBlocks,
                discardableBlocks,
                reservedTypeTotal,
                outOfRangeTotal,
                unmappedTotal);
        }

        private static RelocationAnomalySummary BuildRelocationAnomalySummary(
            int zeroSizedBlocks,
            int emptyBlocks,
            int invalidBlocks,
            int orphanedBlocks,
            int discardableBlocks,
            int reservedTypeCount,
            int outOfRangeEntryCount,
            int unmappedEntryCount)
        {
            return new RelocationAnomalySummary(
                zeroSizedBlocks,
                emptyBlocks,
                invalidBlocks,
                orphanedBlocks,
                discardableBlocks,
                reservedTypeCount,
                outOfRangeEntryCount,
                unmappedEntryCount);
        }

        private sealed class BaseRelocationSectionAccumulator
        {
            public string SectionName { get; }
            public uint SectionRva { get; }
            public uint SectionSize { get; }
            public int BlockCount { get; set; }
            public int EntryCount { get; set; }
            public int[] TypeCounts { get; } = new int[16];
            public int ReservedTypeCount { get; set; }
            public int OutOfRangeCount { get; set; }
            public int UnmappedCount { get; set; }
            public List<RelocationSampleInfo> Samples { get; } = new List<RelocationSampleInfo>();

            public BaseRelocationSectionAccumulator(string sectionName, uint sectionRva, uint sectionSize)
            {
                SectionName = sectionName ?? string.Empty;
                SectionRva = sectionRva;
                SectionSize = sectionSize;
            }
        }

        private static BaseRelocationSectionAccumulator GetOrCreateRelocationSummary(
            Dictionary<string, BaseRelocationSectionAccumulator> summaries,
            string sectionName,
            uint sectionRva,
            uint sectionSize)
        {
            string key = string.Concat(sectionName, "@", sectionRva.ToString("X", CultureInfo.InvariantCulture));
            if (!summaries.TryGetValue(key, out BaseRelocationSectionAccumulator accumulator))
            {
                accumulator = new BaseRelocationSectionAccumulator(sectionName, sectionRva, sectionSize);
                summaries[key] = accumulator;
            }

            return accumulator;
        }

        private static RelocationTypeSummary[] BuildTopRelocationTypes(MachineTypes machine, int[] typeCounts, int maxItems)
        {
            if (typeCounts == null || typeCounts.Length == 0 || maxItems <= 0)
            {
                return Array.Empty<RelocationTypeSummary>();
            }

            return typeCounts
                .Select((count, index) => new { index, count })
                .Where(item => item.count > 0)
                .OrderByDescending(item => item.count)
                .ThenBy(item => item.index)
                .Take(maxItems)
                .Select(item => new RelocationTypeSummary(item.index, GetRelocationTypeName(machine, item.index), item.count))
                .ToArray();
        }

        private static string GetRelocationTypeName(MachineTypes machine, int type)
        {
            switch (type)
            {
                case 0: return "ABSOLUTE";
                case 1: return "HIGH";
                case 2: return "LOW";
                case 3: return "HIGHLOW";
                case 4: return "HIGHADJ";
                case 5:
                    if (IsArmMachine(machine))
                    {
                        return "ARM_MOV32";
                    }
                    if (IsRiscVMachine(machine))
                    {
                        return "RISCV_HIGH20";
                    }
                    if (IsMipsMachine(machine))
                    {
                        return "MIPS_JMPADDR";
                    }
                    return "RESERVED";
                case 6:
                    return "RESERVED";
                case 7:
                    if (IsThumbMachine(machine))
                    {
                        return "THUMB_MOV32";
                    }
                    if (IsRiscVMachine(machine))
                    {
                        return "RISCV_LOW12I";
                    }
                    return "RESERVED";
                case 8:
                    if (IsRiscVMachine(machine))
                    {
                        return "RISCV_LOW12S";
                    }
                    if (machine == MachineTypes.IMAGE_FILE_MACHINE_LOONGARCH32)
                    {
                        return "LOONGARCH32_MARK_LA";
                    }
                    if (machine == MachineTypes.IMAGE_FILE_MACHINE_LOONGARCH64)
                    {
                        return "LOONGARCH64_MARK_LA";
                    }
                    return "RESERVED";
                case 9:
                    return IsMipsMachine(machine) ? "MIPS_JMPADDR16" : "RESERVED";
                case 10: return "DIR64";
                case 11: return "HIGH3ADJ";
                default: return string.Format(CultureInfo.InvariantCulture, "TYPE_{0}", type);
            }
        }

        private static bool IsRelocationTypeKnown(MachineTypes machine, int type)
        {
            switch (type)
            {
                case 0:
                case 1:
                case 2:
                case 3:
                case 4:
                case 10:
                case 11:
                    return true;
                case 5:
                    return IsArmMachine(machine) || IsRiscVMachine(machine) || IsMipsMachine(machine);
                case 6:
                    return false;
                case 7:
                    return IsThumbMachine(machine) || IsRiscVMachine(machine);
                case 8:
                    return IsRiscVMachine(machine) || IsLoongArchMachine(machine);
                case 9:
                    return IsMipsMachine(machine);
                default:
                    return false;
            }
        }

        private static bool IsRelocationTypeReserved(MachineTypes machine, int type)
        {
            return !IsRelocationTypeKnown(machine, type);
        }

        private static bool IsRiscVMachine(MachineTypes machine)
        {
            return machine == MachineTypes.IMAGE_FILE_MACHINE_RISCV32 ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_RISCV64 ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_RISCV128;
        }

        private static bool IsLoongArchMachine(MachineTypes machine)
        {
            return machine == MachineTypes.IMAGE_FILE_MACHINE_LOONGARCH32 ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_LOONGARCH64;
        }

        private static bool IsArmMachine(MachineTypes machine)
        {
            return machine == MachineTypes.IMAGE_FILE_MACHINE_ARM ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_ARMNT ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_THUMB;
        }

        private static bool IsThumbMachine(MachineTypes machine)
        {
            return machine == MachineTypes.IMAGE_FILE_MACHINE_THUMB ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_ARMNT;
        }

        private static bool IsMipsMachine(MachineTypes machine)
        {
            switch (machine)
            {
                case MachineTypes.IMAGE_FILE_MACHINE_R3000BE:
                case MachineTypes.IMAGE_FILE_MACHINE_R3000:
                case MachineTypes.IMAGE_FILE_MACHINE_R4000:
                case MachineTypes.IMAGE_FILE_MACHINE_R10000:
                case MachineTypes.IMAGE_FILE_MACHINE_WCEMIPSV2:
                case MachineTypes.IMAGE_FILE_MACHINE_MIPS16:
                case MachineTypes.IMAGE_FILE_MACHINE_MIPSFPU:
                case MachineTypes.IMAGE_FILE_MACHINE_MIPSFPU16:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsPairRelocationDisplacementCarrier(MachineTypes machine, ushort type)
        {
            if (IsMipsMachine(machine))
            {
                return type == 0x0025; // IMAGE_REL_MIPS_PAIR
            }

            if (machine == MachineTypes.IMAGE_FILE_MACHINE_M32R)
            {
                return type == 0x000B; // IMAGE_REL_M32R_PAIR
            }

            if (machine == MachineTypes.IMAGE_FILE_MACHINE_SH3 ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_SH3DSP ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_SH3E ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_SH4 ||
                machine == MachineTypes.IMAGE_FILE_MACHINE_SH5)
            {
                return type == 0x0018; // IMAGE_REL_SHM_PAIR
            }

            return false;
        }

        private static string GetMachineName(ushort machine)
        {
            MachineTypes type = (MachineTypes)machine;
            if (Enum.IsDefined(typeof(MachineTypes), type))
            {
                switch (type)
                {
                    case MachineTypes.IMAGE_FILE_MACHINE_TARGET_HOST: return "TARGET_HOST";
                    case MachineTypes.IMAGE_FILE_MACHINE_I386: return "x86";
                    case MachineTypes.IMAGE_FILE_MACHINE_AMD64: return "x64";
                    case MachineTypes.IMAGE_FILE_MACHINE_ARM: return "ARM";
                    case MachineTypes.IMAGE_FILE_MACHINE_ARMNT: return "ARMNT";
                    case MachineTypes.IMAGE_FILE_MACHINE_CHPE_X86: return "CHPE_X86";
                    case MachineTypes.IMAGE_FILE_MACHINE_ARM64: return "ARM64";
                    case MachineTypes.IMAGE_FILE_MACHINE_ARM64EC: return "ARM64EC";
                    case MachineTypes.IMAGE_FILE_MACHINE_ARM64X: return "ARM64X";
                    case MachineTypes.IMAGE_FILE_MACHINE_IA64: return "IA64";
                    case MachineTypes.IMAGE_FILE_MACHINE_EBC: return "EBC";
                    case MachineTypes.IMAGE_FILE_MACHINE_CEF: return "CEF";
                    case MachineTypes.IMAGE_FILE_MACHINE_POWERPC: return "PowerPC";
                    case MachineTypes.IMAGE_FILE_MACHINE_POWERPCFP: return "PowerPCFP";
                    case MachineTypes.IMAGE_FILE_MACHINE_R3000BE: return "R3000BE";
                    case MachineTypes.IMAGE_FILE_MACHINE_R3000: return "R3000";
                    case MachineTypes.IMAGE_FILE_MACHINE_R4000: return "R4000";
                    case MachineTypes.IMAGE_FILE_MACHINE_R10000: return "R10000";
                    case MachineTypes.IMAGE_FILE_MACHINE_ALPHA_AXP: return "Alpha AXP";
                    case MachineTypes.IMAGE_FILE_MACHINE_ALPHA_AXP64: return "Alpha AXP64";
                    case MachineTypes.IMAGE_FILE_MACHINE_SH3E: return "SH3E";
                    case MachineTypes.IMAGE_FILE_MACHINE_TRICORE: return "TRICORE";
                    case MachineTypes.IMAGE_FILE_MACHINE_MIPS16: return "MIPS16";
                    case MachineTypes.IMAGE_FILE_MACHINE_MIPSFPU: return "MIPSFPU";
                    case MachineTypes.IMAGE_FILE_MACHINE_MIPSFPU16: return "MIPSFPU16";
                    case MachineTypes.IMAGE_FILE_MACHINE_LOONGARCH32: return "LoongArch32";
                    case MachineTypes.IMAGE_FILE_MACHINE_LOONGARCH64: return "LoongArch64";
                    case MachineTypes.IMAGE_FILE_MACHINE_RISCV32: return "RISC-V32";
                    case MachineTypes.IMAGE_FILE_MACHINE_RISCV64: return "RISC-V64";
                    case MachineTypes.IMAGE_FILE_MACHINE_RISCV128: return "RISC-V128";
                    case MachineTypes.IMAGE_FILE_MACHINE_THUMB: return "Thumb";
                    case MachineTypes.IMAGE_FILE_MACHINE_PURE_MSIL: return "MSIL";
                    default: return type.ToString();
                }
            }

            return string.Format(CultureInfo.InvariantCulture, "0x{0:X4}", machine);
        }

        private static string[] DecodeCoffCharacteristics(ushort value)
        {
            if (value == 0)
            {
                return Array.Empty<string>();
            }

            List<string> flags = new List<string>();
            foreach (Characteristics flag in Enum.GetValues(typeof(Characteristics)))
            {
                if (flag == 0)
                {
                    continue;
                }

                if ((value & (ushort)flag) != 0)
                {
                    flags.Add(flag.ToString());
                }
            }

            return flags.ToArray();
        }

        private static string GetCoffRelocationTypeName(MachineTypes machine, ushort type)
        {
            switch (machine)
            {
                case MachineTypes.IMAGE_FILE_MACHINE_I386:
                    switch (type)
                    {
                        case 0x0000: return "ABSOLUTE";
                        case 0x0001: return "DIR16";
                        case 0x0002: return "REL16";
                        case 0x0006: return "DIR32";
                        case 0x0007: return "DIR32NB";
                        case 0x0009: return "SEG12";
                        case 0x000A: return "SECTION";
                        case 0x000B: return "SECREL";
                        case 0x000C: return "TOKEN";
                        case 0x000D: return "SECREL7";
                        case 0x0014: return "REL32";
                        default: return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
                    }
                case MachineTypes.IMAGE_FILE_MACHINE_AMD64:
                    switch (type)
                    {
                        case 0x0000: return "ABSOLUTE";
                        case 0x0001: return "ADDR64";
                        case 0x0002: return "ADDR32";
                        case 0x0003: return "ADDR32NB";
                        case 0x0004: return "REL32";
                        case 0x0005: return "REL32_1";
                        case 0x0006: return "REL32_2";
                        case 0x0007: return "REL32_3";
                        case 0x0008: return "REL32_4";
                        case 0x0009: return "REL32_5";
                        case 0x000A: return "SECTION";
                        case 0x000B: return "SECREL";
                        case 0x000C: return "SECREL7";
                        case 0x000D: return "TOKEN";
                        case 0x000E: return "SREL32";
                        case 0x000F: return "PAIR";
                        case 0x0010: return "SSPAN32";
                        default: return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
                    }
                case MachineTypes.IMAGE_FILE_MACHINE_ARM:
                case MachineTypes.IMAGE_FILE_MACHINE_ARMNT:
                case MachineTypes.IMAGE_FILE_MACHINE_THUMB:
                    switch (type)
                    {
                        case 0x0000: return "ABSOLUTE";
                        case 0x0001: return "ADDR32";
                        case 0x0002: return "ADDR32NB";
                        case 0x0003: return "BRANCH24";
                        case 0x0004: return "BRANCH11";
                        case 0x000A: return "REL32";
                        case 0x000B: return "BLX24";
                        case 0x000C: return "BLX11";
                        case 0x000D: return "TOKEN";
                        case 0x000E: return "SECTION";
                        case 0x000F: return "SECREL";
                        case 0x0010: return "ARM_MOV32";
                        case 0x0011: return "THUMB_MOV32";
                        case 0x0012: return "THUMB_BRANCH20";
                        case 0x0013: return "UNUSED";
                        case 0x0014: return "THUMB_BRANCH24";
                        case 0x0015: return "THUMB_BLX23";
                        case 0x0016: return "PAIR";
                        default: return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
                    }
                case MachineTypes.IMAGE_FILE_MACHINE_ARM64:
                case MachineTypes.IMAGE_FILE_MACHINE_ARM64EC:
                case MachineTypes.IMAGE_FILE_MACHINE_ARM64X:
                    switch (type)
                    {
                        case 0x0000: return "ABSOLUTE";
                        case 0x0001: return "ADDR32";
                        case 0x0002: return "ADDR32NB";
                        case 0x0003: return "BRANCH26";
                        case 0x0004: return "PAGEBASE_REL21";
                        case 0x0005: return "REL21";
                        case 0x0006: return "PAGEOFFSET_12A";
                        case 0x0007: return "PAGEOFFSET_12L";
                        case 0x0008: return "SECREL";
                        case 0x0009: return "SECREL_LOW12A";
                        case 0x000A: return "SECREL_HIGH12A";
                        case 0x000B: return "SECREL_LOW12L";
                        case 0x000C: return "TOKEN";
                        case 0x000D: return "SECTION";
                        case 0x000E: return "ADDR64";
                        case 0x000F: return "BRANCH19";
                        case 0x0010: return "BRANCH14";
                        case 0x0011: return "REL32";
                        default: return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
                    }
                case MachineTypes.IMAGE_FILE_MACHINE_IA64:
                    switch (type)
                    {
                        case 0x0000: return "ABSOLUTE";
                        case 0x0001: return "IMM14";
                        case 0x0002: return "IMM22";
                        case 0x0003: return "IMM64";
                        case 0x0004: return "DIR32";
                        case 0x0005: return "DIR64";
                        case 0x0006: return "PCREL21B";
                        case 0x0007: return "PCREL21M";
                        case 0x0008: return "PCREL21F";
                        case 0x0009: return "GPREL22";
                        case 0x000A: return "LTOFF22";
                        case 0x000B: return "SECTION";
                        case 0x000C: return "SECREL22";
                        case 0x000D: return "SECREL64I";
                        case 0x000E: return "SECREL32";
                        case 0x0010: return "DIR32NB";
                        case 0x0011: return "SREL14";
                        case 0x0012: return "SREL22";
                        case 0x0013: return "SREL32";
                        case 0x0014: return "UREL32";
                        case 0x0015: return "PCREL60X";
                        case 0x0016: return "PCREL60B";
                        case 0x0017: return "PCREL60F";
                        case 0x0018: return "PCREL60I";
                        case 0x0019: return "PCREL60M";
                        case 0x001A: return "IMMGPREL64";
                        case 0x001B: return "TOKEN";
                        case 0x001C: return "GPREL32";
                        case 0x001F: return "ADDEND";
                        default: return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
                    }
                case MachineTypes.IMAGE_FILE_MACHINE_POWERPC:
                case MachineTypes.IMAGE_FILE_MACHINE_POWERPCFP:
                    switch (type)
                    {
                        case 0x0000: return "ABSOLUTE";
                        case 0x0001: return "ADDR64";
                        case 0x0002: return "ADDR32";
                        case 0x0003: return "ADDR24";
                        case 0x0004: return "ADDR16";
                        case 0x0005: return "ADDR14";
                        case 0x0006: return "REL24";
                        case 0x0007: return "REL14";
                        case 0x000A: return "ADDR32NB";
                        case 0x000B: return "SECREL";
                        case 0x000C: return "SECTION";
                        case 0x000F: return "SECREL16";
                        case 0x0010: return "REFHI";
                        case 0x0011: return "REFLO";
                        case 0x0012: return "PAIR";
                        case 0x0013: return "SECRELLO";
                        case 0x0015: return "GPREL";
                        case 0x0016: return "TOKEN";
                        default: return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
                    }
                case MachineTypes.IMAGE_FILE_MACHINE_R3000BE:
                case MachineTypes.IMAGE_FILE_MACHINE_R3000:
                case MachineTypes.IMAGE_FILE_MACHINE_R4000:
                case MachineTypes.IMAGE_FILE_MACHINE_R10000:
                case MachineTypes.IMAGE_FILE_MACHINE_WCEMIPSV2:
                case MachineTypes.IMAGE_FILE_MACHINE_MIPS16:
                case MachineTypes.IMAGE_FILE_MACHINE_MIPSFPU:
                case MachineTypes.IMAGE_FILE_MACHINE_MIPSFPU16:
                    switch (type)
                    {
                        case 0x0000: return "ABSOLUTE";
                        case 0x0001: return "REFHALF";
                        case 0x0002: return "REFWORD";
                        case 0x0003: return "JMPADDR";
                        case 0x0004: return "REFHI";
                        case 0x0005: return "REFLO";
                        case 0x0006: return "GPREL";
                        case 0x0007: return "LITERAL";
                        case 0x000A: return "SECTION";
                        case 0x000B: return "SECREL";
                        case 0x000C: return "SECRELLO";
                        case 0x000D: return "SECRELHI";
                        case 0x0010: return "JMPADDR16";
                        case 0x0022: return "REFWORDNB";
                        case 0x0025: return "PAIR";
                        default: return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
                    }
                case MachineTypes.IMAGE_FILE_MACHINE_SH3:
                case MachineTypes.IMAGE_FILE_MACHINE_SH3DSP:
                case MachineTypes.IMAGE_FILE_MACHINE_SH3E:
                case MachineTypes.IMAGE_FILE_MACHINE_SH4:
                case MachineTypes.IMAGE_FILE_MACHINE_SH5:
                    switch (type)
                    {
                        case 0x0000: return "ABSOLUTE";
                        case 0x0001: return "DIRECT16";
                        case 0x0002: return "DIRECT32";
                        case 0x0003: return "DIRECT8";
                        case 0x0004: return "DIRECT8_WORD";
                        case 0x0005: return "DIRECT8_LONG";
                        case 0x0006: return "DIRECT4";
                        case 0x0007: return "DIRECT4_WORD";
                        case 0x0008: return "DIRECT4_LONG";
                        case 0x0009: return "PCREL8_WORD";
                        case 0x000A: return "PCREL8_LONG";
                        case 0x000B: return "PCREL12_WORD";
                        case 0x000C: return "STARTOF_SECTION";
                        case 0x000D: return "SIZEOF_SECTION";
                        case 0x000E: return "SECTION";
                        case 0x000F: return "SECREL";
                        case 0x0010: return "DIRECT32_NB";
                        case 0x0011: return "GPREL4_LONG";
                        case 0x0012: return "TOKEN";
                        case 0x0013: return "SHM_PCRELPT";
                        case 0x0014: return "SHM_REFLO";
                        case 0x0015: return "SHM_REFHALF";
                        case 0x0016: return "SHM_RELLO";
                        case 0x0017: return "SHM_RELHALF";
                        case 0x0018: return "SHM_PAIR";
                        case 0x8000: return "SHM_NOMODE";
                        default: return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
                    }
                case MachineTypes.IMAGE_FILE_MACHINE_M32R:
                    switch (type)
                    {
                        case 0x0000: return "ABSOLUTE";
                        case 0x0001: return "ADDR32";
                        case 0x0002: return "ADDR32NB";
                        case 0x0003: return "ADDR24";
                        case 0x0004: return "GPREL16";
                        case 0x0005: return "PCREL24";
                        case 0x0006: return "PCREL16";
                        case 0x0007: return "PCREL8";
                        case 0x0008: return "REFHALF";
                        case 0x0009: return "REFHI";
                        case 0x000A: return "REFLO";
                        case 0x000B: return "PAIR";
                        case 0x000C: return "SECTION";
                        case 0x000D: return "SECREL";
                        case 0x000E: return "TOKEN";
                        default: return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
                    }
                default:
                    return string.Format(CultureInfo.InvariantCulture, "TYPE_0x{0:X4}", type);
            }
        }

        private static string GetComdatSelectionName(byte selection)
        {
            switch (selection)
            {
                case 0: return "NONE";
                case 1: return "NODUPLICATES";
                case 2: return "ANY";
                case 3: return "SAME_SIZE";
                case 4: return "EXACT_MATCH";
                case 5: return "ASSOCIATIVE";
                case 6: return "LARGEST";
                case 7: return "NEWEST";
                default: return string.Format(CultureInfo.InvariantCulture, "0x{0:X2}", selection);
            }
        }

        private static string GetCoffStorageClassName(byte storageClass)
        {
            switch (storageClass)
            {
                case 0x00: return "NULL";
                case 0x01: return "AUTOMATIC";
                case 0x02: return "EXTERNAL";
                case 0x03: return "STATIC";
                case 0x04: return "REGISTER";
                case 0x05: return "EXTERNAL_DEF";
                case 0x06: return "LABEL";
                case 0x07: return "UNDEFINED_LABEL";
                case 0x08: return "MEMBER_OF_STRUCT";
                case 0x09: return "ARGUMENT";
                case 0x0A: return "STRUCT_TAG";
                case 0x0B: return "MEMBER_OF_UNION";
                case 0x0C: return "UNION_TAG";
                case 0x0D: return "TYPE_DEFINITION";
                case 0x0E: return "UNDEFINED_STATIC";
                case 0x0F: return "ENUM_TAG";
                case 0x10: return "MEMBER_OF_ENUM";
                case 0x11: return "REGISTER_PARAM";
                case 0x12: return "BIT_FIELD";
                case 0x64: return "BLOCK";
                case 0x65: return "FUNCTION";
                case 0x66: return "END_OF_STRUCT";
                case 0x67: return "FILE";
                case 0x68: return "SECTION";
                case 0x69: return "WEAK_EXTERNAL";
                case 0x6B: return "CLR_TOKEN";
                case 0xFF: return "END_OF_FUNCTION";
                default: return string.Format(CultureInfo.InvariantCulture, "0x{0:X2}", storageClass);
            }
        }

        private static string GetCoffSymbolScopeName(short sectionNumber, byte storageClass)
        {
            if (sectionNumber == 0)
            {
                return "Undefined";
            }

            if (sectionNumber == -1)
            {
                return "Absolute";
            }

            if (sectionNumber == -2)
            {
                return "Debug";
            }

            switch (storageClass)
            {
                case 0x02: return "External";
                case 0x03: return "Static";
                case 0x67: return "File";
                case 0x68: return "Section";
                case 0x69: return "WeakExternal";
                default: return "Other";
            }
        }

        private static string GetWeakExternalCharacteristicsName(uint value)
        {
            switch (value)
            {
                case 1: return "SEARCH_NOLIBRARY";
                case 2: return "SEARCH_LIBRARY";
                case 3: return "SEARCH_ALIAS";
                default: return string.Format(CultureInfo.InvariantCulture, "0x{0:X8}", value);
            }
        }

        private static string NormalizeSectionName(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return string.Empty;
            }

            int nullIndex = name.IndexOf('\0');
            if (nullIndex >= 0)
            {
                name = name.Substring(0, nullIndex);
            }

            return name.Trim();
        }

        private void ParseExceptionDirectory(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections)
        {
            _exceptionDirectoryRva = directory.VirtualAddress;
            _exceptionDirectorySize = directory.Size;
            _exceptionDirectorySectionName = string.Empty;
            _exceptionDirectoryInPdata = false;
            if (directory.Size > 0 && TryGetSectionByRva(sections, directory.VirtualAddress, out IMAGE_SECTION_HEADER exceptionSection))
            {
                _exceptionDirectorySectionName = NormalizeSectionName(exceptionSection.Section);
                _exceptionDirectoryInPdata = string.Equals(_exceptionDirectorySectionName, ".pdata", StringComparison.OrdinalIgnoreCase);

                bool hasPdata = sections.Any(s => string.Equals(NormalizeSectionName(s.Section), ".pdata", StringComparison.OrdinalIgnoreCase));
                if (hasPdata && !_exceptionDirectoryInPdata)
                {
                    Warn(ParseIssueCategory.Sections, "Exception directory is not located in the .pdata section.");
                }

                uint sectionSize = Math.Max(exceptionSection.VirtualSize, exceptionSection.SizeOfRawData);
                ulong endRva = (ulong)directory.VirtualAddress + (ulong)directory.Size;
                ulong sectionEnd = (ulong)exceptionSection.VirtualAddress + sectionSize;
                if (directory.Size > 0 && endRva > sectionEnd)
                {
                    Warn(ParseIssueCategory.Sections, "Exception directory exceeds the section bounds.");
                }
            }

            if (!TryGetFileOffset(sections, directory.VirtualAddress, out long tableOffset))
            {
                Warn(ParseIssueCategory.Sections, "Exception directory RVA not mapped to a section.");
                return;
            }

            if (!TryGetIntSize(directory.Size, out int tableSize))
            {
                Warn(ParseIssueCategory.Sections, "Exception directory size exceeds supported limits.");
                return;
            }

            if (tableSize == 0)
            {
                return;
            }

            bool isArm64 = _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARM64 ||
                _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARM64EC ||
                _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARM64X;
            bool isArm32 = _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARM ||
                _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARMNT;
            int entrySize = (isArm64 || isArm32) ? 8 : 12;

            if (tableSize % entrySize != 0)
            {
                Warn(ParseIssueCategory.Sections, "Exception directory size is not aligned to runtime function entries.");
            }

            int entryCount = tableSize / entrySize;
            for (int i = 0; i < entryCount; i++)
            {
                long entryOffset = tableOffset + (i * entrySize);
                if (!TrySetPosition(entryOffset, entrySize))
                {
                    WarnAt(ParseIssueCategory.Sections, "Exception directory entry outside file bounds.", entryOffset);
                    break;
                }

                if (entrySize == 12)
                {
                    uint begin = PEFile.ReadUInt32();
                    uint end = PEFile.ReadUInt32();
                    uint unwind = PEFile.ReadUInt32();
                    _exceptionFunctions.Add(new ExceptionFunctionInfo(begin, end, unwind));
                    continue;
                }

                uint functionBegin = PEFile.ReadUInt32();
                uint unwindData = PEFile.ReadUInt32();
                uint flag = unwindData & 0x3;
                uint unwindRva = 0;
                uint functionEnd = 0;

                if (flag == 0)
                {
                    unwindRva = unwindData;
                    if (isArm64)
                    {
                        if (TryReadArm64FunctionLength(sections, unwindRva, out int lengthBytes) && lengthBytes > 0)
                        {
                            functionEnd = functionBegin + (uint)lengthBytes;
                        }
                    }
                    else if (isArm32)
                    {
                        if (TryReadArm32FunctionLength(sections, unwindRva, out int lengthBytes) && lengthBytes > 0)
                        {
                            functionEnd = functionBegin + (uint)lengthBytes;
                        }
                    }
                }
                else if (isArm64)
                {
                    if (TryDecodeArm64PackedFunctionLength(unwindData, out int lengthBytes) && lengthBytes > 0)
                    {
                        functionEnd = functionBegin + (uint)lengthBytes;
                    }
                    else
                    {
                        Warn(ParseIssueCategory.Sections, "Packed ARM64 exception data could not be decoded.");
                    }
                }
                else if (isArm32)
                {
                    Warn(ParseIssueCategory.Sections, "Packed ARM exception data is not decoded.");
                }

                _exceptionFunctions.Add(new ExceptionFunctionInfo(functionBegin, functionEnd, unwindRva));
            }
        }

        private void BuildExceptionDirectorySummary(List<IMAGE_SECTION_HEADER> sections)
        {
            if (_exceptionFunctions.Count == 0)
            {
                _exceptionSummary = null;
                _unwindInfoDetails.Clear();
                _arm64UnwindInfoDetails.Clear();
                _arm32UnwindInfoDetails.Clear();
                _ia64UnwindInfoDetails.Clear();
                return;
            }

            bool isAmd64 = _machineType == MachineTypes.IMAGE_FILE_MACHINE_AMD64;
            bool isArm64 = _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARM64 ||
                _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARM64EC ||
                _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARM64X;
            bool isArm32 = _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARM ||
                _machineType == MachineTypes.IMAGE_FILE_MACHINE_ARMNT;
            bool isIa64 = _machineType == MachineTypes.IMAGE_FILE_MACHINE_IA64;
            _unwindInfoDetails.Clear();
            _arm64UnwindInfoDetails.Clear();
            _arm32UnwindInfoDetails.Clear();
            _ia64UnwindInfoDetails.Clear();
            if (isAmd64)
            {
                ParseUnwindInfoDetails(sections);
            }
            else if (isArm64)
            {
                ParseArm64UnwindInfoDetails(sections);
            }
            else if (isArm32)
            {
                ParseArm32UnwindInfoDetails(sections);
            }
            else if (isIa64)
            {
                ParseIa64UnwindInfoDetails(sections);
            }

            TryGetUnwindVersion tryGetVersion = null;
            if (isAmd64)
            {
                tryGetVersion = (uint rva, out byte version) => TryReadUnwindVersion(sections, rva, out version);
            }
            else if (isArm64)
            {
                tryGetVersion = (uint rva, out byte version) => TryReadArm64UnwindVersion(sections, rva, out version);
            }
            else if (isArm32)
            {
                tryGetVersion = (uint rva, out byte version) => TryReadArm32UnwindVersion(sections, rva, out version);
            }
            else if (isIa64)
            {
                tryGetVersion = (uint rva, out byte version) => TryReadIa64UnwindVersion(sections, rva, out version);
            }

            _exceptionSummary = BuildExceptionDirectorySummaryCore(
                _exceptionFunctions,
                _exceptionDirectoryRva,
                _exceptionDirectorySize,
                _exceptionDirectorySectionName,
                _exceptionDirectoryInPdata,
                _sizeOfImage,
                isAmd64 || isArm64 || isArm32 || isIa64,
                tryGetVersion);
        }

        private void ParseUnwindInfoDetails(List<IMAGE_SECTION_HEADER> sections)
        {
            if (_exceptionFunctions.Count == 0 || PEFileStream == null || PEFile == null)
            {
                return;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                foreach (ExceptionFunctionInfo func in _exceptionFunctions)
                {
                    if (func.UnwindInfoAddress == 0)
                    {
                        continue;
                    }

                    if (!TryGetFileOffset(sections, func.UnwindInfoAddress, out long offset))
                    {
                        Warn(ParseIssueCategory.Sections, "Unwind info RVA not mapped to a section.");
                        continue;
                    }

                    if (!TrySetPosition(offset, 4))
                    {
                        Warn(ParseIssueCategory.Sections, "Unwind info header outside file bounds.");
                        continue;
                    }

                    byte verFlags = (byte)PEFile.ReadByte();
                    byte prologSize = (byte)PEFile.ReadByte();
                    byte codeCount = (byte)PEFile.ReadByte();
                    byte frame = (byte)PEFile.ReadByte();

                    int totalBytes = 4 + (codeCount * 2);
                    if (totalBytes < 4 || !TrySetPosition(offset, totalBytes))
                    {
                        Warn(ParseIssueCategory.Sections, "Unwind info size exceeds file bounds.");
                        continue;
                    }

                    byte[] buffer = new byte[totalBytes];
                    ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                    if (TryParseUnwindInfoDetail(func, buffer, out UnwindInfoDetail detail))
                    {
                        _unwindInfoDetails.Add(detail);
                        if (detail.PrologSizeExceedsFunction)
                        {
                            Warn(ParseIssueCategory.Sections, "Unwind prolog size exceeds function length.");
                        }
                    }
                    else
                    {
                        Warn(ParseIssueCategory.Sections, "Unwind info could not be parsed.");
                    }
                }
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private void ParseArm64UnwindInfoDetails(List<IMAGE_SECTION_HEADER> sections)
        {
            if (_exceptionFunctions.Count == 0 || PEFileStream == null || PEFile == null)
            {
                return;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                foreach (ExceptionFunctionInfo func in _exceptionFunctions)
                {
                    if (func.UnwindInfoAddress == 0)
                    {
                        continue;
                    }

                    if (!TryGetFileOffset(sections, func.UnwindInfoAddress, out long offset))
                    {
                        Warn(ParseIssueCategory.Sections, "ARM64 unwind info RVA not mapped to a section.");
                        continue;
                    }

                    if (!TrySetPosition(offset, 4))
                    {
                        Warn(ParseIssueCategory.Sections, "ARM64 unwind info header outside file bounds.");
                        continue;
                    }

                    uint header = PEFile.ReadUInt32();
                    bool hasEpilogFlag = ((header >> 21) & 0x01) != 0;
                    bool hasExceptionData = ((header >> 20) & 0x01) != 0;
                    int epilogCount = (int)((header >> 22) & 0x1F);
                    int codeWords = (int)((header >> 27) & 0x1F);
                    int headerSize = 4;

                    if (epilogCount == 0 && codeWords == 0)
                    {
                        if (!TrySetPosition(offset + 4, 4))
                        {
                            Warn(ParseIssueCategory.Sections, "ARM64 unwind extended header outside file bounds.");
                            continue;
                        }

                        uint extended = PEFile.ReadUInt32();
                        epilogCount = (int)(extended & 0xFFFF);
                        codeWords = (int)((extended >> 16) & 0xFF);
                        headerSize = 8;
                    }

                    int epilogScopeBytes = (!hasEpilogFlag && epilogCount > 0) ? epilogCount * 4 : 0;
                    int codeBytes = codeWords * 4;
                    int sizeBytes = headerSize + epilogScopeBytes + codeBytes + (hasExceptionData ? 4 : 0);
                    if (sizeBytes < 4 || !TrySetPosition(offset, sizeBytes))
                    {
                        Warn(ParseIssueCategory.Sections, "ARM64 unwind info size exceeds file bounds.");
                        continue;
                    }

                    byte[] buffer = new byte[sizeBytes];
                    ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                    if (TryParseArm64UnwindInfoDetail(func, buffer, out Arm64UnwindInfoDetail detail))
                    {
                        _arm64UnwindInfoDetails.Add(detail);
                        uint functionSize = func.EndAddress > func.BeginAddress
                            ? func.EndAddress - func.BeginAddress
                            : 0;
                        if (functionSize > 0 && detail.FunctionLengthBytes > functionSize)
                        {
                            Warn(ParseIssueCategory.Sections, "ARM64 unwind function length exceeds function size.");
                        }

                        if (detail.HasXFlag && detail.ExceptionHandlerRva == 0)
                        {
                            Warn(ParseIssueCategory.Sections, "ARM64 unwind has exception data flag set but handler RVA is missing.");
                        }

                        if (detail.EpilogScopes.Any(scope => !scope.ReservedBitsValid))
                        {
                            Warn(ParseIssueCategory.Sections, "ARM64 unwind epilog scope has non-zero reserved bits.");
                        }

                        if (detail.EpilogScopes.Any(scope => !scope.HasValidIndex))
                        {
                            Warn(ParseIssueCategory.Sections, "ARM64 unwind epilog scope has an invalid code index.");
                        }

                        if (detail.EpilogScopes.Any(scope => !scope.HasValidOffset))
                        {
                            Warn(ParseIssueCategory.Sections, "ARM64 unwind epilog scope has an invalid start offset.");
                        }
                    }
                    else
                    {
                        Warn(ParseIssueCategory.Sections, "ARM64 unwind info could not be parsed.");
                    }
                }
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private void ParseArm32UnwindInfoDetails(List<IMAGE_SECTION_HEADER> sections)
        {
            if (_exceptionFunctions.Count == 0 || PEFileStream == null || PEFile == null)
            {
                return;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                foreach (ExceptionFunctionInfo func in _exceptionFunctions)
                {
                    if (func.UnwindInfoAddress == 0)
                    {
                        continue;
                    }

                    if (!TryGetFileOffset(sections, func.UnwindInfoAddress, out long offset))
                    {
                        Warn(ParseIssueCategory.Sections, "ARM unwind info RVA not mapped to a section.");
                        continue;
                    }

                    if (!TrySetPosition(offset, 4))
                    {
                        Warn(ParseIssueCategory.Sections, "ARM unwind info header outside file bounds.");
                        continue;
                    }

                    uint header = PEFile.ReadUInt32();
                    int epilogCount = (int)((header >> 16) & 0x1F);
                    int codeWords = (int)((header >> 21) & 0x1F);
                    bool hasEpilogFlag = ((header >> 14) & 0x1) != 0;
                    bool hasExceptionData = ((header >> 13) & 0x1) != 0;
                    int headerSize = 4;
                    int epilogScopeBytes = (!hasEpilogFlag && epilogCount > 0) ? epilogCount * 4 : 0;
                    int codeBytes = codeWords * 4;
                    int totalBytes = headerSize + epilogScopeBytes + codeBytes + (hasExceptionData ? 4 : 0);

                    if (totalBytes < 4 || !TrySetPosition(offset, totalBytes))
                    {
                        Warn(ParseIssueCategory.Sections, "ARM unwind info size exceeds file bounds.");
                        continue;
                    }

                    byte[] buffer = new byte[totalBytes];
                    ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                    if (TryParseArm32UnwindInfoDetail(func, buffer, out Arm32UnwindInfoDetail detail))
                    {
                        _arm32UnwindInfoDetails.Add(detail);
                        uint functionSize = func.EndAddress > func.BeginAddress
                            ? func.EndAddress - func.BeginAddress
                            : 0;
                        if (functionSize > 0 && detail.FunctionLengthBytes > functionSize)
                        {
                            Warn(ParseIssueCategory.Sections, "ARM unwind function length exceeds function size.");
                        }

                        if (!detail.ReservedBitsValid)
                        {
                            Warn(ParseIssueCategory.Sections, "ARM unwind header has non-zero reserved bits.");
                        }

                        if (detail.HasExceptionData && detail.ExceptionHandlerRva == 0)
                        {
                            Warn(ParseIssueCategory.Sections, "ARM unwind has exception data flag set but handler RVA is missing.");
                        }
                    }
                    else
                    {
                        Warn(ParseIssueCategory.Sections, "ARM unwind info could not be parsed.");
                    }
                }
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private void ParseIa64UnwindInfoDetails(List<IMAGE_SECTION_HEADER> sections)
        {
            if (_exceptionFunctions.Count == 0 || PEFileStream == null || PEFile == null)
            {
                return;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                foreach (ExceptionFunctionInfo func in _exceptionFunctions)
                {
                    if (func.UnwindInfoAddress == 0)
                    {
                        continue;
                    }

                    if (!TryGetFileOffset(sections, func.UnwindInfoAddress, out long offset))
                    {
                        Warn(ParseIssueCategory.Sections, "IA64 unwind info RVA not mapped to a section.");
                        continue;
                    }

                    int readSize = 32;
                    long maxAvailable = PEFileStream.Length - offset;
                    if (maxAvailable < 16)
                    {
                        Warn(ParseIssueCategory.Sections, "IA64 unwind info header outside file bounds.");
                        continue;
                    }
                    if (maxAvailable < readSize)
                    {
                        readSize = (int)maxAvailable;
                    }
                    if (!TrySetPosition(offset, readSize))
                    {
                        Warn(ParseIssueCategory.Sections, "IA64 unwind info header outside file bounds.");
                        continue;
                    }

                    byte[] buffer = new byte[readSize];
                    ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                    uint header = ReadUInt32(buffer, 0);
                    byte version = (byte)(header & 0x07);
                    byte flags = (byte)((header >> 3) & 0x1F);
                    int descriptorBytes = Math.Max(0, buffer.Length - 4);
                    int descriptorCount = descriptorBytes / 8;
                    int trailing = descriptorBytes % 8;
                    string descriptorPreview = descriptorBytes > 0
                        ? BuildHexPreview(new ReadOnlySpan<byte>(buffer, 4, Math.Min(descriptorBytes, 16)), 32)
                        : string.Empty;
                    Ia64UnwindInfoDetail detail = new Ia64UnwindInfoDetail(
                        func.BeginAddress,
                        func.EndAddress,
                        func.UnwindInfoAddress,
                        header,
                        version,
                        flags,
                        descriptorCount,
                        trailing,
                        descriptorPreview,
                        readSize,
                        BuildHexPreview(buffer, 32));
                    _ia64UnwindInfoDetails.Add(detail);
                }
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private bool TryReadArm64FunctionLength(List<IMAGE_SECTION_HEADER> sections, uint rva, out int lengthBytes)
        {
            lengthBytes = 0;
            if (rva == 0 || PEFileStream == null || PEFile == null)
            {
                return false;
            }

            if (!TryGetFileOffset(sections, rva, out long offset))
            {
                return false;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                if (!TrySetPosition(offset, 4))
                {
                    return false;
                }

                uint header = PEFile.ReadUInt32();
                int functionLength = (int)(header & 0x3FFFF);
                lengthBytes = functionLength * 4;
                return true;
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private bool TryReadArm32FunctionLength(List<IMAGE_SECTION_HEADER> sections, uint rva, out int lengthBytes)
        {
            lengthBytes = 0;
            if (rva == 0 || PEFileStream == null || PEFile == null)
            {
                return false;
            }

            if (!TryGetFileOffset(sections, rva, out long offset))
            {
                return false;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                if (!TrySetPosition(offset, 4))
                {
                    return false;
                }

                uint header = PEFile.ReadUInt32();
                int functionLength = (int)(header & 0x7FF);
                lengthBytes = functionLength * 4;
                return true;
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private static bool TryDecodeArm64PackedFunctionLength(uint unwindData, out int lengthBytes)
        {
            lengthBytes = 0;
            uint flag = unwindData & 0x3;
            if (flag == 0)
            {
                return false;
            }

            int functionLength = (int)((unwindData >> 2) & 0x7FF);
            if (functionLength <= 0)
            {
                return false;
            }

            lengthBytes = functionLength * 4;
            return true;
        }

        private static bool TryParseUnwindInfoDetail(ExceptionFunctionInfo func, ReadOnlySpan<byte> data, out UnwindInfoDetail detail)
        {
            detail = null;
            if (data.Length < 4)
            {
                return false;
            }

            byte verFlags = data[0];
            byte version = (byte)(verFlags & 0x07);
            byte flags = (byte)(verFlags >> 3);
            byte prologSize = data[1];
            byte codeCount = data[2];
            byte frame = data[3];
            byte frameRegister = (byte)(frame & 0x0F);
            byte frameOffset = (byte)((frame >> 4) & 0x0F);

            int needed = 4 + (codeCount * 2);
            if (needed > data.Length)
            {
                return false;
            }

            UnwindCodeInfo[] codes = new UnwindCodeInfo[codeCount];
            int cursor = 4;
            for (int i = 0; i < codeCount; i++)
            {
                byte codeOffset = data[cursor];
                byte opInfo = (byte)(data[cursor + 1] >> 4);
                byte unwindOp = (byte)(data[cursor + 1] & 0x0F);
                codes[i] = new UnwindCodeInfo(codeOffset, unwindOp, opInfo);
                cursor += 2;
            }

            uint functionSize = func.EndAddress > func.BeginAddress
                ? func.EndAddress - func.BeginAddress
                : 0;
            bool prologTooLarge = functionSize > 0 && prologSize > functionSize;
            bool hasChained = (flags & 0x04) != 0;

            detail = new UnwindInfoDetail(
                func.BeginAddress,
                func.EndAddress,
                func.UnwindInfoAddress,
                version,
                flags,
                prologSize,
                codeCount,
                frameRegister,
                frameOffset,
                hasChained,
                prologTooLarge,
                codes);
            return true;
        }

        private static bool TryParseArm64UnwindInfoDetail(ExceptionFunctionInfo func, ReadOnlySpan<byte> data, out Arm64UnwindInfoDetail detail)
        {
            detail = null;
            if (data.Length < 4)
            {
                return false;
            }

            int offset = 0;
            uint header = ReadUInt32(data, 0);
            offset += 4;

            int functionLength = (int)(header & 0x3FFFF);
            byte version = (byte)((header >> 18) & 0x03);
            bool hasXFlag = ((header >> 20) & 0x01) != 0;
            bool hasEpilogFlag = ((header >> 21) & 0x01) != 0;
            int epilogCount = (int)((header >> 22) & 0x1F);
            int codeWords = (int)((header >> 27) & 0x1F);

            if (epilogCount == 0 && codeWords == 0)
            {
                if (data.Length < 8)
                {
                    return false;
                }

                uint extended = ReadUInt32(data, offset);
                offset += 4;
                epilogCount = (int)(extended & 0xFFFF);
                codeWords = (int)((extended >> 16) & 0xFF);
            }

            int epilogScopeBytes = (!hasEpilogFlag && epilogCount > 0) ? epilogCount * 4 : 0;
            int codeBytes = codeWords * 4;
            int totalSize = offset + epilogScopeBytes + codeBytes + (hasXFlag ? 4 : 0);
            if (totalSize > data.Length)
            {
                return false;
            }

            List<Arm64EpilogScopeInfo> scopes = new List<Arm64EpilogScopeInfo>();
            int functionLengthBytes = functionLength * 4;
            if (!hasEpilogFlag && epilogCount > 0)
            {
                for (int i = 0; i < epilogCount; i++)
                {
                    uint scope = ReadUInt32(data, offset);
                    offset += 4;
                    int startOffset = (int)(scope & 0x3FFFF) * 4;
                    int reserved = (int)((scope >> 18) & 0x0F);
                    int startIndex = (int)((scope >> 22) & 0x03FF);
                    bool reservedOk = reserved == 0;
                    bool offsetValid = functionLengthBytes == 0 || startOffset < functionLengthBytes;
                    bool indexValid = startIndex < codeBytes;
                    scopes.Add(new Arm64EpilogScopeInfo(startOffset, startIndex, false, reservedOk, indexValid, offsetValid));
                }
            }
            else if (hasEpilogFlag)
            {
                int startIndex = epilogCount;
                bool indexValid = startIndex < codeBytes;
                scopes.Add(new Arm64EpilogScopeInfo(-1, startIndex, true, true, indexValid, true));
            }

            ReadOnlySpan<byte> codeSpan = codeBytes > 0
                ? data.Slice(offset, codeBytes)
                : ReadOnlySpan<byte>.Empty;
            Arm64UnwindCodeInfo[] codes = DecodeArm64UnwindCodes(codeSpan);
            offset += codeBytes;

            uint exceptionHandlerRva = 0;
            if (hasXFlag && offset + 4 <= data.Length)
            {
                exceptionHandlerRva = ReadUInt32(data, offset);
                offset += 4;
            }

            string preview = BuildHexPreview(data, 32);

            detail = new Arm64UnwindInfoDetail(
                func.BeginAddress,
                func.EndAddress,
                func.UnwindInfoAddress,
                header,
                functionLengthBytes,
                version,
                hasXFlag,
                hasEpilogFlag,
                epilogCount,
                codeWords,
                totalSize,
                exceptionHandlerRva,
                scopes.ToArray(),
                codes,
                preview);
            return true;
        }

        private static bool TryParseArm32UnwindInfoDetail(ExceptionFunctionInfo func, ReadOnlySpan<byte> data, out Arm32UnwindInfoDetail detail)
        {
            detail = null;
            if (data.Length < 4)
            {
                return false;
            }

            uint header = ReadUInt32(data, 0);
            int functionLength = (int)(header & 0x7FF);
            byte version = (byte)((header >> 11) & 0x03);
            bool hasExceptionData = ((header >> 13) & 0x01) != 0;
            bool hasEpilogFlag = ((header >> 14) & 0x01) != 0;
            bool isFragment = ((header >> 15) & 0x01) != 0;
            int epilogCount = (int)((header >> 16) & 0x1F);
            int codeWords = (int)((header >> 21) & 0x1F);
            uint reservedBits = (header >> 26) & 0x3F;
            bool reservedBitsValid = reservedBits == 0;

            int offset = 4;
            List<uint> epilogScopes = new List<uint>();
            if (!hasEpilogFlag && epilogCount > 0)
            {
                int scopeBytes = epilogCount * 4;
                if (offset + scopeBytes > data.Length)
                {
                    return false;
                }

                for (int i = 0; i < epilogCount; i++)
                {
                    epilogScopes.Add(ReadUInt32(data, offset));
                    offset += 4;
                }
            }

            List<uint> codeWordList = new List<uint>();
            int codeBytes = codeWords * 4;
            if (offset + codeBytes > data.Length)
            {
                return false;
            }

            for (int i = 0; i < codeWords; i++)
            {
                codeWordList.Add(ReadUInt32(data, offset));
                offset += 4;
            }

            uint exceptionHandlerRva = 0;
            if (hasExceptionData && offset + 4 <= data.Length)
            {
                exceptionHandlerRva = ReadUInt32(data, offset);
                offset += 4;
            }

            string[] opcodeSummaries = DecodeArm32UnwindOpcodes(codeWordList, out bool hasFinish, out int opcodeCount);
            string preview = BuildHexPreview(data, 32);
            detail = new Arm32UnwindInfoDetail(
                func.BeginAddress,
                func.EndAddress,
                func.UnwindInfoAddress,
                header,
                functionLength * 4,
                version,
                hasExceptionData,
                hasEpilogFlag,
                isFragment,
                epilogCount,
                codeWords,
                reservedBits,
                reservedBitsValid,
                exceptionHandlerRva,
                epilogScopes.ToArray(),
                codeWordList.ToArray(),
                opcodeCount,
                hasFinish,
                opcodeSummaries,
                preview);
            return true;
        }

        internal static UnwindInfoDetail BuildUnwindInfoDetailForTest(ExceptionFunctionInfo func, byte[] data)
        {
            if (data == null || func == null)
            {
                return null;
            }

            return TryParseUnwindInfoDetail(func, data, out UnwindInfoDetail detail)
                ? detail
                : null;
        }

        internal static Arm64UnwindInfoDetail BuildArm64UnwindInfoDetailForTest(ExceptionFunctionInfo func, byte[] data)
        {
            if (data == null || func == null)
            {
                return null;
            }

            return TryParseArm64UnwindInfoDetail(func, data, out Arm64UnwindInfoDetail detail)
                ? detail
                : null;
        }

        internal static Arm32UnwindInfoDetail BuildArm32UnwindInfoDetailForTest(ExceptionFunctionInfo func, byte[] data)
        {
            if (data == null || func == null)
            {
                return null;
            }

            return TryParseArm32UnwindInfoDetail(func, data, out Arm32UnwindInfoDetail detail)
                ? detail
                : null;
        }

        internal static Ia64UnwindInfoDetail BuildIa64UnwindInfoDetailForTest(ExceptionFunctionInfo func, byte[] data)
        {
            if (data == null || func == null || data.Length < 4)
            {
                return null;
            }

            int sizeBytes = Math.Min(data.Length, 16);
            uint header = ReadUInt32(data, 0);
            byte version = (byte)(header & 0x07);
            byte flags = (byte)((header >> 3) & 0x1F);
            int descriptorBytes = Math.Max(0, Math.Min(data.Length, sizeBytes) - 4);
            int descriptorCount = descriptorBytes / 8;
            int trailing = descriptorBytes % 8;
            string descriptorPreview = descriptorBytes > 0
                ? BuildHexPreview(new ReadOnlySpan<byte>(data, 4, Math.Min(descriptorBytes, 16)), 32)
                : string.Empty;
            string preview = BuildHexPreview(new ReadOnlySpan<byte>(data, 0, sizeBytes), 32);
            return new Ia64UnwindInfoDetail(
                func.BeginAddress,
                func.EndAddress,
                func.UnwindInfoAddress,
                header,
                version,
                flags,
                descriptorCount,
                trailing,
                descriptorPreview,
                sizeBytes,
                preview);
        }

        private static Arm64UnwindCodeInfo[] DecodeArm64UnwindCodes(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                return Array.Empty<Arm64UnwindCodeInfo>();
            }

            List<Arm64UnwindCodeInfo> codes = new List<Arm64UnwindCodeInfo>();
            int index = 0;
            while (index < data.Length)
            {
                if (TryDecodeArm64UnwindCode(data, index, out Arm64UnwindCodeInfo info, out int length))
                {
                    codes.Add(info);
                    index += length;
                }
                else
                {
                    string raw = BuildHexPreview(data.Slice(index, 1), 1);
                    codes.Add(new Arm64UnwindCodeInfo(index, 1, "unknown", string.Empty, raw));
                    index += 1;
                }
            }

            return codes.ToArray();
        }

        private static string[] DecodeArm32UnwindOpcodes(List<uint> codeWords, out bool hasFinishOpcode, out int opcodeCount)
        {
            hasFinishOpcode = false;
            opcodeCount = 0;
            if (codeWords == null || codeWords.Count == 0)
            {
                return Array.Empty<string>();
            }

            List<string> opcodes = new List<string>();
            int maxOps = 32;
            foreach (uint word in codeWords)
            {
                for (int i = 0; i < 4; i++)
                {
                    byte opcode = (byte)((word >> (i * 8)) & 0xFF);
                    opcodeCount++;
                    string name = DescribeArm32UnwindOpcode(opcode, out bool isFinish);
                    opcodes.Add(name);
                    if (isFinish)
                    {
                        hasFinishOpcode = true;
                        return opcodes.ToArray();
                    }
                    if (opcodes.Count >= maxOps)
                    {
                        return opcodes.ToArray();
                    }
                }
            }

            return opcodes.ToArray();
        }

        private static string DescribeArm32UnwindOpcode(byte opcode, out bool isFinish)
        {
            isFinish = false;
            if (opcode == 0xB0)
            {
                isFinish = true;
                return "FINISH";
            }
            if (opcode == 0xB1)
            {
                return "POP_MASK";
            }
            if (opcode == 0xB2)
            {
                return "VSP_SET";
            }
            if (opcode == 0xB3)
            {
                return "POP_REGS";
            }
            if (opcode <= 0x7F)
            {
                return "VSP_ADD";
            }
            if (opcode <= 0xBF)
            {
                return "VSP_SUB";
            }

            return "OP_0x" + opcode.ToString("X2", CultureInfo.InvariantCulture);
        }

        private static bool TryDecodeArm64UnwindCode(ReadOnlySpan<byte> data, int index, out Arm64UnwindCodeInfo info, out int length)
        {
            info = null;
            length = 1;
            if (index < 0 || index >= data.Length)
            {
                return false;
            }

            byte b0 = data[index];
            string opcode = string.Empty;
            string details = string.Empty;

            if ((b0 & 0xE0) == 0x00)
            {
                int size = (b0 & 0x1F) * 16;
                opcode = "alloc_s";
                details = $"Size={size}";
                length = 1;
            }
            else if ((b0 & 0xE0) == 0x20)
            {
                int offset = -(b0 & 0x1F) * 8;
                opcode = "save_r19r20_x";
                details = $"Offset={offset}";
                length = 1;
            }
            else if ((b0 & 0xC0) == 0x40)
            {
                int offset = (b0 & 0x3F) * 8;
                opcode = "save_fplr";
                details = $"Offset={offset}";
                length = 1;
            }
            else if ((b0 & 0xC0) == 0x80)
            {
                int offset = -((b0 & 0x3F) + 1) * 8;
                opcode = "save_fplr_x";
                details = $"Offset={offset}";
                length = 1;
            }
            else if ((b0 & 0xF8) == 0xC0)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int value = ((b0 & 0x07) << 8) | b1;
                int size = value * 16;
                opcode = "alloc_m";
                details = $"Size={size}";
                length = 2;
            }
            else if ((b0 & 0xFC) == 0xC8)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int x = ((b0 & 0x03) << 2) | (b1 >> 6);
                int z = b1 & 0x3F;
                int reg = 19 + (x * 2);
                int offset = z * 8;
                opcode = "save_regp";
                details = $"Regs=x{reg}/x{reg + 1} Offset={offset}";
                length = 2;
            }
            else if ((b0 & 0xFC) == 0xCC)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int x = ((b0 & 0x03) << 2) | (b1 >> 6);
                int z = b1 & 0x3F;
                int reg = 19 + (x * 2);
                int offset = -((z + 1) * 8);
                opcode = "save_regp_x";
                details = $"Regs=x{reg}/x{reg + 1} Offset={offset}";
                length = 2;
            }
            else if ((b0 & 0xFC) == 0xD0)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int x = ((b0 & 0x03) << 2) | (b1 >> 6);
                int z = b1 & 0x3F;
                int reg = 19 + x;
                int offset = z * 8;
                opcode = "save_reg";
                details = $"Reg=x{reg} Offset={offset}";
                length = 2;
            }
            else if ((b0 & 0xFE) == 0xD4)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int x = ((b0 & 0x01) << 3) | (b1 >> 5);
                int z = b1 & 0x1F;
                int reg = 19 + x;
                int offset = -((z + 1) * 8);
                opcode = "save_reg_x";
                details = $"Reg=x{reg} Offset={offset}";
                length = 2;
            }
            else if ((b0 & 0xFE) == 0xD6)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int x = ((b0 & 0x01) << 2) | (b1 >> 6);
                int z = b1 & 0x3F;
                int reg = 19 + (x * 2);
                int offset = z * 8;
                opcode = "save_lrpair";
                details = $"Regs=x{reg}/lr Offset={offset}";
                length = 2;
            }
            else if ((b0 & 0xFE) == 0xD8)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int x = ((b0 & 0x01) << 2) | (b1 >> 6);
                int z = b1 & 0x3F;
                int reg = 8 + (x * 2);
                int offset = z * 8;
                opcode = "save_fregp";
                details = $"Regs=d{reg}/d{reg + 1} Offset={offset}";
                length = 2;
            }
            else if ((b0 & 0xFE) == 0xDA)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int x = ((b0 & 0x01) << 2) | (b1 >> 6);
                int z = b1 & 0x3F;
                int reg = 8 + (x * 2);
                int offset = -((z + 1) * 8);
                opcode = "save_fregp_x";
                details = $"Regs=d{reg}/d{reg + 1} Offset={offset}";
                length = 2;
            }
            else if ((b0 & 0xFE) == 0xDC)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int x = ((b0 & 0x01) << 2) | (b1 >> 6);
                int z = b1 & 0x3F;
                int reg = 8 + x;
                int offset = z * 8;
                opcode = "save_freg";
                details = $"Reg=d{reg} Offset={offset}";
                length = 2;
            }
            else if (b0 == 0xDE)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                int x = (b1 >> 5) & 0x07;
                int z = b1 & 0x1F;
                int reg = 8 + x;
                int offset = -((z + 1) * 8);
                opcode = "save_freg_x";
                details = $"Reg=d{reg} Offset={offset}";
                length = 2;
            }
            else if (b0 == 0xDF)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                opcode = "alloc_z";
                details = $"Units={b1}*VL";
                length = 2;
            }
            else if (b0 == 0xE0)
            {
                if (index + 3 >= data.Length)
                {
                    return false;
                }

                uint value = (uint)(data[index + 1] | (data[index + 2] << 8) | (data[index + 3] << 16));
                opcode = "alloc_l";
                details = $"Size={(int)value * 16}";
                length = 4;
            }
            else if (b0 == 0xE1)
            {
                opcode = "set_fp";
                length = 1;
            }
            else if (b0 == 0xE2)
            {
                if (index + 1 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                opcode = "add_fp";
                details = $"Offset={b1 * 8}";
                length = 2;
            }
            else if (b0 == 0xE3)
            {
                opcode = "nop";
                length = 1;
            }
            else if (b0 == 0xE4)
            {
                opcode = "end";
                length = 1;
            }
            else if (b0 == 0xE5)
            {
                opcode = "end_c";
                length = 1;
            }
            else if (b0 == 0xE6)
            {
                opcode = "save_next";
                length = 1;
            }
            else if (b0 == 0xE7)
            {
                if (index + 2 >= data.Length)
                {
                    return false;
                }

                byte b1 = data[index + 1];
                byte b2 = data[index + 2];
                if ((b2 & 0xC0) == 0x00)
                {
                    int p = (b1 >> 6) & 0x01;
                    int x = (b1 >> 5) & 0x01;
                    int r = b1 & 0x1F;
                    int o = b2 & 0x3F;
                    int offset = (x == 1 || p == 1) ? o * 16 : o * 8;
                    opcode = x == 1 ? "save_any_xreg" : "save_any_dreg";
                    string kind = p == 1 ? "pair" : "single";
                    details = $"Reg={r} {kind} Offset={offset}";
                    length = 3;
                }
                else if ((b2 & 0xC0) == 0xC0)
                {
                    int ohi = (b1 >> 5) & 0x03;
                    int r = b1 & 0x0F;
                    bool isPreg = (b1 & 0x10) != 0;
                    int o = (ohi << 6) | (b2 & 0x3F);
                    opcode = isPreg ? "save_preg" : "save_zreg";
                    details = $"Reg={r} OffsetUnits={o}";
                    length = 3;
                }
                else
                {
                    opcode = "save_any";
                    length = 3;
                }
            }
            else if ((b0 & 0xF8) == 0xE8)
            {
                opcode = "custom_stack";
                length = 1;
            }
            else if (b0 == 0xFC)
            {
                opcode = "pac_sign_lr";
                length = 1;
            }
            else
            {
                return false;
            }

            string rawBytes = BuildHexPreview(data.Slice(index, Math.Min(length, data.Length - index)), length);
            info = new Arm64UnwindCodeInfo(index, length, opcode, details, rawBytes);
            return true;
        }

        private bool TryReadUnwindVersion(List<IMAGE_SECTION_HEADER> sections, uint rva, out byte version)
        {
            version = 0;
            if (rva == 0 || PEFileStream == null || PEFile == null)
            {
                return false;
            }

            if (!TryGetFileOffset(sections, rva, out long offset))
            {
                return false;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                if (!TrySetPosition(offset, 1))
                {
                    return false;
                }

                int value = PEFile.ReadByte();
                if (value < 0)
                {
                    return false;
                }

                version = (byte)(value & 0x07);
                return true;
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private bool TryReadArm64UnwindVersion(List<IMAGE_SECTION_HEADER> sections, uint rva, out byte version)
        {
            version = 0;
            if (rva == 0 || PEFileStream == null || PEFile == null)
            {
                return false;
            }

            if (!TryGetFileOffset(sections, rva, out long offset))
            {
                return false;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                if (!TrySetPosition(offset, 4))
                {
                    return false;
                }

                uint header = PEFile.ReadUInt32();
                version = (byte)((header >> 18) & 0x03);
                return true;
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private bool TryReadArm32UnwindVersion(List<IMAGE_SECTION_HEADER> sections, uint rva, out byte version)
        {
            version = 0;
            if (rva == 0 || PEFileStream == null || PEFile == null)
            {
                return false;
            }

            if (!TryGetFileOffset(sections, rva, out long offset))
            {
                return false;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                if (!TrySetPosition(offset, 4))
                {
                    return false;
                }

                uint header = PEFile.ReadUInt32();
                version = (byte)((header >> 11) & 0x03);
                return true;
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private bool TryReadIa64UnwindVersion(List<IMAGE_SECTION_HEADER> sections, uint rva, out byte version)
        {
            version = 0;
            if (rva == 0 || PEFileStream == null || PEFile == null)
            {
                return false;
            }

            if (!TryGetFileOffset(sections, rva, out long offset))
            {
                return false;
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                if (!TrySetPosition(offset, 1))
                {
                    return false;
                }

                int value = PEFile.ReadByte();
                if (value < 0)
                {
                    return false;
                }

                version = (byte)value;
                return true;
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private delegate bool TryGetUnwindVersion(uint rva, out byte version);

        private static ExceptionDirectorySummary BuildExceptionDirectorySummaryCore(
            IReadOnlyList<ExceptionFunctionInfo> functions,
            uint directoryRva,
            uint directorySize,
            string directorySection,
            bool directoryInPdata,
            uint sizeOfImage,
            bool parseUnwindInfo,
            TryGetUnwindVersion tryGetUnwindVersion)
        {
            if (functions == null || functions.Count == 0)
            {
                return new ExceptionDirectorySummary(
                    directoryRva,
                    directorySize,
                    directorySection,
                    directoryInPdata,
                    0,
                    0,
                    0,
                    0,
                    0,
                    Array.Empty<UnwindInfoVersionCount>());
            }

            int invalidRange = 0;
            int outOfRange = 0;
            int unwindCount = 0;
            int unwindFailures = 0;
            Dictionary<byte, int> versionCounts = new Dictionary<byte, int>();
            HashSet<uint> seenUnwind = new HashSet<uint>();

            foreach (ExceptionFunctionInfo entry in functions)
            {
                if (entry.EndAddress <= entry.BeginAddress)
                {
                    invalidRange++;
                }

                if (sizeOfImage > 0 &&
                    (entry.BeginAddress > sizeOfImage || entry.EndAddress > sizeOfImage))
                {
                    outOfRange++;
                }

                if (!parseUnwindInfo || entry.UnwindInfoAddress == 0)
                {
                    continue;
                }

                if (!seenUnwind.Add(entry.UnwindInfoAddress))
                {
                    continue;
                }

                if (tryGetUnwindVersion != null && tryGetUnwindVersion(entry.UnwindInfoAddress, out byte version))
                {
                    unwindCount++;
                    if (!versionCounts.TryGetValue(version, out int count))
                    {
                        count = 0;
                    }

                    versionCounts[version] = count + 1;
                }
                else
                {
                    unwindFailures++;
                }
            }

            UnwindInfoVersionCount[] versions = versionCounts
                .OrderBy(kvp => kvp.Key)
                .Select(kvp => new UnwindInfoVersionCount(kvp.Key, kvp.Value))
                .ToArray();

            return new ExceptionDirectorySummary(
                directoryRva,
                directorySize,
                directorySection,
                directoryInPdata,
                functions.Count,
                invalidRange,
                outOfRange,
                unwindCount,
                unwindFailures,
                versions);
        }

        internal static ExceptionDirectorySummary BuildExceptionDirectorySummaryForTest(
            ExceptionFunctionInfo[] functions,
            uint sizeOfImage,
            bool parseUnwindInfo,
            Dictionary<uint, byte[]> unwindInfo,
            uint directoryRva = 0,
            uint directorySize = 0,
            string directorySection = "",
            bool directoryInPdata = false)
        {
            bool TryGetVersion(uint rva, out byte version)
            {
                version = 0;
                if (unwindInfo == null || !unwindInfo.TryGetValue(rva, out byte[] data) || data == null || data.Length == 0)
                {
                    return false;
                }

                version = (byte)(data[0] & 0x07);
                return true;
            }

            return BuildExceptionDirectorySummaryCore(
                functions ?? Array.Empty<ExceptionFunctionInfo>(),
                directoryRva,
                directorySize,
                directorySection,
                directoryInPdata,
                sizeOfImage,
                parseUnwindInfo,
                TryGetVersion);
        }

        private void ParseDebugDirectory(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections)
        {
            if (!TryGetFileOffset(sections, directory.VirtualAddress, out long tableOffset))
            {
                Warn(ParseIssueCategory.Debug, "Debug directory RVA not mapped to a section.");
                return;
            }

            if (!TryGetIntSize(directory.Size, out int tableSize))
            {
                Warn(ParseIssueCategory.Debug, "Debug directory size exceeds supported limits.");
                return;
            }

            int entrySize = Marshal.SizeOf(typeof(IMAGE_DEBUG_DIRECTORY));
            if (entrySize <= 0)
            {
                return;
            }

            int entryCount = tableSize / entrySize;
            for (int i = 0; i < entryCount; i++)
            {
                long entryOffset = tableOffset + (i * entrySize);
                if (!TrySetPosition(entryOffset, entrySize))
                {
                    WarnAt(ParseIssueCategory.Debug, "Debug directory entry outside file bounds.", entryOffset);
                    break;
                }

                byte[] buffer = new byte[entrySize];
                ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                IMAGE_DEBUG_DIRECTORY entry = ByteArrayToStructure<IMAGE_DEBUG_DIRECTORY>(buffer);

                DebugCodeViewInfo codeView = null;
                PdbInfo pdbInfo = null;
                DebugCoffInfo coff = null;
                DebugPogoInfo pogo = null;
                DebugVcFeatureInfo vcFeature = null;
                DebugExDllCharacteristicsInfo exDll = null;
                DebugFpoInfo fpo = null;
                DebugBorlandInfo borland = null;
                DebugReservedInfo reserved = null;
                DebugRawInfo fixup = null;
                DebugExceptionInfo exceptionInfo = null;
                DebugMiscInfo misc = null;
                DebugOmapInfo omapToSource = null;
                DebugOmapInfo omapFromSource = null;
                DebugReproInfo repro = null;
                DebugEmbeddedPortablePdbInfo embeddedPortablePdb = null;
                DebugSpgoInfo spgo = null;
                DebugPdbHashInfo pdbHash = null;
                DebugRawInfo iltcg = null;
                DebugRawInfo mpx = null;
                DebugClsidInfo clsid = null;
                DebugRawInfo other = null;
                string note = string.Empty;
                if ((DebugDirectoryType)entry.Type == DebugDirectoryType.CodeView && entry.SizeOfData > 0)
                {
                    long dataOffset = entry.PointerToRawData;
                    if (dataOffset == 0 && entry.AddressOfRawData != 0)
                    {
                        if (!TryGetFileOffset(sections, entry.AddressOfRawData, out dataOffset))
                        {
                            dataOffset = 0;
                        }
                    }

                    if (dataOffset > 0 && TrySetPosition(dataOffset, (int)Math.Min(entry.SizeOfData, int.MaxValue)))
                    {
                        int dataSize = entry.SizeOfData > int.MaxValue ? int.MaxValue : (int)entry.SizeOfData;
                        byte[] data = new byte[dataSize];
                        ReadExactly(PEFileStream, data, 0, data.Length);
                        if (TryParseCodeViewInfo(data, entry.TimeDateStamp, out DebugCodeViewInfo parsed))
                        {
                            codeView = parsed;
                            if (codeView != null && codeView.HasPdbPath && TryParsePdbInfo(codeView.PdbPath, out PdbInfo parsedPdb))
                            {
                                pdbInfo = parsedPdb;
                            }
                            if (parsed.IsRsds)
                            {
                                if (!parsed.HasValidGuid)
                                {
                                    Warn(ParseIssueCategory.Debug, "CodeView RSDS entry has an empty GUID.");
                                }

                                if (!parsed.HasValidAge)
                                {
                                    Warn(ParseIssueCategory.Debug, "CodeView RSDS entry has an invalid age.");
                                }
                            }

                            if (parsed.IsNb10 && parsed.HasPdbTimeDateStamp && !parsed.TimeDateStampMatches)
                            {
                                Warn(ParseIssueCategory.Debug, "CodeView NB10 timestamp does not match debug directory timestamp.");
                            }

                            if (!parsed.HasPdbPath)
                            {
                                Warn(ParseIssueCategory.Debug, "CodeView entry is missing a PDB path.");
                            }
                            else if (!parsed.PdbPathEndsWithPdb)
                            {
                                Warn(ParseIssueCategory.Debug, "CodeView PDB path does not end with .pdb.");
                            }
                        }
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Coff)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseDebugCoffData(data, out DebugCoffInfo parsed))
                    {
                        coff = parsed;
                    }
                    else
                    {
                        note = "COFF debug info (likely /Z7).";
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Pogo && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParsePogoData(data, out DebugPogoInfo parsed))
                    {
                        pogo = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.VCFeature && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseVcFeatureData(data, out DebugVcFeatureInfo parsed))
                    {
                        vcFeature = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.ExDllCharacteristics && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseExDllCharacteristicsData(data, out DebugExDllCharacteristicsInfo parsed))
                    {
                        exDll = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Fpo && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseFpoData(data, out DebugFpoInfo parsed))
                    {
                        fpo = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Borland && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseDebugBorlandData(data, out DebugBorlandInfo parsed))
                    {
                        borland = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Reserved10 && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseDebugReservedData(data, out DebugReservedInfo parsed))
                    {
                        reserved = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Fixup && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data))
                    {
                        fixup = BuildDebugRawInfo(data);
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Exception && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseDebugExceptionData(data, out DebugExceptionInfo parsed))
                    {
                        exceptionInfo = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Misc && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseDebugMiscData(data, out DebugMiscInfo parsed))
                    {
                        misc = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.OmapToSrc && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseOmapData(data, out DebugOmapInfo parsed))
                    {
                        omapToSource = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.OmapFromSrc && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseOmapData(data, out DebugOmapInfo parsed))
                    {
                        omapFromSource = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Repro && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseReproData(data, out DebugReproInfo parsed))
                    {
                        repro = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.EmbeddedPortablePdb && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseDebugEmbeddedPortablePdbData(data, out DebugEmbeddedPortablePdbInfo parsed))
                    {
                        embeddedPortablePdb = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Spgo && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseDebugSpgoData(data, out DebugSpgoInfo parsed))
                    {
                        spgo = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.PdbHash && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseDebugPdbHashData(data, out DebugPdbHashInfo parsed))
                    {
                        pdbHash = parsed;
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.ILTCG && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data))
                    {
                        iltcg = BuildDebugRawInfo(data);
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.MPX && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data))
                    {
                        mpx = BuildDebugRawInfo(data);
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Clsid && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data) &&
                        TryParseDebugClsidData(data, out DebugClsidInfo parsed))
                    {
                        clsid = parsed;
                    }
                }

                bool hasStructuredData = codeView != null ||
                    pdbInfo != null ||
                    coff != null ||
                    pogo != null ||
                    vcFeature != null ||
                    exDll != null ||
                    fpo != null ||
                    borland != null ||
                    reserved != null ||
                    fixup != null ||
                    exceptionInfo != null ||
                    misc != null ||
                    omapToSource != null ||
                    omapFromSource != null ||
                    repro != null ||
                    embeddedPortablePdb != null ||
                    spgo != null ||
                    pdbHash != null ||
                    iltcg != null ||
                    mpx != null ||
                    clsid != null;

                if (!hasStructuredData && entry.SizeOfData > 0)
                {
                    if (TryReadDebugDirectoryData(entry, sections, out byte[] data))
                    {
                        other = BuildDebugRawInfo(data);
                        if (string.IsNullOrWhiteSpace(note))
                        {
                            note = "Unparsed debug directory data.";
                        }
                    }
                }

                _debugDirectories.Add(new DebugDirectoryEntry(
                    entry.Characteristics,
                    entry.TimeDateStamp,
                    entry.MajorVersion,
                    entry.MinorVersion,
                    (DebugDirectoryType)entry.Type,
                    entry.SizeOfData,
                    entry.AddressOfRawData,
                    entry.PointerToRawData,
                    codeView,
                    pdbInfo,
                    coff,
                    pogo,
                    vcFeature,
                    exDll,
                    fpo,
                    borland,
                    reserved,
                    fixup,
                    exceptionInfo,
                    misc,
                    omapToSource,
                    omapFromSource,
                    repro,
                    embeddedPortablePdb,
                    spgo,
                    pdbHash,
                    iltcg,
                    mpx,
                    clsid,
                    other,
                    note));
            }
        }

        private bool TryReadDebugDirectoryData(IMAGE_DEBUG_DIRECTORY entry, List<IMAGE_SECTION_HEADER> sections, out byte[] data)
        {
            data = Array.Empty<byte>();
            if (entry.SizeOfData == 0 || PEFileStream == null)
            {
                return false;
            }

            long dataOffset = entry.PointerToRawData;
            if (dataOffset == 0 && entry.AddressOfRawData != 0)
            {
                if (!TryGetFileOffset(sections, entry.AddressOfRawData, out dataOffset))
                {
                    dataOffset = 0;
                }
            }

            if (dataOffset <= 0)
            {
                return false;
            }

            if (!TryGetIntSize(entry.SizeOfData, out int dataSize))
            {
                return false;
            }

            if (!TrySetPosition(dataOffset, dataSize))
            {
                return false;
            }

            data = new byte[dataSize];
            ReadExactly(PEFileStream, data, 0, data.Length);
            return true;
        }

        private static bool TryParsePogoData(byte[] data, out DebugPogoInfo info)
        {
            info = null;
            if (data == null || data.Length < 12)
            {
                return false;
            }

            string signature = Encoding.ASCII.GetString(data, 0, 4).TrimEnd('\0', ' ');
            int offset = 4;
            List<DebugPogoEntryInfo> entries = new List<DebugPogoEntryInfo>();
            int total = 0;
            bool truncated = false;
            const int maxEntries = 512;

            while (offset + 8 <= data.Length)
            {
                uint size = ReadUInt32(data, offset);
                uint rva = ReadUInt32(data, offset + 4);
                offset += 8;
                if (offset >= data.Length)
                {
                    break;
                }

                string name = ReadNullTerminatedAscii(data, offset, out int bytesRead);
                if (bytesRead <= 0)
                {
                    break;
                }

                offset += bytesRead;
                if ((offset % 4) != 0)
                {
                    offset += 4 - (offset % 4);
                }

                total++;
                if (entries.Count < maxEntries)
                {
                    entries.Add(new DebugPogoEntryInfo(rva, size, name));
                }
                else
                {
                    truncated = true;
                }
            }

            info = new DebugPogoInfo(signature, total, truncated, entries.ToArray());
            return true;
        }

        private static bool TryParseDebugMiscData(byte[] data, out DebugMiscInfo info)
        {
            info = null;
            if (data == null || data.Length < 12)
            {
                return false;
            }

            uint dataType = ReadUInt32(data, 0);
            uint length = ReadUInt32(data, 4);
            bool isUnicode = data[8] != 0;

            int availableLength = data.Length;
            int declaredLength = length > int.MaxValue ? int.MaxValue : (int)length;
            int totalLength = declaredLength >= 12 ? Math.Min(declaredLength, availableLength) : availableLength;
            if (totalLength < 12)
            {
                totalLength = availableLength;
            }

            int payloadLength = Math.Max(0, totalLength - 12);
            string payload = string.Empty;
            if (payloadLength > 0)
            {
                if (isUnicode)
                {
                    int safeLength = payloadLength - (payloadLength % 2);
                    payload = Encoding.Unicode.GetString(data, 12, safeLength);
                }
                else
                {
                    payload = Encoding.ASCII.GetString(data, 12, payloadLength);
                }

                payload = payload.TrimEnd('\0');
            }

            info = new DebugMiscInfo(dataType, length, isUnicode, payload);
            return true;
        }

        private static bool TryParseDebugExceptionData(byte[] data, out DebugExceptionInfo info)
        {
            info = null;
            if (data == null || data.Length < 4)
            {
                return false;
            }

            bool aligned = (data.Length % 4) == 0;
            int count = data.Length / 4;
            int sampleCount = Math.Min(count, 16);
            uint[] samples = new uint[sampleCount];
            for (int i = 0; i < sampleCount; i++)
            {
                samples[i] = ReadUInt32(data, i * 4);
            }

            info = new DebugExceptionInfo(count, aligned, samples);
            return true;
        }

        internal static bool TryParseDebugExceptionDataForTest(byte[] data, out DebugExceptionInfo info)
        {
            return TryParseDebugExceptionData(data, out info);
        }

        private static bool TryParseOmapData(byte[] data, out DebugOmapInfo info)
        {
            info = null;
            if (data == null || data.Length < 8)
            {
                return false;
            }

            int total = data.Length / 8;
            const int maxEntries = 512;
            int count = Math.Min(total, maxEntries);
            bool truncated = total > maxEntries;
            DebugOmapEntryInfo[] entries = new DebugOmapEntryInfo[count];
            for (int i = 0; i < count; i++)
            {
                int offset = i * 8;
                uint from = ReadUInt32(data, offset);
                uint to = ReadUInt32(data, offset + 4);
                entries[i] = new DebugOmapEntryInfo(from, to);
            }

            info = new DebugOmapInfo(total, truncated, entries);
            return true;
        }

        private static bool TryParseReproData(byte[] data, out DebugReproInfo info)
        {
            info = null;
            if (data == null || data.Length == 0)
            {
                return false;
            }

            info = new DebugReproInfo((uint)data.Length, ToHex(data));
            return true;
        }

        private static bool TryParseDebugCoffData(byte[] data, out DebugCoffInfo info)
        {
            info = null;
            if (data == null || data.Length < 32)
            {
                return false;
            }

            uint numberOfSymbols = ReadUInt32(data, 0);
            uint lvaToFirstSymbol = ReadUInt32(data, 4);
            uint numberOfLineNumbers = ReadUInt32(data, 8);
            uint lvaToFirstLineNumber = ReadUInt32(data, 12);
            uint rvaToFirstByteOfCode = ReadUInt32(data, 16);
            uint rvaToLastByteOfCode = ReadUInt32(data, 20);
            uint rvaToFirstByteOfData = ReadUInt32(data, 24);
            uint rvaToLastByteOfData = ReadUInt32(data, 28);

            info = new DebugCoffInfo(
                numberOfSymbols,
                lvaToFirstSymbol,
                numberOfLineNumbers,
                lvaToFirstLineNumber,
                rvaToFirstByteOfCode,
                rvaToLastByteOfCode,
                rvaToFirstByteOfData,
                rvaToLastByteOfData);
            return true;
        }

        private static bool TryParseDebugClsidData(byte[] data, out DebugClsidInfo info)
        {
            info = null;
            if (data == null || data.Length < 16)
            {
                return false;
            }

            Guid clsid = new Guid(new ReadOnlySpan<byte>(data, 0, 16));
            info = new DebugClsidInfo(clsid);
            return true;
        }

        private static DebugRawInfo BuildDebugRawInfo(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            string hash = data.Length > 0 ? ToHex(SHA256.HashData(data)) : string.Empty;
            string preview = BuildHexPreview(data, 48);
            return new DebugRawInfo((uint)data.Length, hash, preview);
        }

        private static bool TryParseVcFeatureData(byte[] data, out DebugVcFeatureInfo info)
        {
            info = null;
            if (data == null || data.Length < 4)
            {
                return false;
            }

            uint flags = ReadUInt32(data, 0);
            info = new DebugVcFeatureInfo(flags, DecodeBitFlags(flags));
            return true;
        }

        private static bool TryParseExDllCharacteristicsData(byte[] data, out DebugExDllCharacteristicsInfo info)
        {
            info = null;
            if (data == null || data.Length < 4)
            {
                return false;
            }

            uint flags = ReadUInt32(data, 0);
            info = new DebugExDllCharacteristicsInfo(flags, DecodeBitFlags(flags));
            return true;
        }

        private static bool TryParseFpoData(byte[] data, out DebugFpoInfo info)
        {
            info = null;
            if (data == null || data.Length < 16)
            {
                return false;
            }

            int entrySize = 16;
            int total = data.Length / entrySize;
            int limit = Math.Min(total, 256);
            bool truncated = total > limit;
            List<DebugFpoEntryInfo> entries = new List<DebugFpoEntryInfo>(limit);
            for (int i = 0; i < limit; i++)
            {
                int offset = i * entrySize;
                uint start = ReadUInt32(data, offset);
                uint procSize = ReadUInt32(data, offset + 4);
                uint locals = ReadUInt32(data, offset + 8);
                ushort paramsBytes = ReadUInt16(data, offset + 12);
                ushort flags = ReadUInt16(data, offset + 14);
                byte prolog = (byte)(flags & 0xFF);
                byte regs = (byte)((flags >> 8) & 0x07);
                bool hasSeh = (flags & (1 << 11)) != 0;
                bool usesBp = (flags & (1 << 12)) != 0;
                byte frame = (byte)((flags >> 14) & 0x03);
                entries.Add(new DebugFpoEntryInfo(
                    start,
                    procSize,
                    locals,
                    paramsBytes,
                    prolog,
                    regs,
                    hasSeh,
                    usesBp,
                    frame));
            }

            info = new DebugFpoInfo(total, truncated, entries.ToArray());
            return true;
        }

        private static bool TryParseDebugBorlandData(byte[] data, out DebugBorlandInfo info)
        {
            info = null;
            if (data == null || data.Length < 8)
            {
                return false;
            }

            uint version = ReadUInt32(data, 0);
            uint flags = ReadUInt32(data, 4);
            int count = (data.Length - 8) / 4;
            uint[] offsets = new uint[count];
            int cursor = 8;
            for (int i = 0; i < count; i++)
            {
                offsets[i] = ReadUInt32(data, cursor);
                cursor += 4;
            }

            info = new DebugBorlandInfo(version, flags, offsets);
            return true;
        }

        private static bool TryParseDebugReservedData(byte[] data, out DebugReservedInfo info)
        {
            info = null;
            if (data == null || data.Length < 8)
            {
                return false;
            }

            uint version = ReadUInt32(data, 0);
            uint flags = ReadUInt32(data, 4);
            int count = (data.Length - 8) / 4;
            uint[] offsets = new uint[count];
            int cursor = 8;
            for (int i = 0; i < count; i++)
            {
                offsets[i] = ReadUInt32(data, cursor);
                cursor += 4;
            }

            info = new DebugReservedInfo(version, flags, offsets);
            return true;
        }

        private static bool TryParseDebugEmbeddedPortablePdbData(byte[] data, out DebugEmbeddedPortablePdbInfo info)
        {
            info = null;
            if (data == null || data.Length < 8)
            {
                return false;
            }

            string signature = Encoding.ASCII.GetString(data, 0, 4);
            uint uncompressedSize = ReadUInt32(data, 4);
            uint compressedSize = data.Length >= 8 ? (uint)(data.Length - 8) : 0;
            string notes = string.Empty;
            if (!string.Equals(signature, "MPDB", StringComparison.Ordinal))
            {
                notes = "Unexpected signature.";
            }

            string payloadHash = string.Empty;
            if (data.Length > 8)
            {
                byte[] payload = new byte[data.Length - 8];
                Array.Copy(data, 8, payload, 0, payload.Length);
                payloadHash = ToHex(SHA256.HashData(payload));
            }

            info = new DebugEmbeddedPortablePdbInfo(signature, uncompressedSize, compressedSize, payloadHash, notes);
            return true;
        }

        private static bool TryParseDebugSpgoData(byte[] data, out DebugSpgoInfo info)
        {
            info = null;
            if (data == null)
            {
                return false;
            }

            string hash = data.Length > 0 ? ToHex(SHA256.HashData(data)) : string.Empty;
            string preview = BuildHexPreview(data, 48);
            info = new DebugSpgoInfo((uint)data.Length, hash, preview);
            return true;
        }

        private static bool TryParseDebugPdbHashData(byte[] data, out DebugPdbHashInfo info)
        {
            info = null;
            if (data == null || data.Length < 4)
            {
                return false;
            }

            uint algorithm = ReadUInt32(data, 0);
            string algorithmName = GetPdbHashAlgorithmName(algorithm);
            string hash = data.Length > 4 ? ToHex(new ReadOnlySpan<byte>(data, 4, data.Length - 4).ToArray()) : string.Empty;
            info = new DebugPdbHashInfo(algorithm, algorithmName, hash);
            return true;
        }

        private static string GetPdbHashAlgorithmName(uint algorithm)
        {
            return algorithm switch
            {
                1 => "SHA1",
                2 => "SHA256",
                3 => "SHA384",
                4 => "SHA512",
                _ => "Unknown"
            };
        }

        private static string[] DecodeBitFlags(uint flags)
        {
            if (flags == 0)
            {
                return Array.Empty<string>();
            }

            List<string> names = new List<string>();
            for (int bit = 0; bit < 32; bit++)
            {
                uint mask = 1u << bit;
                if ((flags & mask) != 0)
                {
                    names.Add("0x" + mask.ToString("X8", CultureInfo.InvariantCulture));
                }
            }

            return names.ToArray();
        }

        private bool TryParseCodeViewInfo(byte[] data, uint debugTimeDateStamp, out DebugCodeViewInfo info)
        {
            info = null;
            if (data == null || data.Length < 4)
            {
                return false;
            }

            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(data);
            string signature = Encoding.ASCII.GetString(data, 0, 4);
            if (string.Equals(signature, "RSDS", StringComparison.Ordinal) && data.Length >= 24)
            {
                Guid guid = new Guid(span.Slice(4, 16));
                uint age = ReadUInt32(span, 20);
                string path = ReadNullTerminatedAscii(span, 24, out int _);
                string fileName = GetFileNameFromPath(path);
                string sanitized = !string.IsNullOrWhiteSpace(fileName) ? fileName : path;
                bool hasGuid = guid != Guid.Empty;
                bool hasAge = age > 0;
                bool hasPath = !string.IsNullOrWhiteSpace(path);
                bool hasDirectory = hasPath && (path.Contains("\\", StringComparison.Ordinal) || path.Contains("/", StringComparison.Ordinal));
                bool pathEndsWithPdb = path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase);
                string pdbId = hasGuid
                    ? string.Format(CultureInfo.InvariantCulture, "{0:N}{1:X}", guid, age)
                    : string.Empty;
                bool identityLooksValid = hasGuid && hasAge && pathEndsWithPdb;
                info = new DebugCodeViewInfo(
                    signature,
                    guid,
                    age,
                    path,
                    fileName,
                    sanitized,
                    pdbId,
                    0,
                    0,
                    false,
                    false,
                    true,
                    false,
                    hasGuid,
                    hasAge,
                    hasPath,
                    pathEndsWithPdb,
                    hasDirectory,
                    identityLooksValid);
                return true;
            }

            if (string.Equals(signature, "NB10", StringComparison.Ordinal) && data.Length >= 16)
            {
                uint pdbSignature = ReadUInt32(span, 4);
                uint timeDateStamp = ReadUInt32(span, 8);
                uint age = ReadUInt32(span, 12);
                string path = ReadNullTerminatedAscii(span, 16, out int _);
                bool matches = timeDateStamp != 0 && timeDateStamp == debugTimeDateStamp;
                string fileName = GetFileNameFromPath(path);
                string sanitized = !string.IsNullOrWhiteSpace(fileName) ? fileName : path;
                bool hasAge = age > 0;
                bool hasPath = !string.IsNullOrWhiteSpace(path);
                bool hasDirectory = hasPath && (path.Contains("\\", StringComparison.Ordinal) || path.Contains("/", StringComparison.Ordinal));
                bool pathEndsWithPdb = path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase);
                string pdbId = (pdbSignature != 0 || timeDateStamp != 0)
                    ? string.Format(CultureInfo.InvariantCulture, "{0:X8}{1:X8}{2:X}", pdbSignature, timeDateStamp, age)
                    : string.Empty;
                bool identityLooksValid = (pdbSignature != 0 || timeDateStamp != 0) && hasAge && pathEndsWithPdb;
                info = new DebugCodeViewInfo(
                    signature,
                    Guid.Empty,
                    age,
                    path,
                    fileName,
                    sanitized,
                    pdbId,
                    pdbSignature,
                    timeDateStamp,
                    true,
                    matches,
                    false,
                    true,
                    false,
                    hasAge,
                    hasPath,
                    pathEndsWithPdb,
                    hasDirectory,
                    identityLooksValid);
                return true;
            }

            return false;
        }

        private static string GetFileNameFromPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            try
            {
                return Path.GetFileName(path);
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        private void ParseTlsDirectory(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections, bool isPe32Plus, ulong imageBase)
        {
            if (!TryGetFileOffset(sections, directory.VirtualAddress, out long tlsOffset))
            {
                Warn(ParseIssueCategory.Tls, "TLS directory RVA not mapped to a section.");
                return;
            }

            int size = isPe32Plus ? Marshal.SizeOf(typeof(IMAGE_TLS_DIRECTORY64)) : Marshal.SizeOf(typeof(IMAGE_TLS_DIRECTORY32));
            if (!TrySetPosition(tlsOffset, size))
            {
                Warn(ParseIssueCategory.Tls, "TLS directory offset outside file bounds.");
                return;
            }

            byte[] buffer = new byte[size];
            ReadExactly(PEFileStream, buffer, 0, buffer.Length);

            ulong startRaw = 0;
            ulong endRaw = 0;
            ulong indexAddr = 0;
            ulong callbacksAddr = 0;
            uint zeroFill = 0;
            uint characteristics = 0;

            if (isPe32Plus)
            {
                IMAGE_TLS_DIRECTORY64 tls = ByteArrayToStructure<IMAGE_TLS_DIRECTORY64>(buffer);
                startRaw = tls.StartAddressOfRawData;
                endRaw = tls.EndAddressOfRawData;
                indexAddr = tls.AddressOfIndex;
                callbacksAddr = tls.AddressOfCallbacks;
                zeroFill = tls.SizeOfZeroFill;
                characteristics = tls.Characteristics;
            }
            else
            {
                IMAGE_TLS_DIRECTORY32 tls = ByteArrayToStructure<IMAGE_TLS_DIRECTORY32>(buffer);
                startRaw = tls.StartAddressOfRawData;
                endRaw = tls.EndAddressOfRawData;
                indexAddr = tls.AddressOfIndex;
                callbacksAddr = tls.AddressOfCallbacks;
                zeroFill = tls.SizeOfZeroFill;
                characteristics = tls.Characteristics;
            }

            uint rawDataSize = 0;
            uint rawDataRva = 0;
            bool rawDataMapped = false;
            string rawDataSectionName = string.Empty;
            int alignmentBytes = DecodeTlsAlignmentBytes(characteristics);
            string rawDataHash = string.Empty;
            string rawDataPreview = string.Empty;
            bool rawDataPreviewIsText = false;
            TlsIndexInfo indexInfo = null;

            if (startRaw != 0 && endRaw >= startRaw)
            {
                ulong diff = endRaw - startRaw;
                rawDataSize = diff > uint.MaxValue ? uint.MaxValue : (uint)diff;
                if (TryVaToRva(startRaw, imageBase, out uint startRva))
                {
                    rawDataRva = startRva;
                    if (TryGetSectionByRva(sections, startRva, out IMAGE_SECTION_HEADER rawSection))
                    {
                        rawDataSectionName = NormalizeSectionName(rawSection.Section);
                        rawDataMapped = true;
                        if (rawDataSize > 0)
                        {
                            uint sectionSize = Math.Max(rawSection.VirtualSize, rawSection.SizeOfRawData);
                            ulong endRva = (ulong)startRva + rawDataSize;
                            ulong sectionEnd = (ulong)rawSection.VirtualAddress + sectionSize;
                            if (endRva > sectionEnd)
                            {
                                rawDataMapped = false;
                                Warn(ParseIssueCategory.Tls, "TLS raw data range exceeds section bounds.");
                            }
                        }
                    }
                    else
                    {
                        Warn(ParseIssueCategory.Tls, "TLS raw data RVA not mapped to a section.");
                    }
                }
            }

            if (rawDataMapped && rawDataSize > 0)
            {
                TryComputeTlsRawDataInfo(sections, rawDataRva, rawDataSize, out rawDataHash, out rawDataPreviewIsText, out rawDataPreview);
            }

            if (indexAddr != 0)
            {
                bool hasRva = TryVaToRva(indexAddr, imageBase, out uint indexRva);
                bool indexMapped = false;
                string indexSectionName = string.Empty;
                uint indexSectionRva = 0;
                uint indexSectionOffset = 0;
                if (hasRva && TryGetSectionByRva(sections, indexRva, out IMAGE_SECTION_HEADER indexSection))
                {
                    indexMapped = true;
                    indexSectionName = NormalizeSectionName(indexSection.Section);
                    indexSectionRva = indexSection.VirtualAddress;
                    if (indexRva >= indexSectionRva)
                    {
                        indexSectionOffset = indexRva - indexSectionRva;
                    }
                }

                bool hasValue = false;
                uint indexValue = 0;
                if (TryGetFileOffsetFromVa(sections, indexAddr, imageBase, out long indexOffset) &&
                    TrySetPosition(indexOffset, 4))
                {
                    indexValue = PEFile.ReadUInt32();
                    hasValue = true;
                }

                indexInfo = BuildTlsIndexInfoCore(
                    indexAddr,
                    indexRva,
                    hasRva,
                    indexMapped,
                    indexSectionName,
                    indexSectionRva,
                    indexSectionOffset,
                    hasValue,
                    indexValue);
            }

            TlsTemplateInfo templateInfo = BuildTlsTemplateInfo(
                startRaw,
                endRaw,
                rawDataSize,
                zeroFill,
                alignmentBytes,
                rawDataMapped,
                rawDataHash,
                rawDataPreviewIsText,
                rawDataPreview);

            ulong[] callbacks = Array.Empty<ulong>();
            List<TlsCallbackInfo> callbackInfos = new List<TlsCallbackInfo>();
            if (callbacksAddr != 0 &&
                TryGetFileOffsetFromVa(sections, callbacksAddr, imageBase, out long callbacksOffset))
            {
                List<ulong> callbackList = new List<ulong>();
                int pointerSize = isPe32Plus ? 8 : 4;
                int maxEntries = 128;
                for (int i = 0; i < maxEntries; i++)
                {
                    long entryOffset = callbacksOffset + (i * pointerSize);
                    if (!TrySetPosition(entryOffset, pointerSize))
                    {
                        break;
                    }

                    ulong value = isPe32Plus ? PEFile.ReadUInt64() : PEFile.ReadUInt32();
                    if (value == 0)
                    {
                        break;
                    }

                    callbackList.Add(value);
                }

                callbacks = callbackList.ToArray();
            }

            if (callbacks.Length > 0)
            {
                bool warnedUnmapped = false;
                foreach (ulong callback in callbacks)
                {
                    uint callbackRva = 0;
                    string symbol = string.Empty;
                    string sectionName = string.Empty;
                    uint sectionRva = 0;
                    uint sectionOffset = 0;
                    string resolutionSource = "None";
                    if (TryVaToRva(callback, imageBase, out uint resolvedRva))
                    {
                        callbackRva = resolvedRva;
                        if (TryResolveExportName(callbackRva, out string resolved))
                        {
                            symbol = resolved;
                            resolutionSource = "Export";
                        }

                        if (TryGetSectionByRva(sections, callbackRva, out IMAGE_SECTION_HEADER section))
                        {
                            sectionName = NormalizeSectionName(section.Section);
                            sectionRva = section.VirtualAddress;
                            if (callbackRva >= section.VirtualAddress)
                            {
                                sectionOffset = callbackRva - section.VirtualAddress;
                            }
                        }
                        else if (!warnedUnmapped)
                        {
                            Warn(ParseIssueCategory.Tls, "TLS callback RVA not mapped to a section.");
                            warnedUnmapped = true;
                        }
                    }

                    callbackInfos.Add(new TlsCallbackInfo(
                        callback,
                        callbackRva,
                        symbol,
                        sectionName,
                        sectionRva,
                        sectionOffset,
                        resolutionSource));
                }
            }

            _tlsInfo = new TlsInfo(
                startRaw,
                endRaw,
                indexAddr,
                indexInfo,
                callbacksAddr,
                zeroFill,
                characteristics,
                rawDataSize,
                rawDataRva,
                rawDataMapped,
                rawDataSectionName,
                alignmentBytes,
                templateInfo,
                rawDataHash,
                rawDataPreviewIsText,
                rawDataPreview,
                callbacks,
                callbackInfos.ToArray());
        }

        private static TlsTemplateInfo BuildTlsTemplateInfo(
            ulong startRaw,
            ulong endRaw,
            uint rawDataSize,
            uint zeroFill,
            int alignmentBytes,
            bool rawDataMapped,
            string rawDataHash,
            bool rawDataPreviewIsText,
            string rawDataPreview)
        {
            bool rangeValid = endRaw >= startRaw;
            uint rangeSize = 0;
            if (rangeValid && (startRaw != 0 || endRaw != 0))
            {
                ulong diff = endRaw - startRaw;
                rangeSize = diff > uint.MaxValue ? uint.MaxValue : (uint)diff;
            }

            ulong totalSizeLong = (ulong)rawDataSize + zeroFill;
            uint totalSize = totalSizeLong > uint.MaxValue ? uint.MaxValue : (uint)totalSizeLong;
            bool sizeMatchesRange = rangeValid && (startRaw == 0 && endRaw == 0
                ? rawDataSize == 0
                : rangeSize == rawDataSize);
            bool aligned = alignmentBytes <= 1 || totalSize % alignmentBytes == 0;
            string notes = string.Empty;
            if (!rangeValid && (startRaw != 0 || endRaw != 0))
            {
                notes = AppendNote(notes, "invalid raw data range");
            }
            if (rawDataSize == 0 && zeroFill > 0)
            {
                notes = AppendNote(notes, "zero-fill only");
            }
            if (!rawDataMapped && rawDataSize > 0)
            {
                notes = AppendNote(notes, "raw data not mapped");
            }
            if (!aligned && alignmentBytes > 1)
            {
                notes = AppendNote(notes, "template size not aligned");
            }

            return new TlsTemplateInfo(
                rawDataSize,
                zeroFill,
                totalSize,
                rangeValid,
                rangeSize,
                sizeMatchesRange,
                aligned,
                notes,
                rawDataHash,
                rawDataPreviewIsText,
                rawDataPreview);
        }

        private static TlsIndexInfo BuildTlsIndexInfoCore(
            ulong address,
            uint rva,
            bool hasRva,
            bool isMapped,
            string sectionName,
            uint sectionRva,
            uint sectionOffset,
            bool hasValue,
            uint value)
        {
            string notes = string.Empty;
            if (address != 0 && !hasRva)
            {
                notes = AppendNote(notes, "index VA not in image");
            }
            if (hasRva && !isMapped)
            {
                notes = AppendNote(notes, "index RVA not mapped to a section");
            }
            if (!hasValue && address != 0)
            {
                notes = AppendNote(notes, "index value not readable");
            }

            return new TlsIndexInfo(
                address,
                rva,
                hasRva,
                isMapped,
                sectionName,
                sectionRva,
                sectionOffset,
                hasValue,
                value,
                notes);
        }

        private bool TryComputeTlsRawDataInfo(
            List<IMAGE_SECTION_HEADER> sections,
            uint rawDataRva,
            uint rawDataSize,
            out string hash,
            out bool isText,
            out string preview)
        {
            hash = string.Empty;
            preview = string.Empty;
            isText = false;

            if (PEFileStream == null || rawDataSize == 0)
            {
                return false;
            }

            if (!TryGetFileOffset(sections, rawDataRva, out long rawOffset))
            {
                return false;
            }

            long fileLength = PEFileStream.Length;
            if (rawOffset < 0 || rawOffset >= fileLength)
            {
                return false;
            }

            long available = Math.Min((long)rawDataSize, fileLength - rawOffset);
            if (available <= 0)
            {
                return false;
            }

            long originalPosition = PEFileStream.CanSeek ? PEFileStream.Position : 0;
            try
            {
                int previewBytes = (int)Math.Min(available, 96);
                if (previewBytes > 0 && TrySetPosition(rawOffset, previewBytes))
                {
                    byte[] previewBuffer = new byte[previewBytes];
                    ReadExactly(PEFileStream, previewBuffer, 0, previewBuffer.Length);
                    BuildRawDataPreview(previewBuffer, out isText, out preview);
                }

                using (IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    byte[] buffer = new byte[8192];
                    long remaining = available;
                    long offset = rawOffset;
                    while (remaining > 0)
                    {
                        int read = (int)Math.Min(remaining, buffer.Length);
                        if (!TrySetPosition(offset, read))
                        {
                            break;
                        }

                        ReadExactly(PEFileStream, buffer, 0, read);
                        hasher.AppendData(buffer, 0, read);
                        offset += read;
                        remaining -= read;
                    }

                    if (remaining == 0)
                    {
                        hash = ToHex(hasher.GetHashAndReset());
                    }
                }
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }

            return !string.IsNullOrWhiteSpace(hash) || !string.IsNullOrWhiteSpace(preview);
        }

        private void ParseLoadConfigDirectory(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections, bool isPe32Plus)
        {
            if (!TryGetFileOffset(sections, directory.VirtualAddress, out long configOffset))
            {
                Warn(ParseIssueCategory.LoadConfig, "Load config directory RVA not mapped to a section.");
                return;
            }

            if (!TryGetIntSize(directory.Size, out int configSize) || configSize <= 0)
            {
                Warn(ParseIssueCategory.LoadConfig, "Load config directory size is invalid.");
                return;
            }

            if (!TrySetPosition(configOffset, configSize))
            {
                Warn(ParseIssueCategory.LoadConfig, "Load config directory offset outside file bounds.");
                return;
            }

            byte[] buffer = new byte[configSize];
            ReadExactly(PEFileStream, buffer, 0, buffer.Length);
            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(buffer);

            int offset = 0;
            uint size = ReadUInt32(span, offset);
            offset += 4;
            int limit = span.Length;
            if (size > 0 && size < (uint)limit)
            {
                limit = (int)size;
            }
            uint timeDateStamp = ReadUInt32(span, offset);
            offset += 4;
            ushort major = ReadUInt16(span, offset);
            offset += 2;
            ushort minor = ReadUInt16(span, offset);
            offset += 2;
            uint globalFlagsClear = ReadUInt32(span, offset);
            offset += 4;
            uint globalFlagsSet = ReadUInt32(span, offset);
            offset += 4;
            offset += 4; // CriticalSectionDefaultTimeout

            if (isPe32Plus)
            {
                offset += 8; // DeCommitFreeBlockThreshold
                offset += 8; // DeCommitTotalFreeThreshold
                offset += 8; // LockPrefixTable
                offset += 8; // MaximumAllocationSize
                offset += 8; // VirtualMemoryThreshold
            }
            else
            {
                offset += 4; // DeCommitFreeBlockThreshold
                offset += 4; // DeCommitTotalFreeThreshold
                offset += 4; // LockPrefixTable
                offset += 4; // MaximumAllocationSize
                offset += 4; // VirtualMemoryThreshold
            }

            uint processHeapFlags = ReadUInt32(span, offset);
            offset += 4;

            if (isPe32Plus)
            {
                offset += 8; // ProcessAffinityMask
            }
            else
            {
                offset += 4; // ProcessAffinityMask
            }

            uint csdVersion = ReadUInt16(span, offset);
            offset += 2;
            uint dependentLoadFlags = ReadUInt16(span, offset);
            offset += 2;

            if (isPe32Plus)
            {
                offset += 8; // EditList
            }
            else
            {
                offset += 4; // EditList
            }

            ulong securityCookie = ReadPointer(span, ref offset, isPe32Plus);
            ulong seHandlerTable = ReadPointer(span, ref offset, isPe32Plus);
            uint seHandlerCount = isPe32Plus ? (uint)ReadUInt64(span, offset) : ReadUInt32(span, offset);
            offset += isPe32Plus ? 8 : 4;

            ulong guardCfCheck = ReadPointer(span, ref offset, isPe32Plus);
            ulong guardCfDispatch = ReadPointer(span, ref offset, isPe32Plus);
            ulong guardCfTable = ReadPointer(span, ref offset, isPe32Plus);
            uint guardCfCount = isPe32Plus ? (uint)ReadUInt64(span, offset) : ReadUInt32(span, offset);
            offset += isPe32Plus ? 8 : 4;
            uint guardFlags = ReadUInt32(span, offset);
            offset += 4;
            LoadConfigGuardFlagsInfo guardFlagsInfo = DecodeGuardFlags(guardFlags);
            LoadConfigGlobalFlagsInfo globalFlagsInfo = DecodeGlobalFlags(globalFlagsClear, globalFlagsSet);
            LoadConfigCodeIntegrityInfo codeIntegrityInfo = null;
            ulong guardAddressTakenIatEntryTable = 0;
            ulong guardAddressTakenIatEntryCount = 0;
            ulong guardLongJumpTargetTable = 0;
            ulong guardLongJumpTargetCount = 0;

            ulong dynamicValueRelocTable = 0;
            uint dynamicValueRelocTableOffset = 0;
            ushort dynamicValueRelocTableSection = 0;
            uint dynamicValueRelocTableOffsetRaw = 0;
            ushort dynamicValueRelocTableSectionRaw = 0;
            ulong chpeMetadataPointer = 0;
            ulong guardRFFailureRoutine = 0;
            ulong guardRFFailureRoutineFunctionPointer = 0;
            ulong guardRFVerifyStackPointerFunctionPointer = 0;
            uint hotPatchTableOffset = 0;
            ulong enclaveConfigurationPointer = 0;
            ulong volatileMetadataPointer = 0;
            ulong guardEhContinuationTable = 0;
            ulong guardEhContinuationCount = 0;
            ulong guardXfgCheckFunctionPointer = 0;
            ulong guardXfgDispatchFunctionPointer = 0;
            ulong guardXfgTableDispatchFunctionPointer = 0;
            EnclaveConfigurationInfo enclaveConfigInfo = null;
            GuardRvaTableInfo guardCfFunctionTableInfo = null;
            GuardRvaTableInfo guardAddressTakenIatTableInfo = null;
            GuardRvaTableInfo guardLongJumpTargetTableInfo = null;
            DynamicRelocationMetadataInfo dynamicRelocationMetadataInfo = null;
            ChpeMetadataInfo chpeMetadataInfo = null;
            VolatileMetadataInfo volatileMetadataInfo = null;

            bool readCodeIntegrity = TryReadCodeIntegrity(span, ref offset, limit, out codeIntegrityInfo);
            bool readGuardAddressTakenIatTable = false;
            bool readGuardAddressTakenIatCount = false;
            bool readGuardLongJumpTargetTable = false;
            bool readGuardLongJumpTargetCount = false;
            bool readDynamicValueRelocTable = false;
            bool readChpeMetadataPointer = false;
            bool readGuardRFFailureRoutine = false;
            bool readGuardRFFailureRoutineFunctionPointer = false;
            bool readDynamicRelocMetadata = false;
            bool readGuardRFVerifyStackPointer = false;
            bool readHotPatchTableOffset = false;
            bool readEnclaveConfigurationPointer = false;
            bool readVolatileMetadataPointer = false;
            bool readGuardEhContinuationTable = false;
            bool readGuardEhContinuationCount = false;
            bool readGuardXfgCheckFunctionPointer = false;
            bool readGuardXfgDispatchFunctionPointer = false;
            bool readGuardXfgTableDispatchFunctionPointer = false;

            if (readCodeIntegrity &&
                (readGuardAddressTakenIatTable = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardAddressTakenIatEntryTable)) &&
                (readGuardAddressTakenIatCount = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardAddressTakenIatEntryCount)) &&
                (readGuardLongJumpTargetTable = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardLongJumpTargetTable)) &&
                (readGuardLongJumpTargetCount = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardLongJumpTargetCount)) &&
                (readDynamicValueRelocTable = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out dynamicValueRelocTable)) &&
                (readChpeMetadataPointer = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out chpeMetadataPointer)))
            {
                readGuardRFFailureRoutine = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardRFFailureRoutine); // GuardRFFailureRoutine
                readGuardRFFailureRoutineFunctionPointer = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardRFFailureRoutineFunctionPointer); // GuardRFFailureRoutineFunctionPointer
                if (TryReadUInt32Value(span, ref offset, limit, out dynamicValueRelocTableOffsetRaw))
                {
                    readDynamicRelocMetadata = true;
                    if (TryReadUInt16Value(span, ref offset, limit, out dynamicValueRelocTableSectionRaw))
                    {
                        TryReadUInt16Value(span, ref offset, limit, out _);
                    }
                }

                readGuardRFVerifyStackPointer = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardRFVerifyStackPointerFunctionPointer); // GuardRFVerifyStackPointerFunctionPointer
                readHotPatchTableOffset = TryReadUInt32Value(span, ref offset, limit, out hotPatchTableOffset); // HotPatchTableOffset
                if (readHotPatchTableOffset)
                {
                    TryReadUInt32Value(span, ref offset, limit, out _); // Reserved3
                }

                readEnclaveConfigurationPointer = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out enclaveConfigurationPointer); // EnclaveConfigurationPointer
                readVolatileMetadataPointer = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out volatileMetadataPointer); // VolatileMetadataPointer

                if (TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardEhContinuationTable))
                {
                    readGuardEhContinuationTable = true;
                    readGuardEhContinuationCount = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardEhContinuationCount);
                    readGuardXfgCheckFunctionPointer = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardXfgCheckFunctionPointer);
                    readGuardXfgDispatchFunctionPointer = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardXfgDispatchFunctionPointer);
                    readGuardXfgTableDispatchFunctionPointer = TryReadPointerValue(span, ref offset, limit, isPe32Plus, out guardXfgTableDispatchFunctionPointer);
                }
            }

            if (readDynamicRelocMetadata)
            {
                dynamicValueRelocTableOffset = dynamicValueRelocTableOffsetRaw;
                dynamicValueRelocTableSection = dynamicValueRelocTableSectionRaw;
            }

            if (dynamicValueRelocTable != 0)
            {
                if (_imageBase == 0)
                {
                    Warn(ParseIssueCategory.LoadConfig, "Dynamic value relocation table pointer set but image base is unavailable.");
                }
                else if (TryGetRvaFromAddress(dynamicValueRelocTable, _imageBase, out uint dynamicRva, out _))
                {
                    if (TryGetSectionIndexByRva(sections, dynamicRva, out int sectionIndex, out IMAGE_SECTION_HEADER section))
                    {
                        dynamicValueRelocTableOffset = dynamicRva - section.VirtualAddress;
                        dynamicValueRelocTableSection = (ushort)(sectionIndex + 1);
                    }
                    else
                    {
                        Warn(ParseIssueCategory.LoadConfig, "Dynamic value relocation table pointer is not mapped to a section.");
                    }
                }
            }
            else if (!readDynamicRelocMetadata)
            {
                dynamicValueRelocTableOffset = 0;
                dynamicValueRelocTableSection = 0;
            }

            if (guardFlagsInfo.CfFunctionTablePresent && (guardCfTable == 0 || guardCfCount == 0))
            {
                Warn(ParseIssueCategory.LoadConfig, "Guard CF table present flag is set but table pointer/count is missing.");
            }

            if (guardFlagsInfo.EhContinuationTablePresent && (guardEhContinuationTable == 0 || guardEhContinuationCount == 0))
            {
                Warn(ParseIssueCategory.LoadConfig, "Guard EH continuation table present flag is set but table pointer/count is missing.");
            }

            if (guardFlagsInfo.XfgTablePresent && guardXfgTableDispatchFunctionPointer == 0)
            {
                Warn(ParseIssueCategory.LoadConfig, "Guard XFG table present flag is set but table dispatch pointer is missing.");
            }

            if (guardFlagsInfo.XfgEnabled && (guardXfgCheckFunctionPointer == 0 || guardXfgDispatchFunctionPointer == 0))
            {
                Warn(ParseIssueCategory.LoadConfig, "Guard XFG enabled flag is set but check/dispatch pointers are missing.");
            }

            if ((guardFlagsInfo.CfInstrumented || guardFlagsInfo.CfwInstrumented) && guardCfCheck == 0 && guardCfDispatch == 0)
            {
                Warn(ParseIssueCategory.LoadConfig, "Guard CF instrumentation is enabled but CF check/dispatch pointers are missing.");
            }

            List<GuardFeatureInfo> guardFeatures = new List<GuardFeatureInfo>
            {
                new GuardFeatureInfo(
                    "ControlFlowGuard",
                    guardFlagsInfo.CfInstrumented || guardFlagsInfo.CfwInstrumented,
                    guardFlagsInfo.CfFunctionTablePresent && guardCfTable != 0 && guardCfCount > 0,
                    guardCfCheck != 0 || guardCfDispatch != 0,
                    guardFlagsInfo.CfFunctionTablePresent ? "CF table present" : string.Empty),
                new GuardFeatureInfo(
                    "EHContinuation",
                    guardFlagsInfo.EhContinuationTablePresent,
                    guardEhContinuationTable != 0 && guardEhContinuationCount > 0,
                    guardEhContinuationTable != 0,
                    guardFlagsInfo.EhContinuationTablePresent ? "EH continuation table present" : string.Empty),
                new GuardFeatureInfo(
                    "XFG",
                    guardFlagsInfo.XfgEnabled || guardFlagsInfo.XfgTablePresent,
                    guardXfgTableDispatchFunctionPointer != 0,
                    guardXfgCheckFunctionPointer != 0 || guardXfgDispatchFunctionPointer != 0,
                    guardFlagsInfo.XfgTablePresent ? "XFG table present" : string.Empty),
                new GuardFeatureInfo(
                    "CHPE",
                    chpeMetadataPointer != 0,
                    chpeMetadataPointer != 0,
                    chpeMetadataPointer != 0,
                    chpeMetadataPointer != 0 ? "CHPE metadata present" : string.Empty)
            };

            List<GuardTableSanityInfo> guardTableSanity = new List<GuardTableSanityInfo>
            {
                BuildGuardTableSanity(
                    "CFG Function Table",
                    guardCfTable,
                    guardCfCount,
                    true,
                    sections,
                    4,
                    false),
                BuildGuardTableSanity(
                    "EH Continuation Table",
                    guardEhContinuationTable,
                    guardEhContinuationCount,
                    true,
                    sections,
                    4,
                    false),
                BuildGuardTableSanity(
                    "XFG Table Dispatch",
                    guardXfgTableDispatchFunctionPointer,
                    0,
                    false,
                    sections,
                    0,
                    true)
            };

            foreach (GuardTableSanityInfo info in guardTableSanity)
            {
                if (info.PointerPresent && !info.MappedToSection)
                {
                    Warn(ParseIssueCategory.LoadConfig, $"{info.Name} pointer is not mapped to a section.");
                }

                if (info.PointerPresent && info.CountPresent && !info.SizeFits)
                {
                    Warn(ParseIssueCategory.LoadConfig, $"{info.Name} size exceeds section bounds.");
                }
            }

            guardCfFunctionTableInfo = BuildGuardRvaTableInfo("Guard CF Function Table", guardCfTable, guardCfCount, 4, sections);
            guardAddressTakenIatTableInfo = BuildGuardRvaTableInfo("Guard Address Taken IAT Table", guardAddressTakenIatEntryTable, guardAddressTakenIatEntryCount, 4, sections);
            guardLongJumpTargetTableInfo = BuildGuardRvaTableInfo("Guard Long Jump Target Table", guardLongJumpTargetTable, guardLongJumpTargetCount, 4, sections);

            SehHandlerTableInfo sehHandlerTableInfo = null;
            if (!isPe32Plus && seHandlerTable != 0 && seHandlerCount > 0)
            {
                sehHandlerTableInfo = BuildSehHandlerTableInfo(seHandlerTable, seHandlerCount, sections);
            }

            if (enclaveConfigurationPointer != 0)
            {
                enclaveConfigInfo = TryReadEnclaveConfiguration(enclaveConfigurationPointer, sections);
            }

            if (dynamicValueRelocTable != 0)
            {
                dynamicRelocationMetadataInfo = TryReadDynamicRelocationMetadata(dynamicValueRelocTable, sections);
            }

            if (chpeMetadataPointer != 0)
            {
                chpeMetadataInfo = TryReadChpeMetadata(chpeMetadataPointer, sections);
            }

            if (volatileMetadataPointer != 0)
            {
                volatileMetadataInfo = TryReadVolatileMetadata(volatileMetadataPointer, sections);
            }

            LoadConfigVersionInfo versionInfo = BuildLoadConfigVersionInfo(
                size,
                (uint)limit,
                (uint)Math.Min(offset, limit),
                readCodeIntegrity,
                readGuardAddressTakenIatTable,
                readDynamicValueRelocTable,
                readChpeMetadataPointer,
                readGuardRFFailureRoutine || readGuardRFFailureRoutineFunctionPointer || readGuardRFVerifyStackPointer,
                readHotPatchTableOffset,
                readEnclaveConfigurationPointer,
                readVolatileMetadataPointer,
                readGuardEhContinuationTable,
                readGuardXfgCheckFunctionPointer || readGuardXfgDispatchFunctionPointer || readGuardXfgTableDispatchFunctionPointer,
                span);

            _loadConfig = new LoadConfigInfo(
                size,
                versionInfo,
                timeDateStamp,
                major,
                minor,
                globalFlagsClear,
                globalFlagsSet,
                globalFlagsInfo,
                codeIntegrityInfo,
                processHeapFlags,
                csdVersion,
                dependentLoadFlags,
                securityCookie,
                seHandlerTable,
                seHandlerCount,
                guardCfCheck,
                guardCfDispatch,
                guardCfTable,
                guardCfCount,
                guardFlags,
                guardFlagsInfo,
                dynamicValueRelocTable,
                dynamicValueRelocTableOffset,
                dynamicValueRelocTableSection,
                chpeMetadataPointer,
                guardRFFailureRoutine,
                guardRFFailureRoutineFunctionPointer,
                guardRFVerifyStackPointerFunctionPointer,
                hotPatchTableOffset,
                enclaveConfigurationPointer,
                volatileMetadataPointer,
                guardEhContinuationTable,
                guardEhContinuationCount,
                guardXfgCheckFunctionPointer,
                guardXfgDispatchFunctionPointer,
                guardXfgTableDispatchFunctionPointer,
                guardCfFunctionTableInfo,
                guardAddressTakenIatTableInfo,
                guardLongJumpTargetTableInfo,
                guardFeatures.ToArray(),
                guardTableSanity.ToArray(),
                sehHandlerTableInfo,
                dynamicRelocationMetadataInfo,
                chpeMetadataInfo,
                volatileMetadataInfo,
                enclaveConfigInfo);
        }

        private DynamicRelocationMetadataInfo TryReadDynamicRelocationMetadata(ulong pointer, List<IMAGE_SECTION_HEADER> sections)
        {
            const int minHeaderSize = 8;
            const int maxBlobSize = 64 * 1024;

            if (!TryResolveLoadConfigPointer(pointer, sections, out uint rva, out long fileOffset, out string pointerSource, out string sectionName, out IMAGE_SECTION_HEADER section))
            {
                DynamicRelocationMetadataInfo unmappedInfo = new DynamicRelocationMetadataInfo(
                    pointer,
                    false,
                    string.Empty,
                    0,
                    string.Empty,
                    0,
                    0,
                    true,
                    "pointer not mapped",
                    new[] { "Dynamic relocation metadata pointer is not mapped to a section." },
                    Array.Empty<DynamicRelocationEntryInfo>());
                foreach (string issue in unmappedInfo.Issues)
                {
                    Warn(ParseIssueCategory.LoadConfig, issue);
                }

                return unmappedInfo;
            }

            int available = GetAvailableBytesInSection(section, rva);
            int bytesToRead = Math.Min(maxBlobSize, available);
            if (bytesToRead < minHeaderSize)
            {
                DynamicRelocationMetadataInfo shortInfo = new DynamicRelocationMetadataInfo(
                    pointer,
                    true,
                    pointerSource,
                    rva,
                    sectionName,
                    0,
                    0,
                    true,
                    "header outside bounds",
                    new[] { "Dynamic relocation metadata header is outside section bounds." },
                    Array.Empty<DynamicRelocationEntryInfo>());
                foreach (string issue in shortInfo.Issues)
                {
                    Warn(ParseIssueCategory.LoadConfig, issue);
                }

                return shortInfo;
            }

            if (!TryReadLoadConfigBlob(fileOffset, bytesToRead, out byte[] blob))
            {
                DynamicRelocationMetadataInfo readFailInfo = new DynamicRelocationMetadataInfo(
                    pointer,
                    true,
                    pointerSource,
                    rva,
                    sectionName,
                    0,
                    0,
                    true,
                    "read failed",
                    new[] { "Dynamic relocation metadata could not be read from file." },
                    Array.Empty<DynamicRelocationEntryInfo>());
                foreach (string issue in readFailInfo.Issues)
                {
                    Warn(ParseIssueCategory.LoadConfig, issue);
                }

                return readFailInfo;
            }

            DynamicRelocationMetadataInfo info = ParseDynamicRelocationMetadataBlob(blob, pointer, true, pointerSource, rva, sectionName);
            foreach (string issue in info.Issues)
            {
                Warn(ParseIssueCategory.LoadConfig, issue);
            }

            return info;
        }

        private ChpeMetadataInfo TryReadChpeMetadata(ulong pointer, List<IMAGE_SECTION_HEADER> sections)
        {
            const int minHeaderSize = 12;
            const int maxBlobSize = 64 * 1024;

            if (!TryResolveLoadConfigPointer(pointer, sections, out uint rva, out long fileOffset, out string pointerSource, out string sectionName, out IMAGE_SECTION_HEADER section))
            {
                ChpeMetadataInfo unmappedInfo = new ChpeMetadataInfo(
                    pointer,
                    false,
                    string.Empty,
                    0,
                    string.Empty,
                    0,
                    0,
                    0,
                    true,
                    "pointer not mapped",
                    new[] { "CHPE metadata pointer is not mapped to a section." },
                    Array.Empty<ChpeCodeRangeInfo>());
                foreach (string issue in unmappedInfo.Issues)
                {
                    Warn(ParseIssueCategory.LoadConfig, issue);
                }

                return unmappedInfo;
            }

            int available = GetAvailableBytesInSection(section, rva);
            int bytesToRead = Math.Min(maxBlobSize, available);
            if (bytesToRead < minHeaderSize)
            {
                ChpeMetadataInfo shortInfo = new ChpeMetadataInfo(
                    pointer,
                    true,
                    pointerSource,
                    rva,
                    sectionName,
                    0,
                    0,
                    0,
                    true,
                    "header outside bounds",
                    new[] { "CHPE metadata header is outside section bounds." },
                    Array.Empty<ChpeCodeRangeInfo>());
                foreach (string issue in shortInfo.Issues)
                {
                    Warn(ParseIssueCategory.LoadConfig, issue);
                }

                return shortInfo;
            }

            if (!TryReadLoadConfigBlob(fileOffset, bytesToRead, out byte[] blob))
            {
                ChpeMetadataInfo readFailInfo = new ChpeMetadataInfo(
                    pointer,
                    true,
                    pointerSource,
                    rva,
                    sectionName,
                    0,
                    0,
                    0,
                    true,
                    "read failed",
                    new[] { "CHPE metadata could not be read from file." },
                    Array.Empty<ChpeCodeRangeInfo>());
                foreach (string issue in readFailInfo.Issues)
                {
                    Warn(ParseIssueCategory.LoadConfig, issue);
                }

                return readFailInfo;
            }

            ChpeMetadataInfo info = ParseChpeMetadataBlob(blob, pointer, true, pointerSource, rva, sectionName);
            foreach (string issue in info.Issues)
            {
                Warn(ParseIssueCategory.LoadConfig, issue);
            }

            return info;
        }

        private VolatileMetadataInfo TryReadVolatileMetadata(ulong pointer, List<IMAGE_SECTION_HEADER> sections)
        {
            const int minHeaderSize = 24;
            const int maxBlobSize = 64 * 1024;

            if (!TryResolveLoadConfigPointer(pointer, sections, out uint rva, out long fileOffset, out string pointerSource, out string sectionName, out IMAGE_SECTION_HEADER section))
            {
                VolatileMetadataInfo unmappedInfo = new VolatileMetadataInfo(
                    pointer,
                    false,
                    string.Empty,
                    0,
                    string.Empty,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    true,
                    "pointer not mapped",
                    new[] { "Volatile metadata pointer is not mapped to a section." });
                foreach (string issue in unmappedInfo.Issues)
                {
                    Warn(ParseIssueCategory.LoadConfig, issue);
                }

                return unmappedInfo;
            }

            int available = GetAvailableBytesInSection(section, rva);
            int bytesToRead = Math.Min(maxBlobSize, available);
            if (bytesToRead < minHeaderSize)
            {
                VolatileMetadataInfo shortInfo = new VolatileMetadataInfo(
                    pointer,
                    true,
                    pointerSource,
                    rva,
                    sectionName,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    true,
                    "header outside bounds",
                    new[] { "Volatile metadata header is outside section bounds." });
                foreach (string issue in shortInfo.Issues)
                {
                    Warn(ParseIssueCategory.LoadConfig, issue);
                }

                return shortInfo;
            }

            if (!TryReadLoadConfigBlob(fileOffset, bytesToRead, out byte[] blob))
            {
                VolatileMetadataInfo readFailInfo = new VolatileMetadataInfo(
                    pointer,
                    true,
                    pointerSource,
                    rva,
                    sectionName,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    true,
                    "read failed",
                    new[] { "Volatile metadata could not be read from file." });
                foreach (string issue in readFailInfo.Issues)
                {
                    Warn(ParseIssueCategory.LoadConfig, issue);
                }

                return readFailInfo;
            }

            VolatileMetadataInfo info = ParseVolatileMetadataBlob(blob, pointer, true, pointerSource, rva, sectionName);
            foreach (string issue in info.Issues)
            {
                Warn(ParseIssueCategory.LoadConfig, issue);
            }

            return info;
        }

        private bool TryResolveLoadConfigPointer(
            ulong pointer,
            List<IMAGE_SECTION_HEADER> sections,
            out uint rva,
            out long fileOffset,
            out string pointerSource,
            out string sectionName,
            out IMAGE_SECTION_HEADER section)
        {
            rva = 0;
            fileOffset = -1;
            pointerSource = string.Empty;
            sectionName = string.Empty;
            section = default;

            if (!TryGetRvaFromAddress(pointer, _imageBase, out rva, out pointerSource))
            {
                return false;
            }

            if (!TryGetSectionByRva(sections, rva, out section))
            {
                return false;
            }

            sectionName = NormalizeSectionName(section.Section);
            return TryGetFileOffset(sections, rva, out fileOffset);
        }

        private bool TryReadLoadConfigBlob(long fileOffset, int size, out byte[] blob)
        {
            blob = Array.Empty<byte>();
            if (size <= 0)
            {
                return false;
            }

            long originalPosition = 0;
            if (PEFileStream.CanSeek)
            {
                originalPosition = PEFileStream.Position;
            }

            try
            {
                if (!TrySetPosition(fileOffset, size))
                {
                    return false;
                }

                blob = new byte[size];
                ReadExactly(PEFileStream, blob, 0, size);
                return true;
            }
            catch
            {
                blob = Array.Empty<byte>();
                return false;
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private static int GetAvailableBytesInSection(IMAGE_SECTION_HEADER section, uint rva)
        {
            uint sectionSize = Math.Max(section.VirtualSize, section.SizeOfRawData);
            if (sectionSize == 0 || rva < section.VirtualAddress)
            {
                return 0;
            }

            ulong sectionEnd = (ulong)section.VirtualAddress + sectionSize;
            if ((ulong)rva >= sectionEnd)
            {
                return 0;
            }

            ulong available = sectionEnd - rva;
            return available > int.MaxValue ? int.MaxValue : (int)available;
        }

        private static DynamicRelocationMetadataInfo ParseDynamicRelocationMetadataBlob(
            ReadOnlySpan<byte> data,
            ulong pointer,
            bool isMapped,
            string pointerSource,
            uint rva,
            string sectionName)
        {
            List<string> issues = new List<string>();
            List<DynamicRelocationEntryInfo> entries = new List<DynamicRelocationEntryInfo>();
            uint version = 0;
            uint size = 0;
            bool malformed = false;

            if (data.Length < 8)
            {
                issues.Add("Dynamic relocation metadata header is smaller than 8 bytes.");
                malformed = true;
            }
            else
            {
                version = ReadUInt32(data, 0);
                size = ReadUInt32(data, 4);
                uint effectiveSize = size == 0 ? (uint)data.Length : size;
                if (effectiveSize < 8)
                {
                    issues.Add("Dynamic relocation metadata size is smaller than the header.");
                    malformed = true;
                    effectiveSize = 8;
                }

                if (effectiveSize > data.Length)
                {
                    issues.Add("Dynamic relocation metadata extends beyond readable bounds.");
                    malformed = true;
                    effectiveSize = (uint)data.Length;
                }

                int payloadBytes = (int)effectiveSize - 8;
                if ((payloadBytes & 0x7) != 0)
                {
                    issues.Add("Dynamic relocation metadata payload is not 8-byte aligned.");
                    malformed = true;
                }

                int entryCount = payloadBytes > 0 ? payloadBytes / 8 : 0;
                int maxEntries = Math.Min(entryCount, 512);
                for (int i = 0; i < maxEntries; i++)
                {
                    int entryOffset = 8 + (i * 8);
                    uint symbol = ReadUInt32(data, entryOffset);
                    uint baseRelocSize = ReadUInt32(data, entryOffset + 4);
                    entries.Add(new DynamicRelocationEntryInfo(symbol, baseRelocSize));
                }

                if (entryCount > maxEntries)
                {
                    issues.Add($"Dynamic relocation metadata entry count truncated to {maxEntries}.");
                }
            }

            return new DynamicRelocationMetadataInfo(
                pointer,
                isMapped,
                pointerSource,
                rva,
                sectionName,
                version,
                size,
                malformed,
                JoinIssues(issues),
                issues.ToArray(),
                entries.ToArray());
        }

        private static ChpeMetadataInfo ParseChpeMetadataBlob(
            ReadOnlySpan<byte> data,
            ulong pointer,
            bool isMapped,
            string pointerSource,
            uint rva,
            string sectionName)
        {
            List<string> issues = new List<string>();
            List<ChpeCodeRangeInfo> ranges = new List<ChpeCodeRangeInfo>();
            uint version = 0;
            uint rangeOffset = 0;
            uint rangeCount = 0;
            bool malformed = false;

            if (data.Length < 12)
            {
                issues.Add("CHPE metadata header is smaller than 12 bytes.");
                malformed = true;
            }
            else
            {
                version = ReadUInt32(data, 0);
                rangeOffset = ReadUInt32(data, 4);
                rangeCount = ReadUInt32(data, 8);

                if (rangeCount > 0)
                {
                    if (rangeOffset < 12 || rangeOffset > data.Length)
                    {
                        issues.Add("CHPE metadata code range table offset is invalid.");
                        malformed = true;
                    }
                    else
                    {
                        int available = data.Length - (int)rangeOffset;
                        ulong needed = (ulong)rangeCount * 8;
                        int canParse = available / 8;
                        int parseCount = (int)Math.Min((ulong)Math.Min(canParse, 256), rangeCount);
                        for (int i = 0; i < parseCount; i++)
                        {
                            int entryOffset = (int)rangeOffset + (i * 8);
                            uint start = ReadUInt32(data, entryOffset);
                            uint end = ReadUInt32(data, entryOffset + 4);
                            ranges.Add(new ChpeCodeRangeInfo(start, end));
                        }

                        if (needed > (ulong)available)
                        {
                            issues.Add("CHPE metadata code range table exceeds readable bounds.");
                            malformed = true;
                        }

                        if (rangeCount > (uint)parseCount)
                        {
                            issues.Add($"CHPE metadata code ranges truncated to {parseCount}.");
                        }
                    }
                }
            }

            return new ChpeMetadataInfo(
                pointer,
                isMapped,
                pointerSource,
                rva,
                sectionName,
                version,
                rangeOffset,
                rangeCount,
                malformed,
                JoinIssues(issues),
                issues.ToArray(),
                ranges.ToArray());
        }

        private static VolatileMetadataInfo ParseVolatileMetadataBlob(
            ReadOnlySpan<byte> data,
            ulong pointer,
            bool isMapped,
            string pointerSource,
            uint rva,
            string sectionName)
        {
            List<string> issues = new List<string>();
            uint size = 0;
            uint version = 0;
            uint accessTableRva = 0;
            uint accessTableSize = 0;
            uint infoRangeTableRva = 0;
            uint infoRangeTableSize = 0;
            bool malformed = false;

            if (data.Length < 24)
            {
                issues.Add("Volatile metadata header is smaller than 24 bytes.");
                malformed = true;
            }
            else
            {
                size = ReadUInt32(data, 0);
                version = ReadUInt32(data, 4);
                accessTableRva = ReadUInt32(data, 8);
                accessTableSize = ReadUInt32(data, 12);
                infoRangeTableRva = ReadUInt32(data, 16);
                infoRangeTableSize = ReadUInt32(data, 20);

                if (size < 24)
                {
                    issues.Add("Volatile metadata size is smaller than the header.");
                    malformed = true;
                }
                else if (size > data.Length)
                {
                    issues.Add("Volatile metadata extends beyond readable bounds.");
                    malformed = true;
                }

                if (accessTableSize > 0 && accessTableRva == 0)
                {
                    issues.Add("Volatile metadata access table has non-zero size but zero RVA.");
                    malformed = true;
                }

                if (infoRangeTableSize > 0 && infoRangeTableRva == 0)
                {
                    issues.Add("Volatile metadata info-range table has non-zero size but zero RVA.");
                    malformed = true;
                }
            }

            return new VolatileMetadataInfo(
                pointer,
                isMapped,
                pointerSource,
                rva,
                sectionName,
                size,
                version,
                accessTableRva,
                accessTableSize,
                infoRangeTableRva,
                infoRangeTableSize,
                malformed,
                JoinIssues(issues),
                issues.ToArray());
        }

        private static string JoinIssues(IReadOnlyList<string> issues)
        {
            if (issues == null || issues.Count == 0)
            {
                return string.Empty;
            }

            return string.Join("; ", issues);
        }

        private SehHandlerTableInfo BuildSehHandlerTableInfo(ulong tableAddress, uint handlerCount, List<IMAGE_SECTION_HEADER> sections)
        {
            if (handlerCount == 0 || tableAddress == 0)
            {
                return null;
            }

            if (!TryGetRvaFromAddress(tableAddress, _imageBase, out uint rva, out string source))
            {
                Warn(ParseIssueCategory.LoadConfig, "SEH handler table address could not be mapped to an RVA.");
                return new SehHandlerTableInfo(tableAddress, handlerCount, false, string.Empty, Array.Empty<uint>(), Array.Empty<SehHandlerEntryInfo>());
            }

            bool mapped = TryGetSectionByRva(sections, rva, out IMAGE_SECTION_HEADER section);
            string sectionName = mapped ? NormalizeSectionName(section.Section) : string.Empty;
            if (!mapped)
            {
                Warn(ParseIssueCategory.LoadConfig, "SEH handler table is not mapped to a section.");
            }

            int maxEntries = (int)Math.Min(handlerCount, 512u);
            uint[] handlers = Array.Empty<uint>();
            List<SehHandlerEntryInfo> entries = new List<SehHandlerEntryInfo>();
            if (TryGetFileOffset(sections, rva, handlerCount * 4u, out long fileOffset) &&
                TrySetPosition(fileOffset, maxEntries * 4))
            {
                handlers = new uint[maxEntries];
                for (int i = 0; i < maxEntries; i++)
                {
                    handlers[i] = PEFile.ReadUInt32();
                }

                foreach (uint handlerRva in handlers)
                {
                    string handlerSection = string.Empty;
                    if (handlerRva != 0 && TryGetSectionByRva(sections, handlerRva, out IMAGE_SECTION_HEADER handlerSectionHeader))
                    {
                        handlerSection = NormalizeSectionName(handlerSectionHeader.Section);
                    }

                    string symbolName = ResolveExportNameByRva(handlerRva);
                    string sourceName = string.IsNullOrWhiteSpace(symbolName) ? string.Empty : "Export";
                    entries.Add(new SehHandlerEntryInfo(handlerRva, handlerSection, symbolName, sourceName));
                }

                if (handlerCount > maxEntries)
                {
                    Warn(ParseIssueCategory.LoadConfig, $"SEH handler table has {handlerCount} entries; truncated to {maxEntries}.");
                }
            }
            else
            {
                Warn(ParseIssueCategory.LoadConfig, "SEH handler table could not be read from file.");
            }

            return new SehHandlerTableInfo(tableAddress, handlerCount, mapped, sectionName, handlers, entries.ToArray());
        }

        private static LoadConfigVersionInfo BuildLoadConfigVersionInfo(
            uint declaredSize,
            uint limitBytes,
            uint parsedBytes,
            bool hasCodeIntegrity,
            bool hasGuardIat,
            bool hasDynamicReloc,
            bool hasChpe,
            bool hasGuardRf,
            bool hasHotPatch,
            bool hasEnclave,
            bool hasVolatileMetadata,
            bool hasEhContinuation,
            bool hasXfg,
            ReadOnlySpan<byte> span)
        {
            bool isTruncated = declaredSize > limitBytes;
            if (parsedBytes > limitBytes)
            {
                parsedBytes = limitBytes;
            }

            uint trailingBytes = limitBytes > parsedBytes ? limitBytes - parsedBytes : 0;
            string trailingHash = string.Empty;
            string trailingPreview = string.Empty;
            if (trailingBytes > 0 && parsedBytes < span.Length)
            {
                ReadOnlySpan<byte> trailing = span.Slice((int)parsedBytes, (int)Math.Min(trailingBytes, (uint)(span.Length - (int)parsedBytes)));
                trailingPreview = BuildHexPreview(trailing, 64);
                trailingHash = ToHex(SHA256.HashData(trailing));
            }

            List<string> groups = new List<string> { "Base" };
            if (hasCodeIntegrity)
            {
                groups.Add("CodeIntegrity");
            }
            if (hasGuardIat)
            {
                groups.Add("GuardIAT");
            }
            if (hasDynamicReloc || hasChpe)
            {
                groups.Add("DynamicReloc/CHPE");
            }
            if (hasGuardRf)
            {
                groups.Add("GuardRF");
            }
            if (hasHotPatch)
            {
                groups.Add("HotPatch");
            }
            if (hasEnclave)
            {
                groups.Add("Enclave");
            }
            if (hasVolatileMetadata)
            {
                groups.Add("VolatileMetadata");
            }
            if (hasEhContinuation)
            {
                groups.Add("EHContinuation");
            }
            if (hasXfg)
            {
                groups.Add("XFG");
            }

            string versionHint = "pre-Win8";
            if (hasDynamicReloc || hasChpe)
            {
                versionHint = "Win8+";
            }
            if (hasGuardRf || hasHotPatch)
            {
                versionHint = "Win8.1+";
            }
            if (hasEnclave || hasVolatileMetadata)
            {
                versionHint = "Win10+";
            }
            if (hasXfg)
            {
                versionHint = "Win10+ (XFG)";
            }
            if (trailingBytes > 0)
            {
                versionHint = hasXfg || hasEnclave || hasVolatileMetadata
                    ? "Win11+ (extra fields)"
                    : "Win11/Preview (trailing bytes)";
            }
            if (isTruncated)
            {
                versionHint = versionHint + " (truncated)";
            }

            return new LoadConfigVersionInfo(
                declaredSize,
                limitBytes,
                parsedBytes,
                trailingBytes,
                isTruncated,
                versionHint,
                groups.ToArray(),
                trailingHash,
                trailingPreview);
        }

        private GuardRvaTableInfo BuildGuardRvaTableInfo(string name, ulong tablePointer, ulong count, uint entrySize, List<IMAGE_SECTION_HEADER> sections)
        {
            if (tablePointer == 0 || count == 0 || entrySize == 0)
            {
                return null;
            }

            if (_imageBase == 0 || !TryGetRvaFromAddress(tablePointer, _imageBase, out uint rva, out _))
            {
                Warn(ParseIssueCategory.LoadConfig, $"{name} pointer could not be mapped to an RVA.");
                return new GuardRvaTableInfo(name, tablePointer, count, entrySize, false, string.Empty, false, false, Array.Empty<uint>());
            }

            bool mapped = TryGetSectionByRva(sections, rva, out IMAGE_SECTION_HEADER section);
            string sectionName = mapped ? NormalizeSectionName(section.Section) : string.Empty;
            if (!mapped)
            {
                Warn(ParseIssueCategory.LoadConfig, $"{name} RVA is not mapped to a section.");
            }

            bool sizeFits = false;
            ulong totalSize = 0;
            try
            {
                totalSize = checked(count * entrySize);
                sizeFits = totalSize <= uint.MaxValue;
            }
            catch (OverflowException)
            {
                sizeFits = false;
            }

            int maxEntries = (int)Math.Min(count, 512u);
            uint[] entries = Array.Empty<uint>();
            bool truncated = count > (ulong)maxEntries;

            int sampleSize = maxEntries * (int)entrySize;
            if (sizeFits && TryGetFileOffset(sections, rva, (uint)totalSize, out long fileOffset) &&
                TrySetPosition(fileOffset, sampleSize))
            {
                entries = new uint[maxEntries];
                for (int i = 0; i < maxEntries; i++)
                {
                    entries[i] = PEFile.ReadUInt32();
                }
            }
            else if (TryGetFileOffset(sections, rva, (uint)sampleSize, out long fallbackOffset) &&
                     TrySetPosition(fallbackOffset, sampleSize))
            {
                entries = new uint[maxEntries];
                for (int i = 0; i < maxEntries; i++)
                {
                    entries[i] = PEFile.ReadUInt32();
                }
                sizeFits = false;
            }
            else
            {
                if (!sizeFits)
                {
                    Warn(ParseIssueCategory.LoadConfig, $"{name} size exceeds supported limits.");
                }
                else
                {
                    Warn(ParseIssueCategory.LoadConfig, $"{name} could not be read from file.");
                }
            }

            return new GuardRvaTableInfo(name, tablePointer, count, entrySize, mapped, sectionName, sizeFits, truncated, entries);
        }

        private static ulong ReadPointer(ReadOnlySpan<byte> span, ref int offset, bool isPe32Plus)
        {
            ulong value = isPe32Plus ? ReadUInt64(span, offset) : ReadUInt32(span, offset);
            offset += isPe32Plus ? 8 : 4;
            return value;
        }

        private static bool TryAdvance(ref int offset, int limit, int bytes)
        {
            if (offset + bytes > limit)
            {
                return false;
            }

            offset += bytes;
            return true;
        }

        private static bool TryReadPointerValue(ReadOnlySpan<byte> span, ref int offset, int limit, bool isPe32Plus, out ulong value)
        {
            value = 0;
            int bytes = isPe32Plus ? 8 : 4;
            if (offset + bytes > limit)
            {
                return false;
            }

            value = isPe32Plus ? ReadUInt64(span, offset) : ReadUInt32(span, offset);
            offset += bytes;
            return true;
        }

        private static bool TryReadUInt32Value(ReadOnlySpan<byte> span, ref int offset, int limit, out uint value)
        {
            value = 0;
            if (offset + 4 > limit)
            {
                return false;
            }

            value = ReadUInt32(span, offset);
            offset += 4;
            return true;
        }

        private static bool TryReadUInt16Value(ReadOnlySpan<byte> span, ref int offset, int limit, out ushort value)
        {
            value = 0;
            if (offset + 2 > limit)
            {
                return false;
            }

            value = ReadUInt16(span, offset);
            offset += 2;
            return true;
        }

        private static bool TryReadCodeIntegrity(ReadOnlySpan<byte> span, ref int offset, int limit, out LoadConfigCodeIntegrityInfo info)
        {
            info = null;
            if (offset + 12 > limit)
            {
                return false;
            }

            ushort flags = ReadUInt16(span, offset);
            ushort catalog = ReadUInt16(span, offset + 2);
            uint catalogOffset = ReadUInt32(span, offset + 4);
            uint reserved = ReadUInt32(span, offset + 8);
            offset += 12;
            info = new LoadConfigCodeIntegrityInfo(flags, catalog, catalogOffset, reserved, DecodeBitFlags16(flags));
            return true;
        }

        private EnclaveConfigurationInfo TryReadEnclaveConfiguration(ulong enclavePointer, List<IMAGE_SECTION_HEADER> sections)
        {
            if (enclavePointer == 0)
            {
                return null;
            }

            if (_imageBase == 0 || !TryGetRvaFromAddress(enclavePointer, _imageBase, out uint rva, out _))
            {
                Warn(ParseIssueCategory.LoadConfig, "Enclave configuration pointer could not be mapped to an RVA.");
                return new EnclaveConfigurationInfo(0, 0, 0, 0, 0, 0, string.Empty, string.Empty, 0, 0, 0, 0, 0, string.Empty, false, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<EnclaveImportInfo>());
            }

            bool mapped = TryGetSectionByRva(sections, rva, out IMAGE_SECTION_HEADER section);
            string sectionName = mapped ? NormalizeSectionName(section.Section) : string.Empty;
            if (!TryGetFileOffset(sections, rva, out long fileOffset))
            {
                Warn(ParseIssueCategory.LoadConfig, "Enclave configuration RVA not mapped to a file offset.");
                return new EnclaveConfigurationInfo(0, 0, 0, 0, 0, 0, string.Empty, string.Empty, 0, 0, 0, 0, 0, sectionName, mapped, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<EnclaveImportInfo>());
            }

            if (!TrySetPosition(fileOffset, 4))
            {
                Warn(ParseIssueCategory.LoadConfig, "Enclave configuration header outside file bounds.");
                return new EnclaveConfigurationInfo(0, 0, 0, 0, 0, 0, string.Empty, string.Empty, 0, 0, 0, 0, 0, sectionName, mapped, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<EnclaveImportInfo>());
            }

            byte[] headerBytes = new byte[4];
            ReadExactly(PEFileStream, headerBytes, 0, headerBytes.Length);
            uint size = BitConverter.ToUInt32(headerBytes, 0);
            int readSize = size > 0 && size <= 256 ? (int)size : 76;
            if (!TrySetPosition(fileOffset, readSize))
            {
                Warn(ParseIssueCategory.LoadConfig, "Enclave configuration size exceeds file bounds.");
                return new EnclaveConfigurationInfo(size, 0, 0, 0, 0, 0, string.Empty, string.Empty, 0, 0, 0, 0, 0, sectionName, mapped, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<EnclaveImportInfo>());
            }

            byte[] buffer = new byte[readSize];
            ReadExactly(PEFileStream, buffer, 0, buffer.Length);
            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(buffer);

            uint minimumRequiredConfigSize = ReadUInt32Safe(span, 4);
            uint policyFlags = ReadUInt32Safe(span, 8);
            uint numberOfImports = ReadUInt32Safe(span, 12);
            uint importListRva = ReadUInt32Safe(span, 16);
            uint importEntrySize = ReadUInt32Safe(span, 20);
            string familyId = ReadBytesHexSafe(span, 24, 16);
            string imageId = ReadBytesHexSafe(span, 40, 16);
            uint imageVersion = ReadUInt32Safe(span, 56);
            uint securityVersion = ReadUInt32Safe(span, 60);
            uint enclaveSize = ReadUInt32Safe(span, 64);
            uint numberOfThreads = ReadUInt32Safe(span, 68);
            uint enclaveFlags = ReadUInt32Safe(span, 72);
            EnclaveImportInfo[] imports = ReadEnclaveImports(sections, numberOfImports, importListRva, importEntrySize);

            return new EnclaveConfigurationInfo(
                size,
                minimumRequiredConfigSize,
                policyFlags,
                numberOfImports,
                importListRva,
                importEntrySize,
                familyId,
                imageId,
                imageVersion,
                securityVersion,
                enclaveSize,
                numberOfThreads,
                enclaveFlags,
                sectionName,
                mapped,
                DecodeBitFlags(policyFlags),
                DecodeBitFlags(enclaveFlags),
                imports);
        }

        private EnclaveImportInfo[] ReadEnclaveImports(List<IMAGE_SECTION_HEADER> sections, uint numberOfImports, uint importListRva, uint importEntrySize)
        {
            if (numberOfImports == 0 || importListRva == 0 || importEntrySize == 0 || PEFileStream == null)
            {
                return Array.Empty<EnclaveImportInfo>();
            }

            if (importEntrySize > int.MaxValue)
            {
                Warn(ParseIssueCategory.LoadConfig, "Enclave import entry size exceeds supported limits.");
                return Array.Empty<EnclaveImportInfo>();
            }

            if (!TryGetFileOffset(sections, importListRva, out long listOffset))
            {
                Warn(ParseIssueCategory.LoadConfig, "Enclave import list RVA not mapped to a file offset.");
                return Array.Empty<EnclaveImportInfo>();
            }

            int entrySize = (int)importEntrySize;
            if (entrySize <= 0)
            {
                return Array.Empty<EnclaveImportInfo>();
            }
            int maxEntries = (int)Math.Min(numberOfImports, 128u);
            long totalSize = (long)entrySize * maxEntries;
            if (totalSize > int.MaxValue)
            {
                Warn(ParseIssueCategory.LoadConfig, "Enclave import list size exceeds supported limits.");
                return Array.Empty<EnclaveImportInfo>();
            }

            long originalPosition = PEFileStream.Position;
            try
            {
                if (!TrySetPosition(listOffset, (int)totalSize))
                {
                    Warn(ParseIssueCategory.LoadConfig, "Enclave import list outside file bounds.");
                    return Array.Empty<EnclaveImportInfo>();
                }

                List<EnclaveImportInfo> imports = new List<EnclaveImportInfo>();
                byte[] buffer = new byte[entrySize];
                for (int i = 0; i < maxEntries; i++)
                {
                    ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                    EnclaveImportInfo info = TryParseEnclaveImportEntry(new ReadOnlySpan<byte>(buffer), i, sections);
                    if (info != null)
                    {
                        imports.Add(info);
                    }
                }

                if (numberOfImports > (uint)maxEntries)
                {
                    Warn(ParseIssueCategory.LoadConfig, $"Enclave import list has {numberOfImports} entries; truncated to {maxEntries}.");
                }

                if (entrySize < 80)
                {
                    Warn(ParseIssueCategory.LoadConfig, "Enclave import entry size is smaller than expected.");
                }

                return imports.ToArray();
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private EnclaveImportInfo TryParseEnclaveImportEntry(ReadOnlySpan<byte> span, int index, List<IMAGE_SECTION_HEADER> sections)
        {
            if (span.Length < 8)
            {
                return null;
            }

            uint matchType = ReadUInt32Safe(span, 0);
            uint minimumSecurityVersion = ReadUInt32Safe(span, 4);
            string uniqueOrAuthorId = ReadBytesHexSafe(span, 8, 32);
            string familyId = ReadBytesHexSafe(span, 40, 16);
            string imageId = ReadBytesHexSafe(span, 56, 16);
            uint importNameRva = ReadUInt32Safe(span, 72);
            uint reserved = ReadUInt32Safe(span, 76);

            string importName = string.Empty;
            if (importNameRva != 0 && TryGetFileOffset(sections, importNameRva, out long nameOffset))
            {
                if (!TryReadNullTerminatedString(nameOffset, out string value))
                {
                    Warn(ParseIssueCategory.LoadConfig, "Enclave import name could not be read.");
                }
                else
                {
                    importName = value;
                }
            }

            return new EnclaveImportInfo(
                index,
                matchType,
                GetEnclaveImportMatchTypeName(matchType),
                minimumSecurityVersion,
                uniqueOrAuthorId,
                familyId,
                imageId,
                importNameRva,
                importName,
                reserved);
        }

        private static string GetEnclaveImportMatchTypeName(uint matchType)
        {
            switch (matchType)
            {
                case 0: return "None";
                case 1: return "UniqueId";
                case 2: return "AuthorId";
                case 3: return "FamilyId";
                case 4: return "ImageId";
                default: return "Unknown";
            }
        }

        private static uint ReadUInt32Safe(ReadOnlySpan<byte> span, int offset)
        {
            if (offset < 0 || offset + 4 > span.Length)
            {
                return 0;
            }

            return ReadUInt32(span, offset);
        }

        private static string ReadBytesHexSafe(ReadOnlySpan<byte> span, int offset, int length)
        {
            if (offset < 0 || length <= 0 || offset + length > span.Length)
            {
                return string.Empty;
            }

            byte[] buffer = span.Slice(offset, length).ToArray();
            return ToHex(buffer);
        }

        private static string[] DecodeBitFlags16(ushort flags)
        {
            if (flags == 0)
            {
                return Array.Empty<string>();
            }

            List<string> names = new List<string>();
            for (int bit = 0; bit < 16; bit++)
            {
                ushort mask = (ushort)(1 << bit);
                if ((flags & mask) != 0)
                {
                    names.Add("0x" + mask.ToString("X4", CultureInfo.InvariantCulture));
                }
            }

            return names.ToArray();
        }

        private static bool TryVaToRva(ulong va, ulong imageBase, out uint rva)
        {
            rva = 0;
            if (va == 0 || va < imageBase)
            {
                return false;
            }

            ulong diff = va - imageBase;
            if (diff > uint.MaxValue)
            {
                return false;
            }

            rva = (uint)diff;
            return true;
        }

        private bool TryGetFileOffsetFromVa(List<IMAGE_SECTION_HEADER> sections, ulong va, ulong imageBase, out long fileOffset)
        {
            fileOffset = -1;
            if (!TryVaToRva(va, imageBase, out uint rva))
            {
                return false;
            }

            return TryGetFileOffset(sections, rva, out fileOffset);
        }

        private static bool TryGetRvaFromAddress(ulong address, ulong imageBase, out uint rva, out string source)
        {
            rva = 0;
            source = string.Empty;
            if (address == 0)
            {
                return false;
            }

            if (TryVaToRva(address, imageBase, out rva))
            {
                source = "VA";
                return true;
            }

            if (address <= uint.MaxValue)
            {
                rva = (uint)address;
                source = "RVA";
                return true;
            }

            return false;
        }

        private static bool TryComputeRvaFromPointer(ulong value, ulong imageBase, uint sizeOfImage, out uint rva, out string kind)
        {
            rva = 0;
            kind = string.Empty;
            if (value == 0 || sizeOfImage == 0)
            {
                return false;
            }

            if (value < sizeOfImage)
            {
                rva = (uint)value;
                kind = "RVA";
                return true;
            }

            if (imageBase != 0 && value >= imageBase)
            {
                ulong diff = value - imageBase;
                if (diff < sizeOfImage)
                {
                    rva = (uint)diff;
                    kind = "VA";
                    return true;
                }
            }

            return false;
        }

        private static string AppendNote(string notes, string addition)
        {
            if (string.IsNullOrWhiteSpace(addition))
            {
                return notes ?? string.Empty;
            }

            if (string.IsNullOrWhiteSpace(notes))
            {
                return addition;
            }

            return notes + "; " + addition;
        }

        private GuardTableSanityInfo BuildGuardTableSanity(
            string name,
            ulong pointer,
            ulong count,
            bool hasCount,
            List<IMAGE_SECTION_HEADER> sections,
            uint minEntrySize,
            bool requireExecutable)
        {
            bool pointerPresent = pointer != 0;
            bool countPresent = hasCount && count != 0;
            bool mapped = false;
            string sectionName = string.Empty;
            uint sectionRva = 0;
            uint sectionSize = 0;
            uint estimatedSize = 0;
            bool sizeFits = true;
            string notes = string.Empty;

            if (!pointerPresent)
            {
                if (countPresent)
                {
                    notes = "count present without pointer";
                }

                return new GuardTableSanityInfo(
                    name,
                    pointerPresent,
                    countPresent,
                    mapped,
                    sectionName,
                    sectionRva,
                    sectionSize,
                    estimatedSize,
                    sizeFits,
                    notes);
            }

            if (!TryGetRvaFromAddress(pointer, _imageBase, out uint rva, out string source))
            {
                notes = AppendNote(notes, "address not mappable");
                return new GuardTableSanityInfo(
                    name,
                    pointerPresent,
                    countPresent,
                    mapped,
                    sectionName,
                    sectionRva,
                    sectionSize,
                    estimatedSize,
                    sizeFits,
                    notes);
            }

            notes = AppendNote(notes, "source=" + source);

            if (TryGetSectionByRva(sections, rva, out IMAGE_SECTION_HEADER section))
            {
                mapped = true;
                sectionName = NormalizeSectionName(section.Section);
                sectionRva = section.VirtualAddress;
                sectionSize = Math.Max(section.VirtualSize, section.SizeOfRawData);
                if (countPresent && minEntrySize > 0)
                {
                    ulong estimated = count * minEntrySize;
                    estimatedSize = estimated > uint.MaxValue ? uint.MaxValue : (uint)estimated;
                    ulong end = (ulong)rva + estimated;
                    ulong sectionEnd = (ulong)section.VirtualAddress + sectionSize;
                    sizeFits = end <= sectionEnd;
                }

                if (requireExecutable &&
                    (section.Characteristics & SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) == 0)
                {
                    notes = AppendNote(notes, "non-executable section");
                }
            }
            else
            {
                notes = AppendNote(notes, "address not mapped to section");
            }

            if (countPresent && minEntrySize > 0)
            {
                notes = AppendNote(notes, $"assumed entry size {minEntrySize} bytes");
            }

            return new GuardTableSanityInfo(
                name,
                pointerPresent,
                countPresent,
                mapped,
                sectionName,
                sectionRva,
                sectionSize,
                estimatedSize,
                sizeFits,
                notes);
        }

        private bool TryResolveExportName(uint rva, out string name)
        {
            name = string.Empty;
            if (rva == 0 || _exportEntries.Count == 0)
            {
                return false;
            }

            foreach (ExportEntry entry in _exportEntries)
            {
                if (entry == null || entry.IsForwarder || entry.AddressRva != rva)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(entry.Name))
                {
                    name = entry.Name;
                    return true;
                }

                name = "#" + entry.Ordinal.ToString(CultureInfo.InvariantCulture);
                return true;
            }

            return false;
        }

        private string ResolveExportNameByRva(uint rva)
        {
            return TryResolveExportName(rva, out string name) ? name : string.Empty;
        }

        private static int DecodeTlsAlignmentBytes(uint characteristics)
        {
            uint alignment = (characteristics >> 20) & 0xF;
            if (alignment == 0 || alignment > 0xE)
            {
                return 0;
            }

            int shift = (int)alignment - 1;
            return shift >= 0 && shift < 31 ? 1 << shift : 0;
        }

        private static bool TryParseClrMetadata(byte[] buffer, int length, IMAGE_COR20_HEADER header, out ClrMetadataInfo info)
        {
            info = null;
            if (buffer == null || length < 16)
            {
                return false;
            }

            if (length > buffer.Length)
            {
                length = buffer.Length;
            }

            ReadOnlySpan<byte> metadataSpan = new ReadOnlySpan<byte>(buffer, 0, length);

            uint signature = ReadUInt32(metadataSpan, 0);
            if (signature != 0x424A5342)
            {
                return false;
            }

            ushort majorVersion = ReadUInt16(metadataSpan, 4);
            ushort minorVersion = ReadUInt16(metadataSpan, 6);
            uint versionLength = ReadUInt32(metadataSpan, 12);
            int versionOffset = 16;

            if (versionOffset + versionLength > metadataSpan.Length)
            {
                return false;
            }

            string versionString = ReadAsciiString(buffer, versionOffset, (int)versionLength);
            int cursor = Align4(versionOffset + (int)versionLength);

            if (cursor + 4 > metadataSpan.Length)
            {
                return false;
            }

            ushort flags = ReadUInt16(metadataSpan, cursor);
            ushort streams = ReadUInt16(metadataSpan, cursor + 2);
            cursor += 4;

            List<ClrStreamInfo> streamInfos = new List<ClrStreamInfo>();
            for (int i = 0; i < streams; i++)
            {
                if (cursor + 8 > metadataSpan.Length)
                {
                    return false;
                }

                uint offset = ReadUInt32(metadataSpan, cursor);
                uint size = ReadUInt32(metadataSpan, cursor + 4);
                cursor += 8;

                string name = ReadNullTerminatedAscii(metadataSpan, cursor, out int nameBytes);
                cursor = Align4(cursor + nameBytes);

                streamInfos.Add(new ClrStreamInfo(name, offset, size));
            }

            List<string> validationMessages = new List<string>();
            HashSet<string> streamNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool isValid = true;
            foreach (ClrStreamInfo stream in streamInfos)
            {
                if (!streamNames.Add(stream.Name ?? string.Empty))
                {
                    validationMessages.Add($"Duplicate metadata stream name: {stream.Name}");
                    isValid = false;
                }

                ulong end = (ulong)stream.Offset + (ulong)stream.Size;
                if (end > (ulong)length)
                {
                    validationMessages.Add($"Metadata stream {stream.Name} exceeds metadata bounds.");
                    isValid = false;
                }
            }

            string assemblyName = string.Empty;
            string assemblyVersion = string.Empty;
            string mvid = string.Empty;
            string targetFramework = string.Empty;
            ClrAssemblyReferenceInfo[] assemblyReferences = Array.Empty<ClrAssemblyReferenceInfo>();
            string[] moduleReferences = Array.Empty<string>();
            ManagedResourceInfo[] managedResources = Array.Empty<ManagedResourceInfo>();
            string[] assemblyAttributes = Array.Empty<string>();
            string[] moduleAttributes = Array.Empty<string>();
            MetadataTableCountInfo[] metadataTableCounts = Array.Empty<MetadataTableCountInfo>();
            int moduleCount = 0;
            int typeDefCount = 0;
            int typeRefCount = 0;
            int methodDefCount = 0;
            int fieldDefCount = 0;
            int propertyDefCount = 0;
            int eventDefCount = 0;
            bool hasDebuggable = false;
            string debuggableModes = string.Empty;
            TryParseMetadataDetails(
                buffer,
                length,
                out assemblyName,
                out assemblyVersion,
                out mvid,
                out targetFramework,
                out assemblyReferences,
                out moduleReferences,
                out managedResources,
                out assemblyAttributes,
                out moduleAttributes,
                out metadataTableCounts,
                out moduleCount,
                out typeDefCount,
                out typeRefCount,
                out methodDefCount,
                out fieldDefCount,
                out propertyDefCount,
                out eventDefCount,
                out hasDebuggable,
                out debuggableModes);

            info = new ClrMetadataInfo(
                header.MajorRuntimeVersion,
                header.MinorRuntimeVersion,
                header.Flags,
                header.EntryPointToken,
                versionString,
                streamInfos.ToArray(),
                assemblyName,
                assemblyVersion,
                mvid,
                targetFramework,
                assemblyReferences,
                moduleReferences,
                managedResources,
                assemblyAttributes,
                moduleAttributes,
                metadataTableCounts,
                Array.Empty<ClrTokenReferenceInfo>(),
                null,
                null,
                (header.Flags & 0x00000001) != 0,
                (header.Flags & 0x00000002) != 0,
                (header.Flags & 0x00020000) != 0,
                (header.Flags & 0x00000008) != 0,
                moduleCount,
                typeDefCount,
                typeRefCount,
                methodDefCount,
                fieldDefCount,
                propertyDefCount,
                eventDefCount,
                hasDebuggable,
                debuggableModes,
                isValid,
                validationMessages.ToArray());

            return true;
        }

        private void ParseReadyToRunHeader(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections)
        {
            if (!TryGetFileOffset(sections, directory.VirtualAddress, out long r2rOffset))
            {
                Warn(ParseIssueCategory.CLR, "ReadyToRun header RVA not mapped to a section.");
                return;
            }

            if (!TryGetIntSize(directory.Size, out int r2rSize) || r2rSize < 16)
            {
                Warn(ParseIssueCategory.CLR, "ReadyToRun header size is invalid.");
                return;
            }

            if (!TrySetPosition(r2rOffset, r2rSize))
            {
                Warn(ParseIssueCategory.CLR, "ReadyToRun header offset outside file bounds.");
                return;
            }

            uint signature = PEFile.ReadUInt32();
            ushort major = PEFile.ReadUInt16();
            ushort minor = PEFile.ReadUInt16();
            uint flags = PEFile.ReadUInt32();
            uint sectionCount = PEFile.ReadUInt32();

            uint cappedSectionCount = sectionCount > 4096 ? 4096u : sectionCount;
            int sectionTableSize = (int)cappedSectionCount * 12;
            int maxSectionTableSize = r2rSize - 16;
            if (sectionTableSize < 0 || sectionTableSize > maxSectionTableSize)
            {
                if (maxSectionTableSize < 0)
                {
                    return;
                }

                sectionCount = (uint)Math.Max(0, maxSectionTableSize / 12);
            }
            else
            {
                sectionCount = cappedSectionCount;
            }

            List<ReadyToRunSectionInfo> sectionsInfo = new List<ReadyToRunSectionInfo>();
            for (int i = 0; i < sectionCount; i++)
            {
                if (!TrySetPosition(r2rOffset + 16 + (i * 12L), 12))
                {
                    break;
                }

                uint type = PEFile.ReadUInt32();
                uint rva = PEFile.ReadUInt32();
                uint size = PEFile.ReadUInt32();
                string name = GetReadyToRunSectionName(type);
                sectionsInfo.Add(new ReadyToRunSectionInfo(type, rva, size, name));
            }

            string signatureText = GetSignatureText(signature);
            int entryPointSectionCount = sectionsInfo.Count(section => IsReadyToRunEntryPointSection(section.Type));
            uint entryPointTotalSize = 0;
            foreach (ReadyToRunSectionInfo section in sectionsInfo)
            {
                if (IsReadyToRunEntryPointSection(section.Type))
                {
                    entryPointTotalSize += section.Size;
                }
            }

            _readyToRun = new ReadyToRunInfo(
                signature,
                signatureText,
                major,
                minor,
                flags,
                sectionsInfo.Count,
                entryPointSectionCount,
                entryPointTotalSize,
                sectionsInfo.ToArray());
        }

        private void ParseClrDirectory(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections)
        {
            _clrMetadata = null;
            _strongNameSignature = null;
            _strongNameValidation = null;
            if (!TryGetFileOffset(sections, directory.VirtualAddress, out long clrOffset))
            {
                Warn(ParseIssueCategory.CLR, "CLR header RVA not mapped to a section.");
                return;
            }

            byte[] buffer = new byte[Marshal.SizeOf(typeof(IMAGE_COR20_HEADER))];
            if (!TrySetPosition(clrOffset, buffer.Length))
            {
                Warn(ParseIssueCategory.CLR, "CLR header offset outside file bounds.");
                return;
            }

            ReadExactly(PEFileStream, buffer, 0, buffer.Length);
            IMAGE_COR20_HEADER clrHeader = ByteArrayToStructure<IMAGE_COR20_HEADER>(buffer);
            uint expectedClrSize = (uint)Marshal.SizeOf(typeof(IMAGE_COR20_HEADER));
            bool strongNameSignedFlag = (clrHeader.Flags & 0x00000008) != 0;
            if (clrHeader.cb < expectedClrSize)
            {
                Warn(ParseIssueCategory.CLR, "CLR header size is smaller than expected.");
            }
            else if (directory.Size > 0 && clrHeader.cb > directory.Size)
            {
                Warn(ParseIssueCategory.CLR, "CLR header size exceeds directory size.");
            }
            if (clrHeader.MetaData.Size == 0)
            {
                Warn(ParseIssueCategory.CLR, "CLR header does not reference metadata.");
                return;
            }

            if (clrHeader.StrongNameSignature.Size > 0 &&
                clrHeader.StrongNameSignature.VirtualAddress != 0)
            {
                if (TryGetFileOffset(sections, clrHeader.StrongNameSignature.VirtualAddress, out long snOffset) &&
                    TryGetIntSize(clrHeader.StrongNameSignature.Size, out int snSize) &&
                    snSize > 0 &&
                    TrySetPosition(snOffset, snSize))
                {
                    byte[] snData = new byte[snSize];
                    ReadExactly(PEFileStream, snData, 0, snData.Length);
                    _strongNameSignature = new StrongNameSignatureInfo(
                        clrHeader.StrongNameSignature.VirtualAddress,
                        clrHeader.StrongNameSignature.Size,
                        snData);
                }
                else
                {
                    Warn(ParseIssueCategory.CLR, "Strong name signature could not be read.");
                }
            }
            else if (clrHeader.StrongNameSignature.Size > 0)
            {
                Warn(ParseIssueCategory.CLR, "Strong name signature size is set but RVA is zero.");
            }

            List<string> strongNameIssues = new List<string>();
            bool hasStrongName = _strongNameSignature != null && _strongNameSignature.Data.Length > 0;
            uint strongNameRva = clrHeader.StrongNameSignature.VirtualAddress;
            uint strongNameSize = clrHeader.StrongNameSignature.Size;
            int strongNameDataSize = hasStrongName ? _strongNameSignature.Data.Length : 0;
            bool strongNameSizeMatches = strongNameSize == 0
                ? strongNameDataSize == 0
                : strongNameDataSize == strongNameSize;

            if (strongNameSignedFlag && !hasStrongName)
            {
                string message = "StrongNameSigned flag is set but signature data is missing.";
                Warn(ParseIssueCategory.CLR, message);
                strongNameIssues.Add(message);
            }
            else if (!strongNameSignedFlag && hasStrongName)
            {
                string message = "Strong name signature data is present but StrongNameSigned flag is not set.";
                Warn(ParseIssueCategory.CLR, message);
                strongNameIssues.Add(message);
            }

            if (hasStrongName && !strongNameSizeMatches)
            {
                string message = "Strong name signature size does not match data length.";
                Warn(ParseIssueCategory.CLR, message);
                strongNameIssues.Add(message);
            }

            if (strongNameSize > 0 && strongNameRva == 0)
            {
                strongNameIssues.Add("Strong name signature size is set but RVA is zero.");
            }

            _strongNameValidation = new StrongNameValidationInfo(
                strongNameSignedFlag,
                hasStrongName,
                strongNameRva,
                strongNameSize,
                strongNameDataSize,
                strongNameSizeMatches,
                strongNameIssues.ToArray());

            if (clrHeader.ManagedNativeHeader.Size > 0 &&
                clrHeader.ManagedNativeHeader.VirtualAddress != 0)
            {
                ParseReadyToRunHeader(clrHeader.ManagedNativeHeader, sections);
            }
            else
            {
                _readyToRun = null;
            }

            if (!TryGetIntSize(clrHeader.MetaData.Size, out int metadataSize))
            {
                Warn(ParseIssueCategory.Metadata, "Metadata size exceeds supported limits.");
                return;
            }

            if (!TryGetFileOffset(sections, clrHeader.MetaData.VirtualAddress, out long metadataOffset))
            {
                Warn(ParseIssueCategory.Metadata, "Metadata RVA not mapped to a section.");
                return;
            }

            if (!TrySetPosition(metadataOffset, metadataSize))
            {
                Warn(ParseIssueCategory.Metadata, "Metadata offset outside file bounds.");
                return;
            }

            byte[] metadataBuffer = ArrayPool<byte>.Shared.Rent(metadataSize);
            try
            {
                ReadExactly(PEFileStream, metadataBuffer, 0, metadataSize);
                if (!TryParseClrMetadata(metadataBuffer, metadataSize, clrHeader, out ClrMetadataInfo metadataInfo))
                {
                    Warn(ParseIssueCategory.Metadata, "Failed to parse CLR metadata.");
                    return;
                }

                _clrMetadata = metadataInfo;
                if (metadataInfo.ValidationMessages != null && metadataInfo.ValidationMessages.Length > 0)
                {
                    int count = Math.Min(metadataInfo.ValidationMessages.Length, 5);
                    for (int i = 0; i < count; i++)
                    {
                        Warn(ParseIssueCategory.Metadata, metadataInfo.ValidationMessages[i]);
                    }
                }
                if (TryBuildClrMetadataDeepDive(metadataBuffer, metadataSize, sections, out ClrTokenReferenceInfo[] tokenRefs, out ClrMethodBodySummaryInfo methodSummary, out ClrSignatureDecodeSummaryInfo signatureSummary))
                {
                    _clrMetadata = CloneClrMetadataWithDeepDive(_clrMetadata, tokenRefs, methodSummary, signatureSummary);
                }
                TryPopulateManagedResourceSizes(clrHeader, sections);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(metadataBuffer);
            }
        }

        private static string GetSignatureText(uint signature)
        {
            byte[] bytes = BitConverter.GetBytes(signature);
            string text = Encoding.ASCII.GetString(bytes);
            return text.TrimEnd('\0', ' ');
        }

        private static string GetReadyToRunSectionName(uint type)
        {
            switch (type)
            {
                case 0x00000001:
                    return "RuntimeFunctions";
                case 0x00000002:
                    return "ExceptionInfo";
                case 0x00000003:
                    return "DebugInfo";
                case 0x00000004:
                    return "DelayLoadMethodCallThunks";
                case 0x00000005:
                    return "AvailableTypes";
                case 0x00000006:
                    return "InstanceMethodEntryPoints";
                case 0x00000007:
                    return "AvailableMethods";
                case 0x00000008:
                    return "ManifestMetadata";
                case 0x00000009:
                    return "AttributePresence";
                case 0x0000000A:
                    return "InliningInfo";
                case 0x0000000B:
                    return "ProfileDataInfo";
                case 0x0000000C:
                    return "ManifestResource";
                default:
                    return string.Empty;
            }
        }

        private static bool IsReadyToRunEntryPointSection(uint type)
        {
            return type == 0x00000006;
        }

        private static bool TryParseMetadataDetails(
            byte[] metadata,
            int length,
            out string assemblyName,
            out string assemblyVersion,
            out string mvid,
            out string targetFramework,
            out ClrAssemblyReferenceInfo[] assemblyReferences,
            out string[] moduleReferences,
            out ManagedResourceInfo[] managedResources,
            out string[] assemblyAttributes,
            out string[] moduleAttributes,
            out MetadataTableCountInfo[] metadataTableCounts,
            out int moduleDefinitionCount,
            out int typeDefinitionCount,
            out int typeReferenceCount,
            out int methodDefinitionCount,
            out int fieldDefinitionCount,
            out int propertyDefinitionCount,
            out int eventDefinitionCount,
            out bool hasDebuggableAttribute,
            out string debuggableModes)
        {
            assemblyName = string.Empty;
            assemblyVersion = string.Empty;
            mvid = string.Empty;
            targetFramework = string.Empty;
            assemblyReferences = Array.Empty<ClrAssemblyReferenceInfo>();
            moduleReferences = Array.Empty<string>();
            managedResources = Array.Empty<ManagedResourceInfo>();
            assemblyAttributes = Array.Empty<string>();
            moduleAttributes = Array.Empty<string>();
            metadataTableCounts = Array.Empty<MetadataTableCountInfo>();
            moduleDefinitionCount = 0;
            typeDefinitionCount = 0;
            typeReferenceCount = 0;
            methodDefinitionCount = 0;
            fieldDefinitionCount = 0;
            propertyDefinitionCount = 0;
            eventDefinitionCount = 0;
            hasDebuggableAttribute = false;
            debuggableModes = string.Empty;

            try
            {
                if (metadata == null || length <= 0)
                {
                    return false;
                }

                if (length > metadata.Length)
                {
                    length = metadata.Length;
                }

                System.Collections.Immutable.ImmutableArray<byte> image = System.Collections.Immutable.ImmutableArray.Create(metadata, 0, length);
                using (MetadataReaderProvider provider = MetadataReaderProvider.FromMetadataImage(image))
                {
                    MetadataReader reader = provider.GetMetadataReader();
                    metadataTableCounts = BuildMetadataTableCounts(reader);
                    moduleDefinitionCount = reader.GetTableRowCount(TableIndex.Module);
                    typeDefinitionCount = reader.GetTableRowCount(TableIndex.TypeDef);
                    typeReferenceCount = reader.GetTableRowCount(TableIndex.TypeRef);
                    methodDefinitionCount = reader.GetTableRowCount(TableIndex.MethodDef);
                    fieldDefinitionCount = reader.GetTableRowCount(TableIndex.Field);
                    propertyDefinitionCount = reader.GetTableRowCount(TableIndex.Property);
                    eventDefinitionCount = reader.GetTableRowCount(TableIndex.Event);

                    ModuleDefinition module = reader.GetModuleDefinition();
                    Guid moduleMvid = reader.GetGuid(module.Mvid);
                    if (moduleMvid != Guid.Empty)
                    {
                        mvid = moduleMvid.ToString();
                    }

                    List<ClrAssemblyReferenceInfo> refs = new List<ClrAssemblyReferenceInfo>();
                    if (reader.IsAssembly)
                    {
                        AssemblyDefinition assembly = reader.GetAssemblyDefinition();
                        assemblyName = reader.GetString(assembly.Name);
                        assemblyVersion = assembly.Version.ToString();
                        targetFramework = TryGetTargetFramework(reader, assembly);
                        debuggableModes = TryGetDebuggableAttribute(reader, assembly, out hasDebuggableAttribute);
                        assemblyAttributes = BuildCustomAttributeNames(reader, assembly.GetCustomAttributes());

                        foreach (AssemblyReferenceHandle handle in reader.AssemblyReferences)
                        {
                            AssemblyReference reference = reader.GetAssemblyReference(handle);
                            string name = reader.GetString(reference.Name);
                            string version = reference.Version.ToString();
                            string culture = reference.Culture.IsNil ? string.Empty : reader.GetString(reference.Culture);
                            byte[] publicKeyOrToken = reader.GetBlobBytes(reference.PublicKeyOrToken);
                            bool isPublicKey = (reference.Flags & AssemblyFlags.PublicKey) != 0;
                            string publicKeyOrTokenHex = ToHex(publicKeyOrToken);
                            string publicKeyToken = isPublicKey
                                ? ComputePublicKeyToken(publicKeyOrToken)
                                : publicKeyOrTokenHex;
                            string resolutionHint = BuildAssemblyReferenceHint(name, publicKeyToken);
                            int rowId = MetadataTokens.GetRowNumber(handle);
                            int metadataToken = MetadataTokens.GetToken(handle);
                            string fullName = BuildAssemblyDisplayName(name, version, culture, publicKeyToken);

                            refs.Add(new ClrAssemblyReferenceInfo(name, version, culture, publicKeyOrTokenHex, publicKeyToken, isPublicKey, resolutionHint, metadataToken, rowId, fullName));
                        }
                    }

                    assemblyReferences = refs.ToArray();
                    moduleReferences = BuildModuleReferenceList(reader);
                    managedResources = BuildManagedResourceList(reader);
                    moduleAttributes = BuildModuleAttributes(reader);
                    return true;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private bool TryBuildClrMetadataDeepDive(
            byte[] metadata,
            int length,
            List<IMAGE_SECTION_HEADER> sections,
            out ClrTokenReferenceInfo[] tokenReferences,
            out ClrMethodBodySummaryInfo methodBodySummary,
            out ClrSignatureDecodeSummaryInfo signatureSummary)
        {
            tokenReferences = Array.Empty<ClrTokenReferenceInfo>();
            methodBodySummary = null;
            signatureSummary = null;

            try
            {
                if (metadata == null || length <= 0)
                {
                    return false;
                }

                if (length > metadata.Length)
                {
                    length = metadata.Length;
                }

                System.Collections.Immutable.ImmutableArray<byte> image = System.Collections.Immutable.ImmutableArray.Create(metadata, 0, length);
                using (MetadataReaderProvider provider = MetadataReaderProvider.FromMetadataImage(image))
                {
                    MetadataReader reader = provider.GetMetadataReader();
                    tokenReferences = BuildTokenReferenceInfos(reader);
                    methodBodySummary = BuildMethodBodySummary(reader, sections);
                    signatureSummary = BuildSignatureSummary(reader);
                    return true;
                }
            }
            catch (Exception)
            {
                tokenReferences = Array.Empty<ClrTokenReferenceInfo>();
                methodBodySummary = null;
                signatureSummary = null;
                return false;
            }
        }

        private static ClrTokenReferenceInfo[] BuildTokenReferenceInfos(MetadataReader reader)
        {
            List<ClrTokenReferenceInfo> infos = new List<ClrTokenReferenceInfo>();

            Dictionary<HandleKind, int> typeRefScopes = new Dictionary<HandleKind, int>();
            foreach (TypeReferenceHandle handle in reader.TypeReferences)
            {
                TypeReference typeRef = reader.GetTypeReference(handle);
                HandleKind kind = typeRef.ResolutionScope.Kind;
                if (!typeRef.ResolutionScope.IsNil)
                {
                    if (typeRefScopes.TryGetValue(kind, out int count))
                    {
                        typeRefScopes[kind] = count + 1;
                    }
                    else
                    {
                        typeRefScopes[kind] = 1;
                    }
                }
            }

            if (typeRefScopes.Count > 0)
            {
                infos.Add(new ClrTokenReferenceInfo(
                    "TypeRef.ResolutionScope",
                    typeRefScopes
                        .OrderBy(kv => kv.Key.ToString(), StringComparer.Ordinal)
                        .Select(kv => new ClrTokenReferenceCount(kv.Key.ToString(), kv.Value))
                        .ToArray()));
            }

            Dictionary<HandleKind, int> memberRefParents = new Dictionary<HandleKind, int>();
            foreach (MemberReferenceHandle handle in reader.MemberReferences)
            {
                MemberReference memberRef = reader.GetMemberReference(handle);
                HandleKind kind = memberRef.Parent.Kind;
                if (!memberRef.Parent.IsNil)
                {
                    if (memberRefParents.TryGetValue(kind, out int count))
                    {
                        memberRefParents[kind] = count + 1;
                    }
                    else
                    {
                        memberRefParents[kind] = 1;
                    }
                }
            }

            if (memberRefParents.Count > 0)
            {
                infos.Add(new ClrTokenReferenceInfo(
                    "MemberRef.Parent",
                    memberRefParents
                        .OrderBy(kv => kv.Key.ToString(), StringComparer.Ordinal)
                        .Select(kv => new ClrTokenReferenceCount(kv.Key.ToString(), kv.Value))
                        .ToArray()));
            }

            Dictionary<HandleKind, int> attributeParents = new Dictionary<HandleKind, int>();
            foreach (CustomAttributeHandle handle in reader.CustomAttributes)
            {
                CustomAttribute attribute = reader.GetCustomAttribute(handle);
                HandleKind kind = attribute.Parent.Kind;
                if (!attribute.Parent.IsNil)
                {
                    if (attributeParents.TryGetValue(kind, out int count))
                    {
                        attributeParents[kind] = count + 1;
                    }
                    else
                    {
                        attributeParents[kind] = 1;
                    }
                }
            }

            if (attributeParents.Count > 0)
            {
                infos.Add(new ClrTokenReferenceInfo(
                    "CustomAttribute.Parent",
                    attributeParents
                        .OrderBy(kv => kv.Key.ToString(), StringComparer.Ordinal)
                        .Select(kv => new ClrTokenReferenceCount(kv.Key.ToString(), kv.Value))
                        .ToArray()));
            }

            return infos.ToArray();
        }

        private ClrSignatureDecodeSummaryInfo BuildSignatureSummary(MetadataReader reader)
        {
            const int maxSamples = 25;
            const int maxFailures = 10;
            List<ClrSignatureSampleInfo> samples = new List<ClrSignatureSampleInfo>();
            List<string> failures = new List<string>();
            SignatureTypeNameProvider provider = new SignatureTypeNameProvider(reader);

            int methodCount = 0;
            int fieldCount = 0;
            int memberRefCount = 0;
            int standaloneCount = 0;
            int decoded = 0;
            int failed = 0;

            foreach (MethodDefinitionHandle handle in reader.MethodDefinitions)
            {
                methodCount++;
                MethodDefinition method = reader.GetMethodDefinition(handle);
                string name = reader.GetString(method.Name);
                try
                {
                    MethodSignature<string> signature = method.DecodeSignature(provider, null);
                    string signatureText = FormatMethodSignature(signature);
                    decoded++;
                    AddSignatureSample(samples, maxSamples, "Method", name, signatureText);
                }
                catch (Exception ex)
                {
                    failed++;
                    AddFailure(failures, maxFailures, ex.Message);
                }
            }

            foreach (FieldDefinitionHandle handle in reader.FieldDefinitions)
            {
                fieldCount++;
                FieldDefinition field = reader.GetFieldDefinition(handle);
                string name = reader.GetString(field.Name);
                try
                {
                    string typeName = field.DecodeSignature(provider, null);
                    string signatureText = string.IsNullOrWhiteSpace(typeName) ? string.Empty : typeName;
                    decoded++;
                    AddSignatureSample(samples, maxSamples, "Field", name, signatureText);
                }
                catch (Exception ex)
                {
                    failed++;
                    AddFailure(failures, maxFailures, ex.Message);
                }
            }

            foreach (MemberReferenceHandle handle in reader.MemberReferences)
            {
                memberRefCount++;
                MemberReference member = reader.GetMemberReference(handle);
                string name = reader.GetString(member.Name);
                try
                {
                    string signatureText = TryDecodeMemberReferenceSignature(member, provider);
                    decoded++;
                    AddSignatureSample(samples, maxSamples, "MemberRef", name, signatureText);
                }
                catch (Exception ex)
                {
                    failed++;
                    AddFailure(failures, maxFailures, ex.Message);
                }
            }

            int standaloneRows = reader.GetTableRowCount(TableIndex.StandAloneSig);
            for (int i = 1; i <= standaloneRows; i++)
            {
                standaloneCount++;
                StandaloneSignatureHandle handle = MetadataTokens.StandaloneSignatureHandle(i);
                StandaloneSignature sig = reader.GetStandaloneSignature(handle);
                try
                {
                    string signatureText = TryDecodeStandaloneSignature(reader, sig, provider);
                    decoded++;
                    AddSignatureSample(samples, maxSamples, "StandaloneSig", string.Empty, signatureText);
                }
                catch (Exception ex)
                {
                    failed++;
                    AddFailure(failures, maxFailures, ex.Message);
                }
            }

            return new ClrSignatureDecodeSummaryInfo(
                methodCount,
                fieldCount,
                memberRefCount,
                standaloneCount,
                decoded,
                failed,
                samples.ToArray(),
                failures.ToArray());
        }

        private ClrMethodBodySummaryInfo BuildMethodBodySummary(MetadataReader reader, List<IMAGE_SECTION_HEADER> sections)
        {
            int methodCount = reader.GetTableRowCount(TableIndex.MethodDef);
            int methodBodyCount = 0;
            int tinyCount = 0;
            int fatCount = 0;
            int invalidCount = 0;
            long totalIlBytes = 0;
            int maxIlBytes = 0;
            int ehClauseCount = 0;
            int ehCatchCount = 0;
            int ehFinallyCount = 0;
            int ehFaultCount = 0;
            int ehFilterCount = 0;
            int ehInvalidCount = 0;

            foreach (MethodDefinitionHandle handle in reader.MethodDefinitions)
            {
                MethodDefinition method = reader.GetMethodDefinition(handle);
                int rvaValue = method.RelativeVirtualAddress;
                if (rvaValue <= 0)
                {
                    continue;
                }

                uint rva = (uint)rvaValue;
                if (!TryReadMethodBodyInfo(sections, rva, out MethodBodyInfo bodyInfo))
                {
                    invalidCount++;
                    continue;
                }

                methodBodyCount++;
                if (bodyInfo.IsTiny)
                {
                    tinyCount++;
                }
                else if (bodyInfo.IsFat)
                {
                    fatCount++;
                }

                totalIlBytes += bodyInfo.CodeSize;
                if (bodyInfo.CodeSize > maxIlBytes)
                {
                    maxIlBytes = bodyInfo.CodeSize;
                }

                ehClauseCount += bodyInfo.ExceptionClauseCount;
                ehCatchCount += bodyInfo.ExceptionClauseCatchCount;
                ehFinallyCount += bodyInfo.ExceptionClauseFinallyCount;
                ehFaultCount += bodyInfo.ExceptionClauseFaultCount;
                ehFilterCount += bodyInfo.ExceptionClauseFilterCount;
                ehInvalidCount += bodyInfo.ExceptionClauseInvalidCount;
            }

            int average = methodBodyCount > 0
                ? (int)Math.Min(int.MaxValue, totalIlBytes / methodBodyCount)
                : 0;
            int total = totalIlBytes > int.MaxValue ? int.MaxValue : (int)totalIlBytes;

            return new ClrMethodBodySummaryInfo(
                methodCount,
                methodBodyCount,
                tinyCount,
                fatCount,
                invalidCount,
                total,
                maxIlBytes,
                average,
                ehClauseCount,
                ehCatchCount,
                ehFinallyCount,
                ehFaultCount,
                ehFilterCount,
                ehInvalidCount);
        }

        private static void AddSignatureSample(
            List<ClrSignatureSampleInfo> samples,
            int maxSamples,
            string kind,
            string name,
            string signature)
        {
            if (samples.Count >= maxSamples)
            {
                return;
            }

            samples.Add(new ClrSignatureSampleInfo(kind, name, signature));
        }

        private static void AddFailure(List<string> failures, int maxFailures, string message)
        {
            if (failures.Count >= maxFailures)
            {
                return;
            }

            string text = string.IsNullOrWhiteSpace(message) ? "Unknown signature decode error." : message.Trim();
            if (!failures.Contains(text))
            {
                failures.Add(text);
            }
        }

        private static string FormatMethodSignature(MethodSignature<string> signature)
        {
            string returnType = string.IsNullOrWhiteSpace(signature.ReturnType) ? "void" : signature.ReturnType;
            if (signature.ParameterTypes.Length == 0)
            {
                return returnType + " ()";
            }

            string[] parameters = new string[signature.ParameterTypes.Length];
            for (int i = 0; i < signature.ParameterTypes.Length; i++)
            {
                string value = string.IsNullOrWhiteSpace(signature.ParameterTypes[i])
                    ? "unknown"
                    : signature.ParameterTypes[i];
                if (i >= signature.RequiredParameterCount)
                {
                    value = "opt " + value;
                }
                parameters[i] = value;
            }

            return returnType + " (" + string.Join(", ", parameters) + ")";
        }

        private static string TryDecodeMemberReferenceSignature(MemberReference member, SignatureTypeNameProvider provider)
        {
            try
            {
                MethodSignature<string> methodSig = member.DecodeMethodSignature(provider, null);
                return FormatMethodSignature(methodSig);
            }
            catch
            {
            }

            try
            {
                string fieldSig = member.DecodeFieldSignature(provider, null);
                return fieldSig ?? string.Empty;
            }
            catch
            {
            }

            return string.Empty;
        }

        private static string TryDecodeStandaloneSignature(MetadataReader reader, StandaloneSignature signature, SignatureTypeNameProvider provider)
        {
            BlobReader blob = reader.GetBlobReader(signature.Signature);
            if (blob.Length == 0)
            {
                return string.Empty;
            }

            SignatureDecoder<string, object> decoder = new SignatureDecoder<string, object>(provider, reader, null);
            BlobReader decodeReader = blob;
            SignatureHeader header = blob.ReadSignatureHeader();
            switch (header.Kind)
            {
                case SignatureKind.Method:
                    return FormatMethodSignature(decoder.DecodeMethodSignature(ref decodeReader));
                case SignatureKind.Field:
                    return decoder.DecodeFieldSignature(ref decodeReader);
                case SignatureKind.LocalVariables:
                    {
                        ImmutableArray<string> locals = decoder.DecodeLocalSignature(ref decodeReader);
                        if (locals.IsDefaultOrEmpty)
                        {
                            return "locals ()";
                        }
                        return "locals (" + string.Join(", ", locals) + ")";
                    }
                default:
                    return header.Kind.ToString();
            }
        }

        private sealed class SignatureTypeNameProvider : ISignatureTypeProvider<string, object>
        {
            private readonly MetadataReader _reader;

            public SignatureTypeNameProvider(MetadataReader reader)
            {
                _reader = reader;
            }

            public string GetArrayType(string elementType, ArrayShape shape)
            {
                if (shape.Rank <= 1)
                {
                    return elementType + "[]";
                }

                return elementType + "[" + new string(',', shape.Rank - 1) + "]";
            }

            public string GetByReferenceType(string elementType) => elementType + "&";

            public string GetFunctionPointerType(MethodSignature<string> signature) => "fnptr " + FormatMethodSignature(signature);

            public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments)
            {
                if (typeArguments.IsDefaultOrEmpty)
                {
                    return genericType;
                }

                return genericType + "<" + string.Join(", ", typeArguments) + ">";
            }

            public string GetGenericMethodParameter(object genericContext, int index) => "!!" + index.ToString(CultureInfo.InvariantCulture);

            public string GetGenericTypeParameter(object genericContext, int index) => "!" + index.ToString(CultureInfo.InvariantCulture);

            public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired)
            {
                string suffix = isRequired ? " modreq(" : " modopt(";
                return unmodifiedType + suffix + modifier + ")";
            }

            public string GetPinnedType(string elementType) => elementType + " pinned";

            public string GetPointerType(string elementType) => elementType + "*";

            public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode.ToString();

            public string GetSZArrayType(string elementType) => elementType + "[]";

            public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind)
            {
                TypeDefinition typeDef = _reader.GetTypeDefinition(handle);
                return FormatTypeName(_reader.GetString(typeDef.Namespace), _reader.GetString(typeDef.Name));
            }

            public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind)
            {
                TypeReference typeRef = _reader.GetTypeReference(handle);
                return FormatTypeName(_reader.GetString(typeRef.Namespace), _reader.GetString(typeRef.Name));
            }

            public string GetTypeFromSpecification(MetadataReader reader, object genericContext, TypeSpecificationHandle handle, byte rawTypeKind)
            {
                TypeSpecification typeSpec = _reader.GetTypeSpecification(handle);
                return typeSpec.DecodeSignature(this, genericContext);
            }

            private static string FormatTypeName(string ns, string name)
            {
                if (string.IsNullOrWhiteSpace(ns))
                {
                    return name ?? string.Empty;
                }

                if (string.IsNullOrWhiteSpace(name))
                {
                    return ns;
                }

                return ns + "." + name;
            }
        }

        private readonly struct MethodBodyInfo
        {
            public int CodeSize { get; }
            public bool IsTiny { get; }
            public bool IsFat { get; }
            public int ExceptionClauseCount { get; }
            public int ExceptionClauseCatchCount { get; }
            public int ExceptionClauseFinallyCount { get; }
            public int ExceptionClauseFaultCount { get; }
            public int ExceptionClauseFilterCount { get; }
            public int ExceptionClauseInvalidCount { get; }

            public MethodBodyInfo(
                int codeSize,
                bool isTiny,
                bool isFat,
                int exceptionClauseCount,
                int exceptionClauseCatchCount,
                int exceptionClauseFinallyCount,
                int exceptionClauseFaultCount,
                int exceptionClauseFilterCount,
                int exceptionClauseInvalidCount)
            {
                CodeSize = codeSize;
                IsTiny = isTiny;
                IsFat = isFat;
                ExceptionClauseCount = exceptionClauseCount;
                ExceptionClauseCatchCount = exceptionClauseCatchCount;
                ExceptionClauseFinallyCount = exceptionClauseFinallyCount;
                ExceptionClauseFaultCount = exceptionClauseFaultCount;
                ExceptionClauseFilterCount = exceptionClauseFilterCount;
                ExceptionClauseInvalidCount = exceptionClauseInvalidCount;
            }
        }

        private bool TryReadMethodBodyInfo(
            List<IMAGE_SECTION_HEADER> sections,
            uint rva,
            out MethodBodyInfo info)
        {
            info = default;
            if (PEFileStream == null)
            {
                return false;
            }

            if (!TryGetFileOffset(sections, rva, out long offset))
            {
                return false;
            }

            long originalPosition = PEFileStream.CanSeek ? PEFileStream.Position : 0;
            try
            {
                if (!TrySetPosition(offset, 1))
                {
                    return false;
                }

                byte first = PEFile.ReadByte();
                int headerType = first & 0x3;
                if (headerType == 2)
                {
                    int codeSize = first >> 2;
                    info = new MethodBodyInfo(codeSize, true, false, 0, 0, 0, 0, 0, 0);
                    return true;
                }
                if (headerType == 3)
                {
                    if (!TrySetPosition(offset, 12))
                    {
                        return false;
                    }

                    byte headerFirst = PEFile.ReadByte();
                    byte headerSecond = PEFile.ReadByte();
                    ushort flags = (ushort)(headerFirst | (headerSecond << 8));
                    int headerSize = ((flags >> 12) & 0xF) * 4;
                    if (headerSize < 12)
                    {
                        return false;
                    }

                    PEFile.ReadUInt16(); // maxStack
                    uint size = PEFile.ReadUInt32();
                    _ = PEFile.ReadUInt32(); // localVarSigTok
                    int codeSize = size > int.MaxValue ? int.MaxValue : (int)size;
                    bool moreSections = (flags & 0x8) != 0;
                    int ehClauseCount = 0;
                    int ehCatchCount = 0;
                    int ehFinallyCount = 0;
                    int ehFaultCount = 0;
                    int ehFilterCount = 0;
                    int ehInvalidCount = 0;

                    if (moreSections && codeSize >= 0)
                    {
                        long codeOffset = offset + headerSize;
                        long sectionOffset = codeOffset + size;
                        sectionOffset = (sectionOffset + 3) & ~3L;
                        if (sectionOffset >= 0 && sectionOffset < PEFileStream.Length)
                        {
                            long sectionCursor = sectionOffset;
                            bool hasMore = true;
                            int safeGuard = 0;
                            while (hasMore && safeGuard++ < 64)
                            {
                                if (sectionCursor + 4 > PEFileStream.Length)
                                {
                                    ehInvalidCount++;
                                    break;
                                }
                                if (!TrySetPosition(sectionCursor, 4))
                                {
                                    ehInvalidCount++;
                                    break;
                                }

                                byte kind = PEFile.ReadByte();
                                byte dataSizeLow = PEFile.ReadByte();
                                ushort dataSizeHigh = PEFile.ReadUInt16();
                                hasMore = (kind & 0x80) != 0;
                                bool isFatSection = (kind & 0x40) != 0;
                                int dataSize = isFatSection
                                    ? (dataSizeHigh << 8) | dataSizeLow
                                    : dataSizeLow;
                                if (dataSize < 4)
                                {
                                    ehInvalidCount++;
                                    break;
                                }

                                int sectionSize = dataSize;
                                long sectionEnd = sectionCursor + sectionSize;
                                if (sectionEnd > PEFileStream.Length)
                                {
                                    ehInvalidCount++;
                                    break;
                                }

                                int sectionKind = kind & 0x3F;
                                if (sectionKind == 0x01)
                                {
                                    int clauseSize = isFatSection ? 24 : 12;
                                    int clauseBytes = sectionSize - 4;
                                    if (clauseBytes < 0 || clauseBytes % clauseSize != 0)
                                    {
                                        ehInvalidCount++;
                                    }
                                    int clauseCount = clauseBytes >= 0 ? clauseBytes / clauseSize : 0;
                                    ehClauseCount += clauseCount;

                                    long clauseOffset = sectionCursor + 4;
                                    for (int i = 0; i < clauseCount; i++)
                                    {
                                        if (clauseOffset + clauseSize > sectionEnd)
                                        {
                                            ehInvalidCount++;
                                            break;
                                        }
                                        if (!TrySetPosition(clauseOffset, clauseSize))
                                        {
                                            ehInvalidCount++;
                                            break;
                                        }

                                        uint clauseFlags = isFatSection ? PEFile.ReadUInt32() : PEFile.ReadUInt16();
                                        if ((clauseFlags & 0x1) != 0)
                                        {
                                            ehFilterCount++;
                                        }
                                        else if ((clauseFlags & 0x2) != 0)
                                        {
                                            ehFinallyCount++;
                                        }
                                        else if ((clauseFlags & 0x4) != 0)
                                        {
                                            ehFaultCount++;
                                        }
                                        else
                                        {
                                            ehCatchCount++;
                                        }

                                        clauseOffset += clauseSize;
                                    }
                                }

                                sectionCursor = (sectionEnd + 3) & ~3L;
                            }
                        }
                    }

                    info = new MethodBodyInfo(
                        codeSize,
                        false,
                        true,
                        ehClauseCount,
                        ehCatchCount,
                        ehFinallyCount,
                        ehFaultCount,
                        ehFilterCount,
                        ehInvalidCount);
                    return true;
                }

                return false;
            }
            finally
            {
                if (PEFileStream.CanSeek)
                {
                    PEFileStream.Position = originalPosition;
                }
            }
        }

        private static bool TryParseMethodBodyInfoFromSpan(ReadOnlySpan<byte> data, out MethodBodyInfo info)
        {
            info = default;
            if (data.Length < 1)
            {
                return false;
            }

            byte first = data[0];
            int headerType = first & 0x3;
            if (headerType == 2)
            {
                int tinyCodeSize = first >> 2;
                info = new MethodBodyInfo(tinyCodeSize, true, false, 0, 0, 0, 0, 0, 0);
                return true;
            }

            if (headerType != 3 || data.Length < 12)
            {
                return false;
            }

            ushort flags = (ushort)(data[0] | (data[1] << 8));
            int headerSize = ((flags >> 12) & 0xF) * 4;
            if (headerSize < 12 || headerSize > data.Length)
            {
                return false;
            }

            uint size = ReadUInt32(data, 4);
            int fatCodeSize = size > int.MaxValue ? int.MaxValue : (int)size;
            bool moreSections = (flags & 0x8) != 0;
            int ehClauseCount = 0;
            int ehCatchCount = 0;
            int ehFinallyCount = 0;
            int ehFaultCount = 0;
            int ehFilterCount = 0;
            int ehInvalidCount = 0;

            if (moreSections)
            {
                long sectionOffset = headerSize + size;
                sectionOffset = (sectionOffset + 3) & ~3L;
                if (sectionOffset >= 0 && sectionOffset < data.Length)
                {
                    long cursor = sectionOffset;
                    bool hasMore = true;
                    int safeGuard = 0;
                    while (hasMore && safeGuard++ < 64)
                    {
                        if (cursor + 4 > data.Length)
                        {
                            ehInvalidCount++;
                            break;
                        }

                        byte kind = data[(int)cursor];
                        byte dataSizeLow = data[(int)cursor + 1];
                        ushort dataSizeHigh = ReadUInt16(data, (int)cursor + 2);
                        hasMore = (kind & 0x80) != 0;
                        bool isFatSection = (kind & 0x40) != 0;
                        int sectionSize = isFatSection
                            ? (dataSizeHigh << 8) | dataSizeLow
                            : dataSizeLow;
                        if (sectionSize < 4)
                        {
                            ehInvalidCount++;
                            break;
                        }

                        long sectionEnd = cursor + sectionSize;
                        if (sectionEnd > data.Length)
                        {
                            ehInvalidCount++;
                            break;
                        }

                        int sectionKind = kind & 0x3F;
                        if (sectionKind == 0x01)
                        {
                            int clauseSize = isFatSection ? 24 : 12;
                            int clauseBytes = sectionSize - 4;
                            if (clauseBytes < 0 || clauseBytes % clauseSize != 0)
                            {
                                ehInvalidCount++;
                            }
                            int clauseCount = clauseBytes >= 0 ? clauseBytes / clauseSize : 0;
                            ehClauseCount += clauseCount;
                            long clauseOffset = cursor + 4;
                            for (int i = 0; i < clauseCount; i++)
                            {
                                if (clauseOffset + clauseSize > sectionEnd)
                                {
                                    ehInvalidCount++;
                                    break;
                                }

                                uint clauseFlags = isFatSection
                                    ? ReadUInt32(data, (int)clauseOffset)
                                    : ReadUInt16(data, (int)clauseOffset);
                                if ((clauseFlags & 0x1) != 0)
                                {
                                    ehFilterCount++;
                                }
                                else if ((clauseFlags & 0x2) != 0)
                                {
                                    ehFinallyCount++;
                                }
                                else if ((clauseFlags & 0x4) != 0)
                                {
                                    ehFaultCount++;
                                }
                                else
                                {
                                    ehCatchCount++;
                                }

                                clauseOffset += clauseSize;
                            }
                        }

                        cursor = (sectionEnd + 3) & ~3L;
                    }
                }
            }

            info = new MethodBodyInfo(
                fatCodeSize,
                false,
                true,
                ehClauseCount,
                ehCatchCount,
                ehFinallyCount,
                ehFaultCount,
                ehFilterCount,
                ehInvalidCount);
            return true;
        }

        private static string TryGetTargetFramework(MetadataReader reader, AssemblyDefinition assembly)
        {
            foreach (CustomAttributeHandle handle in assembly.GetCustomAttributes())
            {
                CustomAttribute attribute = reader.GetCustomAttribute(handle);
                if (!IsTargetFrameworkAttribute(reader, attribute))
                {
                    continue;
                }

                try
                {
                    BlobReader blob = reader.GetBlobReader(attribute.Value);
                    if (blob.Length < 2)
                    {
                        continue;
                    }

                    if (blob.ReadUInt16() != 1)
                    {
                        continue;
                    }

                    string value = blob.ReadSerializedString();
                    return value ?? string.Empty;
                }
                catch (Exception)
                {
                    return string.Empty;
                }
            }

            return string.Empty;
        }

        private static string TryGetDebuggableAttribute(MetadataReader reader, AssemblyDefinition assembly, out bool hasAttribute)
        {
            hasAttribute = false;
            foreach (CustomAttributeHandle handle in assembly.GetCustomAttributes())
            {
                CustomAttribute attribute = reader.GetCustomAttribute(handle);
                if (!IsDebuggableAttribute(reader, attribute))
                {
                    continue;
                }

                hasAttribute = true;
                try
                {
                    BlobReader blob = reader.GetBlobReader(attribute.Value);
                    if (blob.Length < 2)
                    {
                        return string.Empty;
                    }

                    if (blob.ReadUInt16() != 1)
                    {
                        return string.Empty;
                    }

                    if (blob.RemainingBytes >= 4)
                    {
                        int modes = blob.ReadInt32();
                        return BuildDebuggableModesString(modes);
                    }
                }
                catch (Exception)
                {
                    return string.Empty;
                }
            }

            return string.Empty;
        }

        private static MetadataTableCountInfo[] BuildMetadataTableCounts(MetadataReader reader)
        {
            List<MetadataTableCountInfo> counts = new List<MetadataTableCountInfo>();
            foreach (TableIndex table in Enum.GetValues(typeof(TableIndex)))
            {
                int count = reader.GetTableRowCount(table);
                if (count > 0)
                {
                    uint tokenPrefix = ((uint)table) << 24;
                    uint firstToken = tokenPrefix | 0x00000001;
                    uint lastToken = tokenPrefix | (uint)count;
                    counts.Add(new MetadataTableCountInfo((int)table, table.ToString(), count, firstToken, lastToken));
                }
            }

            return counts.ToArray();
        }

        private static string[] BuildCustomAttributeNames(MetadataReader reader, CustomAttributeHandleCollection handles)
        {
            HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
            foreach (CustomAttributeHandle handle in handles)
            {
                CustomAttribute attribute = reader.GetCustomAttribute(handle);
                if (TryGetAttributeTypeName(reader, attribute, out string name))
                {
                    names.Add(name);
                }
            }

            return names.Count == 0
                ? Array.Empty<string>()
                : names.OrderBy(value => value, StringComparer.Ordinal).ToArray();
        }

        private static string[] BuildModuleAttributes(MetadataReader reader)
        {
            ModuleDefinition module = reader.GetModuleDefinition();
            return BuildCustomAttributeNames(reader, module.GetCustomAttributes());
        }

        private static bool TryGetAttributeTypeName(MetadataReader reader, CustomAttribute attribute, out string name)
        {
            name = string.Empty;
            EntityHandle ctor = attribute.Constructor;
            if (ctor.Kind == HandleKind.MemberReference)
            {
                MemberReference member = reader.GetMemberReference((MemberReferenceHandle)ctor);
                if (TryGetTypeName(reader, member.Parent, out string typeName, out string typeNs))
                {
                    name = string.IsNullOrWhiteSpace(typeNs) ? typeName : typeNs + "." + typeName;
                    return !string.IsNullOrWhiteSpace(name);
                }
            }
            else if (ctor.Kind == HandleKind.MethodDefinition)
            {
                MethodDefinition method = reader.GetMethodDefinition((MethodDefinitionHandle)ctor);
                if (TryGetTypeName(reader, method.GetDeclaringType(), out string typeName, out string typeNs))
                {
                    name = string.IsNullOrWhiteSpace(typeNs) ? typeName : typeNs + "." + typeName;
                    return !string.IsNullOrWhiteSpace(name);
                }
            }

            return false;
        }

        private static string BuildAssemblyReferenceHint(string name, string publicKeyToken)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return string.Empty;
            }

            if (string.Equals(name, "mscorlib", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "netstandard", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase))
            {
                return "Framework";
            }

            if (string.IsNullOrWhiteSpace(publicKeyToken))
            {
                return "Unsigned";
            }

            return "ThirdParty";
        }

        private static string BuildAssemblyDisplayName(string name, string version, string culture, string publicKeyToken)
        {
            StringBuilder sb = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(name))
            {
                sb.Append(name);
            }

            if (!string.IsNullOrWhiteSpace(version))
            {
                sb.Append(", Version=").Append(version);
            }

            if (!string.IsNullOrWhiteSpace(culture))
            {
                sb.Append(", Culture=").Append(culture);
            }

            if (!string.IsNullOrWhiteSpace(publicKeyToken))
            {
                sb.Append(", PublicKeyToken=").Append(publicKeyToken);
            }

            return sb.ToString();
        }

        private static string[] BuildModuleReferenceList(MetadataReader reader)
        {
            int count = reader.GetTableRowCount(TableIndex.ModuleRef);
            if (count <= 0)
            {
                return Array.Empty<string>();
            }

            List<string> refs = new List<string>(count);
            for (int i = 1; i <= count; i++)
            {
                ModuleReferenceHandle handle = MetadataTokens.ModuleReferenceHandle(i);
                ModuleReference moduleReference = reader.GetModuleReference(handle);
                string name = reader.GetString(moduleReference.Name);
                if (!string.IsNullOrWhiteSpace(name))
                {
                    refs.Add(name);
                }
            }

            return refs.ToArray();
        }

        private static ManagedResourceInfo[] BuildManagedResourceList(MetadataReader reader)
        {
            int count = reader.GetTableRowCount(TableIndex.ManifestResource);
            if (count <= 0)
            {
                return Array.Empty<ManagedResourceInfo>();
            }

            List<ManagedResourceInfo> resources = new List<ManagedResourceInfo>(count);
            for (int i = 1; i <= count; i++)
            {
                ManifestResourceHandle handle = MetadataTokens.ManifestResourceHandle(i);
                ManifestResource resource = reader.GetManifestResource(handle);
                string name = reader.GetString(resource.Name);
                bool isPublic = (resource.Attributes & ManifestResourceAttributes.Public) != 0;
                string implementation = GetManagedResourceImplementation(reader, resource.Implementation);
                long rawOffset = resource.Offset;
                uint offset = rawOffset < 0
                    ? 0u
                    : (rawOffset > uint.MaxValue ? uint.MaxValue : (uint)rawOffset);
                resources.Add(new ManagedResourceInfo(name, offset, 0, isPublic, implementation, string.Empty));
            }

            return resources.ToArray();
        }

        private static string GetManagedResourceImplementation(MetadataReader reader, EntityHandle handle)
        {
            if (handle.IsNil)
            {
                return "embedded";
            }

            switch (handle.Kind)
            {
                case HandleKind.AssemblyReference:
                    {
                        AssemblyReference reference = reader.GetAssemblyReference((AssemblyReferenceHandle)handle);
                        string name = reader.GetString(reference.Name);
                        return string.IsNullOrWhiteSpace(name) ? "assembly" : "assembly:" + name;
                    }
                case HandleKind.AssemblyFile:
                    {
                        AssemblyFile file = reader.GetAssemblyFile((AssemblyFileHandle)handle);
                        string name = reader.GetString(file.Name);
                        return string.IsNullOrWhiteSpace(name) ? "file" : "file:" + name;
                    }
                case HandleKind.ExportedType:
                    {
                        ExportedType type = reader.GetExportedType((ExportedTypeHandle)handle);
                        string typeName = reader.GetString(type.Name);
                        string typeNamespace = reader.GetString(type.Namespace);
                        string fullName = string.IsNullOrWhiteSpace(typeNamespace) ? typeName : typeNamespace + "." + typeName;
                        return string.IsNullOrWhiteSpace(fullName) ? "exported-type" : "exported-type:" + fullName;
                    }
                default:
                    return "unknown";
            }
        }

        private static string ComputePublicKeyToken(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length == 0)
            {
                return string.Empty;
            }

            byte[] hash = SHA1.HashData(publicKey);
            if (hash.Length < 8)
            {
                return string.Empty;
            }

            byte[] token = new byte[8];
            for (int i = 0; i < token.Length; i++)
            {
                token[i] = hash[hash.Length - 1 - i];
            }

            return ToHex(token);
        }

        private void TryPopulateManagedResourceSizes(IMAGE_COR20_HEADER clrHeader, List<IMAGE_SECTION_HEADER> sections)
        {
            if (_clrMetadata == null || _clrMetadata.ManagedResources.Length == 0)
            {
                return;
            }

            if (clrHeader.Resources.VirtualAddress == 0 || clrHeader.Resources.Size == 0)
            {
                return;
            }

            if (!TryGetFileOffset(sections, clrHeader.Resources.VirtualAddress, out long resourceOffset))
            {
                Warn(ParseIssueCategory.CLR, "CLR managed resources RVA not mapped to a section.");
                return;
            }

            if (!TryGetIntSize(clrHeader.Resources.Size, out int resourceSize) || resourceSize < 4)
            {
                Warn(ParseIssueCategory.CLR, "CLR managed resources size is invalid.");
                return;
            }

            if (!TrySetPosition(resourceOffset, resourceSize))
            {
                Warn(ParseIssueCategory.CLR, "CLR managed resources offset outside file bounds.");
                return;
            }

            byte[] buffer = new byte[resourceSize];
            ReadExactly(PEFileStream, buffer, 0, buffer.Length);

            bool warnedBounds = false;
            bool computeHashes = _options != null && _options.ComputeManagedResourceHashes;
            ManagedResourceInfo[] updated = new ManagedResourceInfo[_clrMetadata.ManagedResources.Length];
            for (int i = 0; i < _clrMetadata.ManagedResources.Length; i++)
            {
                ManagedResourceInfo resource = _clrMetadata.ManagedResources[i];
                uint size = 0;
                string sha256 = resource.Sha256;
                if (string.Equals(resource.Implementation, "embedded", StringComparison.OrdinalIgnoreCase))
                {
                    uint offset = resource.Offset;
                    if (buffer.Length >= 4 && offset <= (uint)buffer.Length - 4)
                    {
                        size = ReadUInt32(buffer, (int)offset);
                        if (size > 0 && (ulong)offset + 4 + size > (uint)buffer.Length)
                        {
                            size = 0;
                            if (!warnedBounds)
                            {
                                Warn(ParseIssueCategory.CLR, "Managed resource size extends beyond resource section.");
                                warnedBounds = true;
                            }
                        }
                        else if (size > 0 && computeHashes)
                        {
                            byte[] hash = SHA256.HashData(new ReadOnlySpan<byte>(buffer, (int)offset + 4, (int)size));
                            sha256 = ToHex(hash);
                        }
                    }
                    else if (!warnedBounds)
                    {
                        Warn(ParseIssueCategory.CLR, "Managed resource offset outside resource section.");
                        warnedBounds = true;
                    }
                }

                updated[i] = new ManagedResourceInfo(resource.Name, resource.Offset, size, resource.IsPublic, resource.Implementation, sha256);
            }

            _clrMetadata = CloneClrMetadataWithResources(_clrMetadata, updated);
        }

        private static ClrMetadataInfo CloneClrMetadataWithResources(ClrMetadataInfo info, ManagedResourceInfo[] resources)
        {
            return new ClrMetadataInfo(
                info.MajorRuntimeVersion,
                info.MinorRuntimeVersion,
                info.Flags,
                info.EntryPointToken,
                info.MetadataVersion,
                info.Streams,
                info.AssemblyName,
                info.AssemblyVersion,
                info.Mvid,
                info.TargetFramework,
                info.AssemblyReferences,
                info.ModuleReferences,
                resources,
                info.AssemblyAttributes,
                info.ModuleAttributes,
                info.MetadataTableCounts,
                info.TokenReferences,
                info.MethodBodySummary,
                info.SignatureSummary,
                info.IlOnly,
                info.Requires32Bit,
                info.Prefers32Bit,
                info.StrongNameSigned,
                info.ModuleDefinitionCount,
                info.TypeDefinitionCount,
                info.TypeReferenceCount,
                info.MethodDefinitionCount,
                info.FieldDefinitionCount,
                info.PropertyDefinitionCount,
                info.EventDefinitionCount,
                info.HasDebuggableAttribute,
                info.DebuggableModes,
                info.IsValid,
                info.ValidationMessages);
        }

        private static ClrMetadataInfo CloneClrMetadataWithDeepDive(
            ClrMetadataInfo info,
            ClrTokenReferenceInfo[] tokenReferences,
            ClrMethodBodySummaryInfo methodBodySummary,
            ClrSignatureDecodeSummaryInfo signatureSummary)
        {
            return new ClrMetadataInfo(
                info.MajorRuntimeVersion,
                info.MinorRuntimeVersion,
                info.Flags,
                info.EntryPointToken,
                info.MetadataVersion,
                info.Streams,
                info.AssemblyName,
                info.AssemblyVersion,
                info.Mvid,
                info.TargetFramework,
                info.AssemblyReferences,
                info.ModuleReferences,
                info.ManagedResources,
                info.AssemblyAttributes,
                info.ModuleAttributes,
                info.MetadataTableCounts,
                tokenReferences ?? Array.Empty<ClrTokenReferenceInfo>(),
                methodBodySummary,
                signatureSummary,
                info.IlOnly,
                info.Requires32Bit,
                info.Prefers32Bit,
                info.StrongNameSigned,
                info.ModuleDefinitionCount,
                info.TypeDefinitionCount,
                info.TypeReferenceCount,
                info.MethodDefinitionCount,
                info.FieldDefinitionCount,
                info.PropertyDefinitionCount,
                info.EventDefinitionCount,
                info.HasDebuggableAttribute,
                info.DebuggableModes,
                info.IsValid,
                info.ValidationMessages);
        }

        private static bool IsTargetFrameworkAttribute(MetadataReader reader, CustomAttribute attribute)
        {
            EntityHandle ctor = attribute.Constructor;
            if (ctor.Kind == HandleKind.MemberReference)
            {
                MemberReference member = reader.GetMemberReference((MemberReferenceHandle)ctor);
                return TryGetTypeName(reader, member.Parent, out string name, out string ns) &&
                       string.Equals(name, "TargetFrameworkAttribute", StringComparison.Ordinal) &&
                       string.Equals(ns, "System.Runtime.Versioning", StringComparison.Ordinal);
            }

            if (ctor.Kind == HandleKind.MethodDefinition)
            {
                MethodDefinition method = reader.GetMethodDefinition((MethodDefinitionHandle)ctor);
                TypeDefinition typeDef = reader.GetTypeDefinition(method.GetDeclaringType());
                string name = reader.GetString(typeDef.Name);
                string ns = reader.GetString(typeDef.Namespace);
                return string.Equals(name, "TargetFrameworkAttribute", StringComparison.Ordinal) &&
                       string.Equals(ns, "System.Runtime.Versioning", StringComparison.Ordinal);
            }

            return false;
        }

        private static bool IsDebuggableAttribute(MetadataReader reader, CustomAttribute attribute)
        {
            EntityHandle ctor = attribute.Constructor;
            if (ctor.Kind == HandleKind.MemberReference)
            {
                MemberReference member = reader.GetMemberReference((MemberReferenceHandle)ctor);
                return TryGetTypeName(reader, member.Parent, out string name, out string ns) &&
                       string.Equals(name, "DebuggableAttribute", StringComparison.Ordinal) &&
                       string.Equals(ns, "System.Diagnostics", StringComparison.Ordinal);
            }

            if (ctor.Kind == HandleKind.MethodDefinition)
            {
                MethodDefinition method = reader.GetMethodDefinition((MethodDefinitionHandle)ctor);
                TypeDefinition typeDef = reader.GetTypeDefinition(method.GetDeclaringType());
                string name = reader.GetString(typeDef.Name);
                string ns = reader.GetString(typeDef.Namespace);
                return string.Equals(name, "DebuggableAttribute", StringComparison.Ordinal) &&
                       string.Equals(ns, "System.Diagnostics", StringComparison.Ordinal);
            }

            return false;
        }

        private static string BuildDebuggableModesString(int modes)
        {
            List<string> labels = new List<string>();
            if ((modes & 0x00000001) != 0)
            {
                labels.Add("Default");
            }
            if ((modes & 0x00000002) != 0)
            {
                labels.Add("IgnoreSymbolStoreSequencePoints");
            }
            if ((modes & 0x00000004) != 0)
            {
                labels.Add("EnableEditAndContinue");
            }
            if ((modes & 0x00000100) != 0)
            {
                labels.Add("DisableOptimizations");
            }

            string hex = "0x" + modes.ToString("X8", System.Globalization.CultureInfo.InvariantCulture);
            if (labels.Count == 0)
            {
                return hex;
            }

            return hex + " (" + string.Join(", ", labels) + ")";
        }

        private void ResolveExportForwarderChains()
        {
            if (_exportEntries.Count == 0)
            {
                return;
            }

            ExportEntry[] resolved = ResolveExportForwarderChains(_exportEntries.ToArray(), _exportDllName, _filePath);
            _exportEntries.Clear();
            _exportEntries.AddRange(resolved);
        }

        private static ExportEntry[] ResolveExportForwarderChains(
            ExportEntry[] entries,
            string exportName,
            string filePath)
        {
            if (entries == null || entries.Length == 0)
            {
                return Array.Empty<ExportEntry>();
            }

            string moduleName = NormalizeModuleName(exportName);
            if (string.IsNullOrWhiteSpace(moduleName))
            {
                moduleName = NormalizeModuleName(Path.GetFileNameWithoutExtension(filePath ?? string.Empty));
            }

            Dictionary<string, ExportEntry> byName = new Dictionary<string, ExportEntry>(StringComparer.OrdinalIgnoreCase);
            Dictionary<uint, ExportEntry> byOrdinal = new Dictionary<uint, ExportEntry>();
            foreach (ExportEntry entry in entries)
            {
                if (!string.IsNullOrWhiteSpace(entry.Name))
                {
                    byName[entry.Name] = entry;
                }

                byOrdinal[entry.Ordinal] = entry;
            }

            ExportEntry[] resolved = new ExportEntry[entries.Length];
            for (int i = 0; i < entries.Length; i++)
            {
                ExportEntry entry = entries[i];
                if (!entry.IsForwarder || string.IsNullOrWhiteSpace(entry.Forwarder))
                {
                    resolved[i] = entry;
                    continue;
                }

                ResolveForwarderChain(entry.Forwarder, moduleName, byName, byOrdinal, out string target, out string[] chain, out bool hasCycle, out bool resolvedTarget);
                resolved[i] = new ExportEntry(
                    entry.Name,
                    entry.Ordinal,
                    entry.AddressRva,
                    entry.IsForwarder,
                    entry.Forwarder,
                    target,
                    chain,
                    hasCycle,
                    resolvedTarget);
            }

            return resolved;
        }

        internal static ExportEntry[] ResolveExportForwarderChainsForTest(
            ExportEntry[] entries,
            string exportName,
            string filePath)
        {
            return ResolveExportForwarderChains(entries, exportName, filePath);
        }

        private static void ResolveForwarderChain(
            string forwarder,
            string moduleName,
            Dictionary<string, ExportEntry> byName,
            Dictionary<uint, ExportEntry> byOrdinal,
            out string target,
            out string[] chain,
            out bool hasCycle,
            out bool resolvedTarget)
        {
            List<string> steps = new List<string>();
            HashSet<string> visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            hasCycle = false;
            target = forwarder ?? string.Empty;
            resolvedTarget = false;

            string currentForwarder = forwarder;
            int maxDepth = 16;
            for (int depth = 0; depth < maxDepth; depth++)
            {
                if (!TryParseForwarderTarget(currentForwarder, out string module, out string symbol))
                {
                    break;
                }

                string normalizedModule = NormalizeModuleName(module);
                string step = normalizedModule.Length == 0 ? symbol : normalizedModule + "!" + symbol;
                if (!visited.Add(step))
                {
                    hasCycle = true;
                    break;
                }

                steps.Add(step);
                target = step;

                if (string.IsNullOrWhiteSpace(moduleName) ||
                    !string.Equals(normalizedModule, moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    resolvedTarget = true;
                    break;
                }

                ExportEntry next;
                if (TryParseForwarderOrdinal(symbol, out uint ordinal))
                {
                    if (!byOrdinal.TryGetValue(ordinal, out next))
                    {
                        resolvedTarget = false;
                        break;
                    }
                }
                else
                {
                    if (!byName.TryGetValue(symbol, out next))
                    {
                        resolvedTarget = false;
                        break;
                    }
                }

                if (!next.IsForwarder || string.IsNullOrWhiteSpace(next.Forwarder))
                {
                    resolvedTarget = true;
                    break;
                }

                currentForwarder = next.Forwarder;
            }

            chain = steps.ToArray();
        }

        private static bool TryParseForwarderTarget(string forwarder, out string module, out string symbol)
        {
            module = string.Empty;
            symbol = string.Empty;
            if (string.IsNullOrWhiteSpace(forwarder))
            {
                return false;
            }

            int dot = forwarder.LastIndexOf('.');
            if (dot <= 0 || dot >= forwarder.Length - 1)
            {
                return false;
            }

            module = forwarder.Substring(0, dot);
            symbol = forwarder.Substring(dot + 1);
            return true;
        }

        private static bool TryParseForwarderOrdinal(string symbol, out uint ordinal)
        {
            ordinal = 0;
            if (string.IsNullOrWhiteSpace(symbol) || symbol.Length < 2 || symbol[0] != '#')
            {
                return false;
            }

            return uint.TryParse(symbol.Substring(1), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out ordinal);
        }

        private static string NormalizeModuleName(string module)
        {
            if (string.IsNullOrWhiteSpace(module))
            {
                return string.Empty;
            }

            string trimmed = module.Trim();
            string fileName = Path.GetFileNameWithoutExtension(trimmed);
            if (string.IsNullOrWhiteSpace(fileName))
            {
                fileName = trimmed;
            }

            return fileName;
        }

        private void ValidateImportExportConsistency()
        {
            if (_importEntries.Count > 0)
            {
                var groups = _importEntries
                    .GroupBy(e => e.DllName, StringComparer.OrdinalIgnoreCase);

                foreach (var group in groups)
                {
                    int intCount = group.Count(e => e.Source == ImportThunkSource.ImportNameTable);
                    int iatCount = group.Count(e => e.Source == ImportThunkSource.ImportAddressTable);
                    if (intCount > 0 && iatCount > 0 && intCount != iatCount)
                    {
                        Warn(ParseIssueCategory.Imports, $"Import INT/IAT count mismatch for {group.Key} (INT={intCount}, IAT={iatCount}).");
                    }
                }
            }

            if (_exportEntries.Count > 0 && _sizeOfImage > 0)
            {
                foreach (ExportEntry entry in _exportEntries)
                {
                    if (!entry.IsForwarder && entry.AddressRva != 0 && entry.AddressRva >= _sizeOfImage)
                    {
                        Warn(ParseIssueCategory.Exports, $"Export {entry.Name} RVA outside SizeOfImage.");
                    }

                    if (entry.IsForwarder && !entry.ForwarderResolved)
                    {
                        Warn(ParseIssueCategory.Exports, $"Forwarder target could not be resolved for export {entry.Name}.");
                    }

                    if (entry.IsForwarder && entry.ForwarderHasCycle)
                    {
                        Warn(ParseIssueCategory.Exports, $"Forwarder chain has a cycle for export {entry.Name}.");
                    }
                }
            }

            ComputeExportAnomalies();
        }

        private void ComputeExportAnomalies()
        {
            if (_exportEntries.Count == 0 && _exportOrdinalOutOfRangeCount == 0)
            {
                _exportAnomalies = new ExportAnomalySummary(0, 0, 0, 0);
                return;
            }

            Dictionary<string, int> nameCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            Dictionary<uint, int> ordinalCounts = new Dictionary<uint, int>();
            int forwarderMissingTargets = 0;
            foreach (ExportEntry entry in _exportEntries)
            {
                if (!string.IsNullOrWhiteSpace(entry.Name))
                {
                    nameCounts[entry.Name] = nameCounts.TryGetValue(entry.Name, out int count) ? count + 1 : 1;
                }

                ordinalCounts[entry.Ordinal] = ordinalCounts.TryGetValue(entry.Ordinal, out int ordCount) ? ordCount + 1 : 1;

                if (entry.IsForwarder && !string.IsNullOrWhiteSpace(entry.Forwarder))
                {
                    if (!TryParseForwarderTarget(entry.Forwarder, out string module, out _))
                    {
                        forwarderMissingTargets++;
                        continue;
                    }

                    string normalizedModule = NormalizeModuleName(module);
                    if (string.IsNullOrWhiteSpace(normalizedModule))
                    {
                        forwarderMissingTargets++;
                        continue;
                    }

                    if (IsApiSetName(normalizedModule))
                    {
                        ApiSetResolutionInfo resolution = ResolveApiSetResolution(normalizedModule);
                        if (!resolution.IsResolved || resolution.CanonicalTargets == null || resolution.CanonicalTargets.Count == 0)
                        {
                            forwarderMissingTargets++;
                        }
                    }
                }
            }

            int duplicateNameCount = nameCounts.Count(pair => pair.Value > 1);
            int duplicateOrdinalCount = ordinalCounts.Count(pair => pair.Value > 1);
            if (duplicateNameCount > 0)
            {
                Warn(ParseIssueCategory.Exports, $"Duplicate export names detected: {duplicateNameCount}.");
            }

            if (duplicateOrdinalCount > 0)
            {
                Warn(ParseIssueCategory.Exports, $"Duplicate export ordinals detected: {duplicateOrdinalCount}.");
            }

            if (_exportOrdinalOutOfRangeCount > 0)
            {
                Warn(ParseIssueCategory.Exports, $"Export name ordinals outside export address table: {_exportOrdinalOutOfRangeCount}.");
            }

            if (forwarderMissingTargets > 0)
            {
                Warn(ParseIssueCategory.Exports, $"Forwarder target modules could not be resolved: {forwarderMissingTargets}.");
            }

            _exportAnomalies = new ExportAnomalySummary(
                duplicateNameCount,
                duplicateOrdinalCount,
                _exportOrdinalOutOfRangeCount,
                forwarderMissingTargets);
        }

        internal static ExportAnomalySummary ComputeExportAnomaliesForTest(
            IEnumerable<ExportEntry> entries,
            int ordinalOutOfRangeCount,
            int forwarderMissingTargetCount)
        {
            Dictionary<string, int> nameCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            Dictionary<uint, int> ordinalCounts = new Dictionary<uint, int>();
            if (entries != null)
            {
                foreach (ExportEntry entry in entries)
                {
                    if (!string.IsNullOrWhiteSpace(entry.Name))
                    {
                        nameCounts[entry.Name] = nameCounts.TryGetValue(entry.Name, out int count) ? count + 1 : 1;
                    }

                    ordinalCounts[entry.Ordinal] = ordinalCounts.TryGetValue(entry.Ordinal, out int ordCount) ? ordCount + 1 : 1;
                }
            }

            int duplicateNameCount = nameCounts.Count(pair => pair.Value > 1);
            int duplicateOrdinalCount = ordinalCounts.Count(pair => pair.Value > 1);
            return new ExportAnomalySummary(
                duplicateNameCount,
                duplicateOrdinalCount,
                ordinalOutOfRangeCount,
                forwarderMissingTargetCount);
        }

        private void ValidateRelocationHints()
        {
            if (_dllCharacteristicsInfo == null)
            {
                return;
            }

            if (_options != null && _options.LazyParseDataDirectories && !_relocationsParsed)
            {
                return;
            }

            bool dynamicBase = (_dllCharacteristicsInfo.Value & (ushort)DllCharacteristics.IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE) != 0;
            if (dynamicBase && _baseRelocations.Count == 0)
            {
                Warn(ParseIssueCategory.Relocations, "DYNAMIC_BASE is set but no base relocation blocks were found.");
            }
            else if (!dynamicBase && _baseRelocations.Count > 0)
            {
                Warn(ParseIssueCategory.Relocations, "Base relocation blocks present but DYNAMIC_BASE is not set.");
            }
        }

        private void ComputeDotNetRuntimeHint()
        {
            if (!_isDotNetFile)
            {
                _dotNetRuntimeHint = string.Empty;
                return;
            }

            if (_clrMetadata == null)
            {
                _dotNetRuntimeHint = _hasClrDirectory && _options != null && _options.LazyParseDataDirectories
                    ? "CLR (metadata deferred)"
                    : "CLR (metadata unavailable)";
                return;
            }

            if (_readyToRun != null)
            {
                _dotNetRuntimeHint = "ReadyToRun";
            }
            else if (_clrMetadata.IlOnly)
            {
                _dotNetRuntimeHint = "IL";
            }
            else
            {
                _dotNetRuntimeHint = "Mixed";
            }
        }

        private void BuildImportDescriptorInfos()
        {
            _importDescriptors.Clear();
            if (_importDescriptorInternals.Count == 0)
            {
                return;
            }

            Dictionary<string, uint> boundByDll = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
            foreach (BoundImportEntry bound in _boundImports)
            {
                if (!string.IsNullOrWhiteSpace(bound.DllName))
                {
                    boundByDll[bound.DllName] = bound.TimeDateStamp;
                }
            }

            Dictionary<string, (HashSet<string> IntSet, HashSet<string> IatSet)> byDll =
                new Dictionary<string, (HashSet<string>, HashSet<string>)>(StringComparer.OrdinalIgnoreCase);

            foreach (ImportEntry entry in _importEntries)
            {
                if (string.IsNullOrWhiteSpace(entry.DllName))
                {
                    continue;
                }

                if (!byDll.TryGetValue(entry.DllName, out var sets))
                {
                    sets = (new HashSet<string>(StringComparer.OrdinalIgnoreCase), new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                    byDll[entry.DllName] = sets;
                }

                string key = entry.IsByOrdinal
                    ? "#" + entry.Ordinal.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    : entry.Name ?? string.Empty;

                if (string.IsNullOrWhiteSpace(key))
                {
                    continue;
                }

                if (entry.Source == ImportThunkSource.ImportNameTable)
                {
                    sets.IntSet.Add(key);
                }
                else
                {
                    sets.IatSet.Add(key);
                }
            }

            foreach (ImportDescriptorInternal descriptor in _importDescriptorInternals)
            {
                if (string.IsNullOrWhiteSpace(descriptor.DllName))
                {
                    continue;
                }

                byDll.TryGetValue(descriptor.DllName, out var sets);
                HashSet<string> intSet = sets.IntSet ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                HashSet<string> iatSet = sets.IatSet ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                string[] intOnly = BuildLimitedList(intSet.Except(iatSet), 128);
                string[] iatOnly = BuildLimitedList(iatSet.Except(intSet), 128);

                int intCount = intSet.Count;
                int iatCount = iatSet.Count;

                bool isBound = descriptor.TimeDateStamp != 0;
                uint boundTimestamp = 0;
                bool hasBound = boundByDll.TryGetValue(descriptor.DllName, out boundTimestamp);
                bool isStale = isBound && hasBound && boundTimestamp != descriptor.TimeDateStamp;

                if (intOnly.Length > 0 || iatOnly.Length > 0)
                {
                    Warn(ParseIssueCategory.Imports, $"Import INT/IAT mismatch for {descriptor.DllName} (INT-only={intOnly.Length}, IAT-only={iatOnly.Length}).");
                }

                if (descriptor.IntNullThunkCount > 0)
                {
                    Warn(ParseIssueCategory.Imports, $"Import INT contains {descriptor.IntNullThunkCount} null thunk(s) for {descriptor.DllName}.");
                }

                if (descriptor.IatNullThunkCount > 0)
                {
                    Warn(ParseIssueCategory.Imports, $"Import IAT contains {descriptor.IatNullThunkCount} null thunk(s) for {descriptor.DllName}.");
                }

                if (isBound && !hasBound)
                {
                    Warn(ParseIssueCategory.Imports, $"Import {descriptor.DllName} is marked bound but no bound import entry was found.");
                }
                else if (isStale)
                {
                    Warn(ParseIssueCategory.Imports, $"Bound import for {descriptor.DllName} is stale (timestamp mismatch).");
                }

                ApiSetResolutionInfo apiSetResolution = ResolveApiSetResolution(descriptor.DllName);
                if (apiSetResolution.IsApiSet && !apiSetResolution.IsResolved)
                {
                    Warn(ParseIssueCategory.Imports, $"API set import {descriptor.DllName} could not be resolved.");
                }

                _importDescriptors.Add(new ImportDescriptorInfo(
                    descriptor.DllName,
                    descriptor.TimeDateStamp,
                    descriptor.ImportNameTableRva,
                    descriptor.ImportAddressTableRva,
                    isBound,
                    boundTimestamp,
                    isStale,
                    intCount,
                    iatCount,
                    descriptor.IntNullThunkCount,
                    descriptor.IatNullThunkCount,
                    descriptor.IntTerminated,
                    descriptor.IatTerminated,
                    intOnly,
                    iatOnly,
                    apiSetResolution));
            }
        }

        private static string[] BuildLimitedList(IEnumerable<string> items, int maxItems)
        {
            if (items == null)
            {
                return Array.Empty<string>();
            }

            List<string> list = new List<string>();
            foreach (string item in items.OrderBy(v => v, StringComparer.OrdinalIgnoreCase))
            {
                if (list.Count >= maxItems)
                {
                    break;
                }

                list.Add(item);
            }

            return list.ToArray();
        }

        private static bool TryGetTypeName(MetadataReader reader, EntityHandle handle, out string name, out string ns)
        {
            name = string.Empty;
            ns = string.Empty;

            if (handle.Kind == HandleKind.TypeReference)
            {
                TypeReference typeRef = reader.GetTypeReference((TypeReferenceHandle)handle);
                name = reader.GetString(typeRef.Name);
                ns = reader.GetString(typeRef.Namespace);
                return true;
            }

            if (handle.Kind == HandleKind.TypeDefinition)
            {
                TypeDefinition typeDef = reader.GetTypeDefinition((TypeDefinitionHandle)handle);
                name = reader.GetString(typeDef.Name);
                ns = reader.GetString(typeDef.Namespace);
                return true;
            }

            return false;
        }

        private static string ToHex(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return string.Empty;
            }

            StringBuilder sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
            {
                sb.Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        private ParseIssueSeverity ResolveSeverity(ParseIssueCategory category, ParseIssueSeverity defaultSeverity)
        {
            if (_options != null)
            {
                if (_options.IssuePolicy != null &&
                    _options.IssuePolicy.TryGetValue(category, out ParseIssueSeverity policySeverity))
                {
                    return policySeverity;
                }

                if (_options.ValidationProfile != ValidationProfile.Default &&
                    TryGetProfileSeverity(_options.ValidationProfile, category, defaultSeverity, out ParseIssueSeverity profileSeverity))
                {
                    defaultSeverity = profileSeverity;
                }

                if (_options.StrictMode && defaultSeverity == ParseIssueSeverity.Warning)
                {
                    return ParseIssueSeverity.Error;
                }
            }

            return defaultSeverity;
        }

        private static bool TryGetProfileSeverity(
            ValidationProfile profile,
            ParseIssueCategory category,
            ParseIssueSeverity defaultSeverity,
            out ParseIssueSeverity result)
        {
            result = defaultSeverity;
            if (defaultSeverity == ParseIssueSeverity.Ignore)
            {
                return false;
            }

            switch (profile)
            {
                case ValidationProfile.Strict:
                    if (defaultSeverity == ParseIssueSeverity.Warning &&
                        (category == ParseIssueCategory.Header ||
                         category == ParseIssueCategory.OptionalHeader ||
                         category == ParseIssueCategory.Sections ||
                         category == ParseIssueCategory.Imports ||
                         category == ParseIssueCategory.Exports ||
                         category == ParseIssueCategory.Resources ||
                         category == ParseIssueCategory.Relocations ||
                         category == ParseIssueCategory.CLR ||
                         category == ParseIssueCategory.Metadata ||
                         category == ParseIssueCategory.Checksum ||
                         category == ParseIssueCategory.Authenticode))
                    {
                        result = ParseIssueSeverity.Error;
                        return true;
                    }
                    break;
                case ValidationProfile.Compatibility:
                    if (defaultSeverity == ParseIssueSeverity.Error &&
                        (category == ParseIssueCategory.Resources ||
                         category == ParseIssueCategory.Debug ||
                         category == ParseIssueCategory.Relocations ||
                         category == ParseIssueCategory.Authenticode ||
                         category == ParseIssueCategory.Checksum ||
                         category == ParseIssueCategory.AssemblyAnalysis))
                    {
                        result = ParseIssueSeverity.Warning;
                        return true;
                    }
                    break;
                case ValidationProfile.Forensic:
                    if (defaultSeverity == ParseIssueSeverity.Error &&
                        (category == ParseIssueCategory.Resources ||
                         category == ParseIssueCategory.Debug ||
                         category == ParseIssueCategory.Relocations ||
                         category == ParseIssueCategory.Authenticode ||
                         category == ParseIssueCategory.Checksum ||
                         category == ParseIssueCategory.AssemblyAnalysis ||
                         category == ParseIssueCategory.Imports ||
                         category == ParseIssueCategory.Exports))
                    {
                        result = ParseIssueSeverity.Warning;
                        return true;
                    }
                    break;
            }

            return false;
        }

        private void Fail(string message)
        {
            Fail(ParseIssueCategory.General, message);
        }

        private void Warn(string message)
        {
            Warn(ParseIssueCategory.General, message);
        }

        private void Fail(ParseIssueCategory category, string message)
        {
            ParseIssueSeverity severity = ResolveSeverity(category, ParseIssueSeverity.Error);
            _parseResult.AddIssue(category, severity, message);
            NotifyIssue(category, severity, message);
            if (severity == ParseIssueSeverity.Error && _options != null && _options.StrictMode)
            {
                throw new PECOFFParseException(message);
            }
        }

        private void Warn(ParseIssueCategory category, string message)
        {
            if (string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            ParseIssueSeverity severity = ResolveSeverity(category, ParseIssueSeverity.Warning);
            _parseResult.AddIssue(category, severity, message);
            NotifyIssue(category, severity, message);
            if (severity == ParseIssueSeverity.Error && _options != null && _options.StrictMode)
            {
                throw new PECOFFParseException(message);
            }
        }

        private void NotifyIssue(ParseIssueCategory category, ParseIssueSeverity severity, string message)
        {
            if (_options?.IssueCallback == null || severity == ParseIssueSeverity.Ignore || string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            _options.IssueCallback(new ParseIssue(category, severity, message));
        }

        private void WarnAt(ParseIssueCategory category, string message, long fileOffset)
        {
            string decorated = string.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                "{0} (FileOffset=0x{1:X})",
                message,
                fileOffset);
            Warn(category, decorated);
        }

        private void ParseTeImage()
        {
            _imageKind = "TE";
            _coffObjectInfo = null;
            _coffArchiveInfo = null;
            _teImageInfo = null;
            _catalogSignatureInfo = null;
            _dosRelocationInfo = null;

            if (PEFileStream == null || PEFile == null)
            {
                Fail(ParseIssueCategory.File, "No PE file stream available.");
                return;
            }

            int headerSize = Marshal.SizeOf(typeof(EFI_TE_IMAGE_HEADER));
            if (!TrySetPosition(0, headerSize))
            {
                Fail(ParseIssueCategory.Header, "TE header exceeds file bounds.");
                return;
            }

            byte[] buffer = new byte[headerSize];
            ReadExactly(PEFileStream, buffer, 0, buffer.Length);
            EFI_TE_IMAGE_HEADER teHeader = ByteArrayToStructure<EFI_TE_IMAGE_HEADER>(buffer);
            if (teHeader.Signature != EFI_TE_SIGNATURE)
            {
                Fail(ParseIssueCategory.Header, "Invalid TE signature.");
                return;
            }

            if (teHeader.StrippedSize < headerSize)
            {
                Warn(ParseIssueCategory.Header, "TE stripped size is smaller than the TE header size.");
            }

            _machineType = (MachineTypes)teHeader.Machine;
            _timeDateStamp = 0;
            _fileAlignment = 0;
            _sectionAlignment = 0;
            _imageBase = teHeader.ImageBase;
            _sizeOfImage = 0;
            _sizeOfCode = 0;
            _sizeOfInitializedData = 0;
            _numberOfRvaAndSizes = 0;
            _sizeOfHeaders = teHeader.StrippedSize;
            _optionalHeaderChecksum = 0;
            _subsystemInfo = BuildSubsystemInfo((Subsystem)teHeader.Subsystem);
            _dllCharacteristicsInfo = null;
            _securityFeaturesInfo = null;
            _dataDirectories = Array.Empty<IMAGE_DATA_DIRECTORY>();
            _dataDirectoryInfos = Array.Empty<DataDirectoryInfo>();
            _architectureDirectory = null;
            _globalPtrDirectory = null;
            _iatDirectory = null;
            _hasResourceDirectory = false;
            _hasRelocationDirectory = false;
            _hasDebugDirectory = false;
            _hasExceptionDirectory = false;
            _hasLoadConfigDirectory = false;
            _hasClrDirectory = false;
            _resourcesParsed = true;
            _debugParsed = true;
            _relocationsParsed = true;
            _exceptionParsed = true;
            _loadConfigParsed = true;
            _clrParsed = true;
            _peHeaderIsPe32Plus = false;

            List<IMAGE_SECTION_HEADER> sections = new List<IMAGE_SECTION_HEADER>();
            int sectionCount = teHeader.NumberOfSections;
            int sectionTableSize = sectionCount * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            long sectionTableOffset = headerSize;
            if (sectionCount > 0)
            {
                if (!TrySetPosition(sectionTableOffset, sectionTableSize))
                {
                    Fail(ParseIssueCategory.Sections, "TE section table exceeds file bounds.");
                    return;
                }

                for (int i = 0; i < sectionCount; i++)
                {
                    sections.Add(new IMAGE_SECTION_HEADER(PEFile));
                }
            }

            _sections = sections;
            ValidateSectionNameEncoding(sections);
            if (sections.Count > 0)
            {
                uint maxEnd = 0;
                foreach (IMAGE_SECTION_HEADER section in sections)
                {
                    uint span = GetSectionSpan(section);
                    uint end = section.VirtualAddress + span;
                    if (end > maxEnd)
                    {
                        maxEnd = end;
                    }
                }
                _sizeOfImage = maxEnd;
            }

            bool entryPointFileOffsetValid = teHeader.AddressOfEntryPoint >= teHeader.StrippedSize;
            uint entryPointFileOffset = entryPointFileOffsetValid ? teHeader.AddressOfEntryPoint - teHeader.StrippedSize : 0;
            bool baseOfCodeFileOffsetValid = teHeader.BaseOfCode >= teHeader.StrippedSize;
            uint baseOfCodeFileOffset = baseOfCodeFileOffsetValid ? teHeader.BaseOfCode - teHeader.StrippedSize : 0;

            if (!entryPointFileOffsetValid && teHeader.AddressOfEntryPoint > 0)
            {
                Warn(ParseIssueCategory.Header, "TE entry point is before the stripped header.");
            }
            if (!baseOfCodeFileOffsetValid && teHeader.BaseOfCode > 0)
            {
                Warn(ParseIssueCategory.Header, "TE base of code is before the stripped header.");
            }

            bool entryPointMapped = false;
            string entryPointSectionName = string.Empty;
            if (teHeader.AddressOfEntryPoint != 0 && TryGetSectionByRva(sections, teHeader.AddressOfEntryPoint, out IMAGE_SECTION_HEADER entrySection))
            {
                entryPointMapped = true;
                entryPointSectionName = NormalizeSectionName(entrySection.Section);
            }
            else if (teHeader.AddressOfEntryPoint != 0 && sections.Count > 0)
            {
                Warn(ParseIssueCategory.Sections, "TE entry point RVA is not mapped to a section.");
            }

            bool baseOfCodeMapped = false;
            string baseOfCodeSectionName = string.Empty;
            if (teHeader.BaseOfCode != 0 && TryGetSectionByRva(sections, teHeader.BaseOfCode, out IMAGE_SECTION_HEADER baseSection))
            {
                baseOfCodeMapped = true;
                baseOfCodeSectionName = NormalizeSectionName(baseSection.Section);
            }
            else if (teHeader.BaseOfCode != 0 && sections.Count > 0)
            {
                Warn(ParseIssueCategory.Sections, "TE base of code RVA is not mapped to a section.");
            }
            BuildSectionPermissionInfos(sections);
            ComputeOverlayInfo(sections);
            ComputeSectionEntropies(sections);
            ComputePackingHints(sections);

            _baseRelocations.Clear();
            _baseRelocationSections.Clear();
            _relocationAnomalies = new RelocationAnomalySummary(0, 0, 0, 0, 0, 0, 0, 0);
            if (teHeader.BaseRelocationTable.Size > 0 && teHeader.BaseRelocationTable.VirtualAddress > 0)
            {
                _hasRelocationDirectory = true;
                _relocationsParsed = false;
                ParseBaseRelocationTable(teHeader.BaseRelocationTable, sections);
                _relocationsParsed = true;
            }

            SubsystemInfo subsystemInfo = _subsystemInfo;
            TeDataDirectoryInfo[] directories = new[]
            {
                new TeDataDirectoryInfo(
                    "BaseRelocation",
                    teHeader.BaseRelocationTable.VirtualAddress,
                    teHeader.BaseRelocationTable.Size,
                    teHeader.BaseRelocationTable.Size > 0),
                new TeDataDirectoryInfo(
                    "Debug",
                    teHeader.DebugTable.VirtualAddress,
                    teHeader.DebugTable.Size,
                    teHeader.DebugTable.Size > 0)
            };

            _teImageInfo = new TeImageInfo(
                teHeader.Machine,
                GetMachineName(teHeader.Machine),
                teHeader.NumberOfSections,
                teHeader.Subsystem,
                subsystemInfo?.Name ?? string.Empty,
                teHeader.StrippedSize,
                (ushort)headerSize,
                (uint)sectionTableOffset,
                (uint)sectionTableSize,
                teHeader.AddressOfEntryPoint,
                teHeader.BaseOfCode,
                teHeader.ImageBase,
                entryPointFileOffset,
                baseOfCodeFileOffset,
                entryPointFileOffsetValid,
                baseOfCodeFileOffsetValid,
                entryPointMapped,
                baseOfCodeMapped,
                entryPointSectionName,
                baseOfCodeSectionName,
                directories);
        }

        private bool TryParseCoffArchive()
        {
            if (PEFileStream == null || PEFile == null)
            {
                return false;
            }

            if (!TrySetPosition(0, 8))
            {
                return false;
            }

            byte[] signatureBytes = new byte[8];
            ReadExactly(PEFileStream, signatureBytes, 0, signatureBytes.Length);
            string signature = Encoding.ASCII.GetString(signatureBytes);
            bool isThinArchive = string.Equals(signature, "!<thin>\n", StringComparison.Ordinal);
            if (!isThinArchive && !string.Equals(signature, "!<arch>\n", StringComparison.Ordinal))
            {
                return false;
            }

            _imageKind = "COFF-Archive";
            _coffObjectInfo = null;
            _coffArchiveInfo = null;
            _teImageInfo = null;
            _catalogSignatureInfo = null;
            _dosRelocationInfo = null;

            List<CoffArchiveMemberInfo> members = new List<CoffArchiveMemberInfo>();
            List<CoffArchiveSymbolTableInfo> symbolTables = new List<CoffArchiveSymbolTableInfo>();
            string longNameTable = null;
            int longNameTableSize = 0;

            long cursor = 8;
            int maxMembers = 4096;
            long fileLength = PEFileStream.Length;
            while (cursor + 60 <= fileLength && members.Count < maxMembers)
            {
                if (!TrySetPosition(cursor, 60))
                {
                    break;
                }

                byte[] header = new byte[60];
                ReadExactly(PEFileStream, header, 0, header.Length);
                string nameField = Encoding.ASCII.GetString(header, 0, 16);
                string dateField = Encoding.ASCII.GetString(header, 16, 12);
                string uidField = Encoding.ASCII.GetString(header, 28, 6);
                string gidField = Encoding.ASCII.GetString(header, 34, 6);
                string modeField = Encoding.ASCII.GetString(header, 40, 8);
                string sizeField = Encoding.ASCII.GetString(header, 48, 10);
                string endField = Encoding.ASCII.GetString(header, 58, 2);

                if (!string.Equals(endField, "`\n", StringComparison.Ordinal))
                {
                    Warn(ParseIssueCategory.Header, "COFF archive member header has invalid trailer.");
                    break;
                }

                long headerOffset = cursor;

                string name = NormalizeArchiveName(nameField, longNameTable);
                uint timeDateStamp = ParseArchiveUInt(dateField);
                int userId = ParseArchiveInt(uidField);
                int groupId = ParseArchiveInt(gidField);
                string mode = modeField.Trim();

                if (!TryParseArchiveSize(sizeField, out long size))
                {
                    Warn(ParseIssueCategory.Header, "COFF archive member size is invalid.");
                    break;
                }

                long dataOffset = cursor + 60;
                if (dataOffset < 0 || dataOffset > fileLength)
                {
                    Warn(ParseIssueCategory.Header, "COFF archive member data exceeds file bounds.");
                    break;
                }

                bool isGnuExtendedName = false;
                int extendedNameLength = 0;
                string nameFieldTrimmed = nameField.Trim();
                if (nameFieldTrimmed.StartsWith("#1/", StringComparison.Ordinal))
                {
                    string lengthText = nameFieldTrimmed.Substring(3).Trim();
                    if (int.TryParse(lengthText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedLength) && parsedLength > 0)
                    {
                        isGnuExtendedName = true;
                        extendedNameLength = parsedLength;
                    }
                }

                if (isGnuExtendedName)
                {
                    if (extendedNameLength > size)
                    {
                        Warn(ParseIssueCategory.Header, "COFF archive extended name length exceeds member size.");
                        extendedNameLength = 0;
                    }
                    else if (dataOffset + extendedNameLength > fileLength)
                    {
                        Warn(ParseIssueCategory.Header, "COFF archive extended name exceeds file bounds.");
                        extendedNameLength = 0;
                    }

                    if (extendedNameLength > 0)
                    {
                        byte[] nameBytes = new byte[extendedNameLength];
                        PEFileStream.Position = dataOffset;
                        ReadExactly(PEFileStream, nameBytes, 0, nameBytes.Length);
                        name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0', '/');
                        dataOffset += extendedNameLength;
                        size -= extendedNameLength;
                    }
                }
                else if (nameFieldTrimmed.StartsWith("/", StringComparison.Ordinal) &&
                         nameFieldTrimmed.Length > 1 &&
                         char.IsDigit(nameFieldTrimmed[1]) &&
                         string.IsNullOrWhiteSpace(longNameTable))
                {
                    Warn(ParseIssueCategory.Header, "COFF archive member references long name table but none was found.");
                }

                bool isSymbolTable = string.Equals(name, "/", StringComparison.Ordinal) ||
                                     string.Equals(name, "/SYM64", StringComparison.Ordinal);
                bool isLongNameTable = string.Equals(name, "//", StringComparison.Ordinal);

                CoffImportObjectInfo importObject = null;
                bool isImportObject = false;
                bool dataInArchive = true;
                long storedSize = size;

                if (!isThinArchive && dataOffset + size > fileLength)
                {
                    Warn(ParseIssueCategory.Header, "COFF archive member data exceeds file bounds.");
                    break;
                }

                if (isThinArchive && !isSymbolTable && !isLongNameTable)
                {
                    storedSize = 0;
                    dataInArchive = false;
                }

                if (storedSize > 0 && dataOffset + storedSize > fileLength)
                {
                    Warn(ParseIssueCategory.Header, "COFF archive member data exceeds file bounds.");
                    break;
                }

                if (isLongNameTable)
                {
                    if (storedSize > 0 && storedSize <= int.MaxValue)
                    {
                        byte[] data = new byte[storedSize];
                        PEFileStream.Position = dataOffset;
                        ReadExactly(PEFileStream, data, 0, data.Length);
                        longNameTable = Encoding.ASCII.GetString(data).TrimEnd('\0');
                        longNameTableSize = data.Length;
                    }
                }
                else if (isSymbolTable)
                {
                    if (storedSize > 0 && storedSize <= int.MaxValue)
                    {
                        byte[] data = new byte[storedSize];
                        PEFileStream.Position = dataOffset;
                        ReadExactly(PEFileStream, data, 0, data.Length);
                        if (TryParseArchiveSymbolTable(data, string.Equals(name, "/SYM64", StringComparison.Ordinal), out CoffArchiveSymbolTableInfo parsed))
                        {
                            symbolTables.Add(parsed);
                        }
                    }
                }
                else if (storedSize > 0)
                {
                    int previewSize = (int)Math.Min(storedSize, 512);
                    byte[] data = new byte[previewSize];
                    PEFileStream.Position = dataOffset;
                    ReadExactly(PEFileStream, data, 0, data.Length);
                    if (TryParseImportObject(data, out CoffImportObjectInfo parsed))
                    {
                        importObject = parsed;
                        isImportObject = true;
                        if (parsed.HasReservedFlags)
                        {
                            Warn(ParseIssueCategory.Header, $"SPEC violation: COFF import object reserved flag bits are non-zero for member {name} (0x{parsed.ReservedFlags:X4}).");
                        }
                    }
                }

                members.Add(new CoffArchiveMemberInfo(
                    name,
                    headerOffset,
                    dataOffset,
                    size,
                    timeDateStamp,
                    userId,
                    groupId,
                    mode,
                    isSymbolTable,
                    isLongNameTable,
                    isImportObject,
                    importObject,
                    dataInArchive));

                cursor = dataOffset + storedSize;
                if ((cursor & 1) == 1)
                {
                    cursor++;
                }
            }

            CoffArchiveSymbolTableInfo[] resolvedSymbolTables = ResolveArchiveSymbolTables(symbolTables, members);
            CoffArchiveSymbolTableInfo primarySymbolTable = resolvedSymbolTables.FirstOrDefault();
            _coffArchiveInfo = new CoffArchiveInfo(
                signature.TrimEnd('\0', ' '),
                members.Count,
                primarySymbolTable,
                resolvedSymbolTables,
                members.ToArray(),
                isThinArchive,
                !string.IsNullOrWhiteSpace(longNameTable),
                longNameTableSize);
            return true;
        }

        private static bool TryParseArchiveSize(string sizeField, out long size)
        {
            size = 0;
            if (string.IsNullOrWhiteSpace(sizeField))
            {
                return false;
            }

            string trimmed = sizeField.Trim();
            return long.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out size) && size >= 0;
        }

        private static uint ParseArchiveUInt(string field)
        {
            if (string.IsNullOrWhiteSpace(field))
            {
                return 0;
            }

            if (uint.TryParse(field.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out uint value))
            {
                return value;
            }

            return 0;
        }

        private static int ParseArchiveInt(string field)
        {
            if (string.IsNullOrWhiteSpace(field))
            {
                return 0;
            }

            if (int.TryParse(field.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
            {
                return value;
            }

            return 0;
        }

        private static string NormalizeArchiveName(string nameField, string longNameTable)
        {
            string name = nameField?.Trim() ?? string.Empty;
            if (name.Length == 0)
            {
                return string.Empty;
            }

            if (string.Equals(name, "/", StringComparison.Ordinal) ||
                string.Equals(name, "//", StringComparison.Ordinal) ||
                string.Equals(name, "/SYM64", StringComparison.Ordinal))
            {
                return name;
            }

            if (name[0] == '/' && name.Length > 1 && char.IsDigit(name[1]) && !string.IsNullOrWhiteSpace(longNameTable))
            {
                if (int.TryParse(name.Substring(1).Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int offset) &&
                    offset >= 0 &&
                    offset < longNameTable.Length)
                {
                    int end = longNameTable.IndexOf('/', offset);
                    if (end < 0)
                    {
                        end = longNameTable.Length;
                    }

                    return longNameTable.Substring(offset, end - offset);
                }
            }

            if (name.EndsWith("/", StringComparison.Ordinal))
            {
                name = name.Substring(0, name.Length - 1);
            }

            return name.Trim();
        }

        private static bool TryParseArchiveSymbolTable(byte[] data, bool isSym64, out CoffArchiveSymbolTableInfo info)
        {
            info = null;
            if (data == null)
            {
                return false;
            }

            if (TryParseArchiveFirstLinkerMember(data, isSym64, out info))
            {
                return true;
            }

            if (!isSym64 && TryParseArchiveSecondLinkerMember(data, out info))
            {
                return true;
            }

            return false;
        }

        private static bool TryParseArchiveFirstLinkerMember(byte[] data, bool isSym64, out CoffArchiveSymbolTableInfo info)
        {
            info = null;
            int headerSize = isSym64 ? 8 : 4;
            int offsetSize = isSym64 ? 8 : 4;
            if (data == null || data.Length < headerSize)
            {
                return false;
            }

            ulong symbolCountRaw = isSym64
                ? ReadUInt64BigEndian(data, 0)
                : ReadUInt32BigEndian(data, 0);
            ulong maxCountByData = (ulong)(data.Length - headerSize) / (ulong)offsetSize;
            if (symbolCountRaw > maxCountByData)
            {
                return false;
            }

            int symbolCount = symbolCountRaw > int.MaxValue ? int.MaxValue : (int)symbolCountRaw;
            long offsetsSize = (long)(symbolCountRaw * (ulong)offsetSize);
            int namesOffset = headerSize + (int)offsetsSize;
            int nameTableSize = data.Length - namesOffset;
            bool truncated = symbolCountRaw > int.MaxValue;
            const int maxReferences = 4096;
            int referencesToParse = (int)Math.Min(Math.Min((ulong)maxReferences, symbolCountRaw), (ulong)int.MaxValue);
            List<CoffArchiveSymbolReferenceInfo> references = new List<CoffArchiveSymbolReferenceInfo>(Math.Min(referencesToParse, 128));

            int nameCursor = namesOffset;
            for (int i = 0; i < referencesToParse; i++)
            {
                int offsetCursor = headerSize + (i * offsetSize);
                long memberOffset = isSym64
                    ? (long)Math.Min(ReadUInt64BigEndian(data, offsetCursor), long.MaxValue)
                    : ReadUInt32BigEndian(data, offsetCursor);

                if (!TryReadArchiveSymbolName(data, ref nameCursor, out string symbolName))
                {
                    truncated = true;
                    break;
                }

                if (string.IsNullOrWhiteSpace(symbolName))
                {
                    return false;
                }

                references.Add(new CoffArchiveSymbolReferenceInfo(
                    symbolName,
                    memberOffset,
                    false,
                    -1,
                    string.Empty));
            }

            bool referencesTruncated = truncated || references.Count < symbolCount;
            info = new CoffArchiveSymbolTableInfo(
                symbolCount,
                nameTableSize,
                isSym64,
                truncated,
                isSym64 ? "FirstLinkerMember64" : "FirstLinkerMember",
                references.Count,
                referencesTruncated,
                references.ToArray());
            return true;
        }

        private static bool TryParseArchiveSecondLinkerMember(byte[] data, out CoffArchiveSymbolTableInfo info)
        {
            info = null;
            if (data == null || data.Length < 12)
            {
                return false;
            }

            uint memberCountRaw = ReadUInt32BigEndian(data, 0);
            ulong memberOffsetsBytes = (ulong)memberCountRaw * 4;
            if (memberOffsetsBytes > (ulong)(data.Length - 4))
            {
                return false;
            }

            int cursor = 4;
            const int maxMemberOffsets = 8192;
            int memberOffsetsToRead = (int)Math.Min((ulong)maxMemberOffsets, memberCountRaw);
            uint[] memberOffsets = new uint[memberOffsetsToRead];
            for (int i = 0; i < memberOffsetsToRead; i++)
            {
                memberOffsets[i] = ReadUInt32BigEndian(data, cursor);
                cursor += 4;
            }
            if (memberCountRaw > (uint)memberOffsetsToRead)
            {
                cursor += (int)((memberCountRaw - (uint)memberOffsetsToRead) * 4);
            }

            if (cursor + 4 > data.Length)
            {
                return false;
            }

            uint symbolCountRaw = ReadUInt32BigEndian(data, cursor);
            cursor += 4;
            ulong indicesBytes = (ulong)symbolCountRaw * 2;
            if (indicesBytes > (ulong)(data.Length - cursor))
            {
                return false;
            }

            int indicesOffset = cursor;
            int namesOffset = cursor + (int)indicesBytes;
            int nameTableSize = data.Length - namesOffset;
            bool truncated = symbolCountRaw > int.MaxValue || memberCountRaw > maxMemberOffsets;
            int symbolCount = symbolCountRaw > int.MaxValue ? int.MaxValue : (int)symbolCountRaw;
            const int maxReferences = 4096;
            int referencesToParse = (int)Math.Min(Math.Min((ulong)maxReferences, symbolCountRaw), (ulong)int.MaxValue);
            List<CoffArchiveSymbolReferenceInfo> references = new List<CoffArchiveSymbolReferenceInfo>(Math.Min(referencesToParse, 128));

            int nameCursor = namesOffset;
            for (int i = 0; i < referencesToParse; i++)
            {
                ushort rawMemberIndex = ReadUInt16BigEndian(data, indicesOffset + (i * 2));
                long memberOffset = 0;
                if (rawMemberIndex > 0 && rawMemberIndex <= memberOffsets.Length)
                {
                    memberOffset = memberOffsets[rawMemberIndex - 1];
                }
                else if (rawMemberIndex < memberOffsets.Length)
                {
                    memberOffset = memberOffsets[rawMemberIndex];
                }
                else
                {
                    truncated = true;
                }

                if (!TryReadArchiveSymbolName(data, ref nameCursor, out string symbolName))
                {
                    truncated = true;
                    break;
                }

                if (string.IsNullOrWhiteSpace(symbolName))
                {
                    truncated = true;
                    break;
                }

                references.Add(new CoffArchiveSymbolReferenceInfo(
                    symbolName,
                    memberOffset,
                    false,
                    -1,
                    string.Empty));
            }

            bool referencesTruncated = truncated || references.Count < symbolCount;
            info = new CoffArchiveSymbolTableInfo(
                symbolCount,
                nameTableSize,
                false,
                truncated,
                "SecondLinkerMember",
                references.Count,
                referencesTruncated,
                references.ToArray());
            return true;
        }

        private static bool TryReadArchiveSymbolName(byte[] data, ref int cursor, out string name)
        {
            name = string.Empty;
            if (data == null || cursor < 0 || cursor >= data.Length)
            {
                return false;
            }

            int start = cursor;
            while (cursor < data.Length && data[cursor] != 0)
            {
                cursor++;
            }

            if (cursor > data.Length)
            {
                return false;
            }

            int length = cursor - start;
            name = length > 0
                ? Encoding.ASCII.GetString(data, start, length)
                : string.Empty;
            if (cursor < data.Length)
            {
                cursor++;
            }

            return true;
        }

        private static CoffArchiveSymbolTableInfo[] ResolveArchiveSymbolTables(
            List<CoffArchiveSymbolTableInfo> symbolTables,
            List<CoffArchiveMemberInfo> members)
        {
            if (symbolTables == null || symbolTables.Count == 0)
            {
                return Array.Empty<CoffArchiveSymbolTableInfo>();
            }

            CoffArchiveMemberInfo[] memberArray = members?.ToArray() ?? Array.Empty<CoffArchiveMemberInfo>();
            CoffArchiveSymbolTableInfo[] resolved = new CoffArchiveSymbolTableInfo[symbolTables.Count];
            for (int i = 0; i < symbolTables.Count; i++)
            {
                resolved[i] = ResolveArchiveSymbolTable(symbolTables[i], memberArray);
            }

            return resolved;
        }

        private static CoffArchiveSymbolTableInfo ResolveArchiveSymbolTable(
            CoffArchiveSymbolTableInfo table,
            IReadOnlyList<CoffArchiveMemberInfo> members)
        {
            if (table == null || table.References == null || table.References.Count == 0 || members == null || members.Count == 0)
            {
                return table;
            }

            Dictionary<long, (int Index, string Name)> byHeaderOffset = new Dictionary<long, (int, string)>();
            Dictionary<long, (int Index, string Name)> byDataOffset = new Dictionary<long, (int, string)>();
            for (int i = 0; i < members.Count; i++)
            {
                CoffArchiveMemberInfo member = members[i];
                if (member == null)
                {
                    continue;
                }

                if (member.HeaderOffset >= 0 && !byHeaderOffset.ContainsKey(member.HeaderOffset))
                {
                    byHeaderOffset[member.HeaderOffset] = (i, member.Name ?? string.Empty);
                }

                if (member.DataOffset >= 0 && !byDataOffset.ContainsKey(member.DataOffset))
                {
                    byDataOffset[member.DataOffset] = (i, member.Name ?? string.Empty);
                }
            }

            CoffArchiveSymbolReferenceInfo[] refs = new CoffArchiveSymbolReferenceInfo[table.References.Count];
            for (int i = 0; i < table.References.Count; i++)
            {
                CoffArchiveSymbolReferenceInfo entry = table.References[i];
                bool found = false;
                int memberIndex = -1;
                string memberName = string.Empty;
                if (entry != null)
                {
                    if (byHeaderOffset.TryGetValue(entry.MemberOffset, out (int Index, string Name) headerHit))
                    {
                        found = true;
                        memberIndex = headerHit.Index;
                        memberName = headerHit.Name;
                    }
                    else if (byDataOffset.TryGetValue(entry.MemberOffset, out (int Index, string Name) dataHit))
                    {
                        found = true;
                        memberIndex = dataHit.Index;
                        memberName = dataHit.Name;
                    }
                }

                refs[i] = new CoffArchiveSymbolReferenceInfo(
                    entry?.Name ?? string.Empty,
                    entry?.MemberOffset ?? 0,
                    found,
                    memberIndex,
                    memberName);
            }

            return new CoffArchiveSymbolTableInfo(
                table.SymbolCount,
                table.NameTableSize,
                table.Is64Bit,
                table.IsTruncated,
                table.Format,
                table.ParsedReferenceCount,
                table.ReferencesTruncated,
                refs);
        }

        private static bool TryParseImportObject(ReadOnlySpan<byte> data, out CoffImportObjectInfo info)
        {
            info = null;
            if (data.Length < 20)
            {
                return false;
            }

            ushort sig1 = ReadUInt16(data, 0);
            ushort sig2 = ReadUInt16(data, 2);
            if (sig1 != 0 || sig2 != 0xFFFF)
            {
                return false;
            }

            ushort version = ReadUInt16(data, 4);
            ushort machine = ReadUInt16(data, 6);
            uint timeDateStamp = ReadUInt32(data, 8);
            uint sizeOfData = ReadUInt32(data, 12);
            ushort ordinalOrHint = ReadUInt16(data, 16);
            ushort flags = ReadUInt16(data, 18);
            ushort type = (ushort)(flags & 0x3);
            ushort nameType = (ushort)((flags >> 2) & 0x7);
            ushort reservedFlags = (ushort)(flags & 0xFFE0);

            int offset = 20;
            string symbolName = ReadAsciiZ(data, ref offset);
            string dllName = ReadAsciiZ(data, ref offset);
            bool isImportByOrdinal = nameType == 0;
            ushort? ordinal = isImportByOrdinal ? ordinalOrHint : null;
            ushort? hint = isImportByOrdinal ? null : ordinalOrHint;
            string importName = isImportByOrdinal ? "#" + ordinalOrHint.ToString(CultureInfo.InvariantCulture) : symbolName;

            info = new CoffImportObjectInfo(
                version,
                machine,
                GetMachineName(machine),
                timeDateStamp,
                sizeOfData,
                ordinalOrHint,
                type,
                GetImportObjectTypeName(type),
                nameType,
                GetImportObjectNameTypeName(nameType),
                symbolName,
                dllName,
                isImportByOrdinal,
                ordinal,
                hint,
                importName,
                flags,
                reservedFlags);
            return true;
        }

        private static string ReadAsciiZ(ReadOnlySpan<byte> data, ref int offset)
        {
            if (offset < 0 || offset >= data.Length)
            {
                return string.Empty;
            }

            int start = offset;
            while (offset < data.Length && data[offset] != 0)
            {
                offset++;
            }

            int length = offset - start;
            if (offset < data.Length && data[offset] == 0)
            {
                offset++;
            }

            if (length <= 0)
            {
                return string.Empty;
            }

            return Encoding.ASCII.GetString(data.Slice(start, length));
        }

        private static string GetImportObjectTypeName(ushort type)
        {
            return type switch
            {
                0 => "Code",
                1 => "Data",
                2 => "Const",
                _ => "Unknown"
            };
        }

        private static string GetImportObjectNameTypeName(ushort nameType)
        {
            return nameType switch
            {
                0 => "Ordinal",
                1 => "Name",
                2 => "NameNoPrefix",
                3 => "NameUndecorate",
                _ => "Unknown"
            };
        }

        private bool TryParseCoffObject()
        {
            if (PEFileStream == null || PEFile == null)
            {
                return false;
            }

            int headerSize = Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));
            if (!TrySetPosition(0, headerSize))
            {
                return false;
            }

            byte[] buffer = new byte[headerSize];
            ReadExactly(PEFileStream, buffer, 0, buffer.Length);
            IMAGE_FILE_HEADER coffHeader = ByteArrayToStructure<IMAGE_FILE_HEADER>(buffer);

            bool isBigObj = coffHeader.Machine == 0 && coffHeader.NumberOfSections == 0xFFFF;
            uint numberOfSections = coffHeader.NumberOfSections;
            uint pointerToSymbolTable = coffHeader.PointerToSymbolTable;
            uint numberOfSymbols = coffHeader.NumberOfSymbols;
            ushort machine = (ushort)coffHeader.Machine;
            uint timeDateStamp = coffHeader.TimeDateStamp;
            ushort characteristics = (ushort)coffHeader.Characteristics;
            uint bigObjFlags = 0;
            uint bigObjMetaDataSize = 0;
            uint bigObjMetaDataOffset = 0;
            string bigObjClassId = string.Empty;
            long sectionTableOffset = headerSize;

            if (isBigObj)
            {
                int bigObjSize = Marshal.SizeOf(typeof(ANON_OBJECT_HEADER_BIGOBJ));
                if (!TrySetPosition(0, bigObjSize))
                {
                    return false;
                }

                byte[] bigBuffer = new byte[bigObjSize];
                ReadExactly(PEFileStream, bigBuffer, 0, bigBuffer.Length);
                ANON_OBJECT_HEADER_BIGOBJ bigObj = ByteArrayToStructure<ANON_OBJECT_HEADER_BIGOBJ>(bigBuffer);
                if (bigObj.Sig1 != 0 || bigObj.Sig2 != 0xFFFF)
                {
                    return false;
                }

                machine = bigObj.Machine;
                numberOfSections = bigObj.NumberOfSections;
                pointerToSymbolTable = bigObj.PointerToSymbolTable;
                numberOfSymbols = bigObj.NumberOfSymbols;
                timeDateStamp = bigObj.TimeDateStamp;
                bigObjFlags = bigObj.Flags;
                bigObjMetaDataSize = bigObj.MetaDataSize;
                bigObjMetaDataOffset = bigObj.MetaDataOffset;
                bigObjClassId = bigObj.ClassID.ToString("D");
                characteristics = 0;
                sectionTableOffset = bigObjSize;
            }
            else if (coffHeader.SizeOfOptionalHeader != 0)
            {
                return false;
            }

            long fileLength = PEFileStream.Length;
            long sectionTableSize = (long)numberOfSections * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            if (sectionTableSize > int.MaxValue)
            {
                Warn(ParseIssueCategory.Sections, "COFF section table size exceeds supported range.");
                return false;
            }
            if (sectionTableOffset + sectionTableSize > fileLength)
            {
                return false;
            }

            _imageKind = "COFF";
            _teImageInfo = null;
            _catalogSignatureInfo = null;
            _machineType = (MachineTypes)machine;
            _timeDateStamp = timeDateStamp;
            _fileAlignment = 0;
            _sectionAlignment = 0;
            _imageBase = 0;
            _sizeOfImage = 0;
            _sizeOfCode = 0;
            _sizeOfInitializedData = 0;
            _numberOfRvaAndSizes = 0;
            _sizeOfHeaders = 0;
            _optionalHeaderChecksum = 0;
            _subsystemInfo = null;
            _dllCharacteristicsInfo = null;
            _securityFeaturesInfo = null;
            _dataDirectories = Array.Empty<IMAGE_DATA_DIRECTORY>();
            _dataDirectoryInfos = Array.Empty<DataDirectoryInfo>();
            _architectureDirectory = null;
            _globalPtrDirectory = null;
            _iatDirectory = null;
            _hasResourceDirectory = false;
            _hasRelocationDirectory = false;
            _hasDebugDirectory = false;
            _hasExceptionDirectory = false;
            _hasLoadConfigDirectory = false;
            _hasClrDirectory = false;
            _resourcesParsed = true;
            _debugParsed = true;
            _relocationsParsed = true;
            _exceptionParsed = true;
            _loadConfigParsed = true;
            _clrParsed = true;
            _peHeaderIsPe32Plus = false;

            List<IMAGE_SECTION_HEADER> sections = new List<IMAGE_SECTION_HEADER>();
            if (numberOfSections > 0)
            {
                if (!TrySetPosition(sectionTableOffset, (int)sectionTableSize))
                {
                    Fail(ParseIssueCategory.Sections, "COFF section table exceeds file bounds.");
                    return true;
                }

                if (numberOfSections > int.MaxValue)
                {
                    Warn(ParseIssueCategory.Sections, "COFF bigobj section count exceeds supported range.");
                }

                int sectionCount = numberOfSections > int.MaxValue ? int.MaxValue : (int)numberOfSections;
                for (int i = 0; i < sectionCount; i++)
                {
                    sections.Add(new IMAGE_SECTION_HEADER(PEFile));
                }
            }

            _sections = sections;
            ValidateSectionNameEncoding(sections);
            ParseCoffSymbolTable(pointerToSymbolTable, numberOfSymbols, sections);
            ResolveCoffObjectSectionLongNames(sections);
            BuildSectionPermissionInfos(sections);
            ParseCoffLineNumbers(sections);
            ParseCoffRelocations(sections);
            BuildSectionHeaderInfos(sections);
            BuildSectionDirectoryCoverage(_dataDirectoryInfos, sections);
            ComputeOverlayInfo(sections);
            ComputeSectionEntropies(sections);
            ComputePackingHints(sections);

            _coffObjectInfo = new CoffObjectInfo(
                machine,
                GetMachineName(machine),
                (ushort)Math.Min(numberOfSections, ushort.MaxValue),
                isBigObj,
                numberOfSections,
                bigObjFlags,
                bigObjMetaDataSize,
                bigObjMetaDataOffset,
                bigObjClassId,
                timeDateStamp,
                TimeDateStampUtc,
                pointerToSymbolTable,
                numberOfSymbols,
                coffHeader.SizeOfOptionalHeader,
                characteristics,
                DecodeCoffCharacteristics(characteristics));

            return true;
        }

        private void ReadPE()
        {
            try
            {
                _parseResult.Clear();
                _imageKind = "Unknown";
                _coffObjectInfo = null;
                _coffArchiveInfo = null;
                _teImageInfo = null;
                _catalogSignatureInfo = null;
                _resources.Clear();
                _resourceStringTables.Clear();
                _resourceStringCoverage.Clear();
                _resourceManifests.Clear();
                _resourceLocaleCoverage.Clear();
                _resourceMessageTables.Clear();
                _resourceDialogs.Clear();
                _resourceAccelerators.Clear();
                _resourceMenus.Clear();
                _resourceToolbars.Clear();
                _resourceBitmaps.Clear();
                _resourceIcons.Clear();
                _resourceCursors.Clear();
                _resourceCursorGroups.Clear();
                _iconGroups.Clear();
                _resourceFonts.Clear();
                _resourceFontDirectories.Clear();
                _resourceDlgInit.Clear();
                _resourceAnimatedCursors.Clear();
                _resourceAnimatedIcons.Clear();
                _resourceRcData.Clear();
                _resourceHtml.Clear();
                _resourceDlgInclude.Clear();
                _resourcePlugAndPlay.Clear();
                _resourceVxd.Clear();
                _coffSymbols.Clear();
                _coffRelocations.Clear();
                _coffStringTable.Clear();
                _coffLineNumbers.Clear();
                _versionInfoDetails = null;
                _sectionEntropies.Clear();
                _sectionSlacks.Clear();
                _sectionGaps.Clear();
                _sectionPermissions.Clear();
                _sectionHeaders.Clear();
                _sectionDirectoryCoverage.Clear();
                _unmappedDataDirectories.Clear();
                _dataDirectoryValidations.Clear();
                _overlayInfo = new OverlayInfo(0, 0);
                _overlayContainers.Clear();
                _securityFeaturesInfo = null;
                imports.Clear();
                exports.Clear();
                _importEntries.Clear();
                _importDescriptors.Clear();
                _importDescriptorInternals.Clear();
                _delayImportEntries.Clear();
                _delayImportDescriptors.Clear();
                _exportEntries.Clear();
                _exportOrdinalOutOfRangeCount = 0;
                _exportAnomalies = new ExportAnomalySummary(0, 0, 0, 0);
                _exportDllName = string.Empty;
                _boundImports.Clear();
                _debugDirectories.Clear();
                _baseRelocations.Clear();
            _relocationAnomalies = new RelocationAnomalySummary(0, 0, 0, 0, 0, 0, 0, 0);
                _exceptionDirectoryRva = 0;
                _exceptionDirectorySize = 0;
                _exceptionDirectorySectionName = string.Empty;
                _exceptionDirectoryInPdata = false;
                _exceptionFunctions.Clear();
                _unwindInfoDetails.Clear();
                _arm64UnwindInfoDetails.Clear();
                _arm32UnwindInfoDetails.Clear();
                _ia64UnwindInfoDetails.Clear();
                _exceptionSummary = null;
                _richHeader = null;
                _tlsInfo = null;
                _loadConfig = null;
                _dataDirectoryInfos = Array.Empty<DataDirectoryInfo>();
                _architectureDirectory = null;
                _globalPtrDirectory = null;
                _iatDirectory = null;
                _clrMetadata = null;
                _strongNameSignature = null;
                _strongNameValidation = null;
                _fileAlignment = 0;
                _sectionAlignment = 0;
                _imageBase = 0;
                _sizeOfImage = 0;
                _sizeOfCode = 0;
                _sizeOfInitializedData = 0;
                _numberOfRvaAndSizes = 0;
                _sizeOfHeaders = 0;
                _optionalHeaderChecksum = 0;
                _dosRelocationInfo = null;
                _subsystemInfo = null;
                _dllCharacteristicsInfo = null;
                _importHash = string.Empty;
                _computedChecksum = 0;
                _checksumFieldOffset = 0;
                _certificateTableOffset = 0;
                _certificateTableSize = 0;
                _timeDateStamp = 0;
                _readyToRun = null;
                _dotNetRuntimeHint = string.Empty;
                if (PEFile == null || PEFileStream == null)
                {
                    Fail(ParseIssueCategory.File, "No PE file stream available.");
                    return;
                }

                Stream fs = PEFileStream;
                if (_options.ComputeHash)
                {
                    _hash = ComputeHash(fs);
                }
                if (!TrySetPosition(0, 2))
                {
                    Fail(ParseIssueCategory.File, "File too small for signature.");
                    return;
                }

                ushort signature = PEFile.ReadUInt16();
                if (signature == EFI_TE_SIGNATURE)
                {
                    ParseTeImage();
                    return;
                }

                if (signature != (ushort)MagicByteSignature.IMAGE_DOS_SIGNATURE &&
                    signature != (ushort)MagicByteSignature.IMAGE_OS2_SIGNATURE &&
                    signature != (ushort)MagicByteSignature.IMAGE_OS2_SIGNATURE_LE)
                {
                    if (TryParseCoffArchive())
                    {
                        return;
                    }

                    if (TryParseCoffObject())
                    {
                        return;
                    }

                    Fail(ParseIssueCategory.Header, "Invalid DOS signature.");
                    return;
                }

                if (!TrySetPosition(0, Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))))
                {
                    Fail(ParseIssueCategory.File, "File too small for DOS header.");
                    return;
                }

                IMAGE_DOS_HEADER header = new IMAGE_DOS_HEADER(PEFile);

                byte[] buffer = new byte[] { };

                // Check the File header signature
                if ((header.e_magic == MagicByteSignature.IMAGE_DOS_SIGNATURE) || (header.e_magic == MagicByteSignature.IMAGE_OS2_SIGNATURE) || (header.e_magic == MagicByteSignature.IMAGE_OS2_SIGNATURE_LE))
                {
                    _imageKind = "PE";
                    ParseRichHeader(header);
                    ParseDosRelocations(header);
                    if (!TrySetPosition(header.e_lfanew, sizeof(uint) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))))
                    {
                        Fail(ParseIssueCategory.Header, "PE header offset is outside the file bounds.");
                        return;
                    }

                    // Set the position to the PE-Header
                    IMAGE_NT_HEADERS peHeader = new IMAGE_NT_HEADERS(PEFile);
                    _machineType = peHeader.FileHeader.Machine;
                    if (peHeader.Signature != IMAGE_NT_SIGNATURE )
                    {
                        Fail(ParseIssueCategory.Header, "Invalid PE signature.");
                        return;
                    }

                    if (peHeader.Magic != PEFormat.PE32 && peHeader.Magic != PEFormat.PE32plus)
                    {
                        Fail(ParseIssueCategory.OptionalHeader, "Unknown PE optional header format.");
                        return;
                    }

                    bool isPe32Plus = peHeader.Magic == PEFormat.PE32plus;
                    _timeDateStamp = peHeader.FileHeader.TimeDateStamp;
                    _fileAlignment = peHeader.FileAlignment;
                    _sectionAlignment = peHeader.SectionAlignment;
                    _imageBase = peHeader.ImageBase;
                    _sizeOfImage = peHeader.SizeOfImage;
                    _sizeOfCode = peHeader.SizeOfCode;
                    _sizeOfInitializedData = peHeader.SizeOfInitializedData;
                    _numberOfRvaAndSizes = peHeader.NumberOfRvaAndSizes;
                    _sizeOfHeaders = peHeader.SizeOfHeaders;
                    _optionalHeaderChecksum = peHeader.CheckSum;
                    _subsystemInfo = BuildSubsystemInfo(peHeader.Subsystem);
                    _dllCharacteristicsInfo = BuildDllCharacteristicsInfo(peHeader.DllCharacteristics);

                    IMAGE_DATA_DIRECTORY[] dataDirectory = peHeader.DataDirectory ?? Array.Empty<IMAGE_DATA_DIRECTORY>();
                    _dataDirectories = dataDirectory;
                    _resourcesParsed = false;
                    _debugParsed = false;
                    _relocationsParsed = false;
                    _exceptionParsed = false;
                    _loadConfigParsed = false;
                    _clrParsed = false;
                    _peHeaderIsPe32Plus = isPe32Plus;
                    _hasResourceDirectory = dataDirectory.Length > 2 && dataDirectory[2].Size > 0;
                    _hasRelocationDirectory = dataDirectory.Length > 5 && dataDirectory[5].Size > 0;
                    _hasDebugDirectory = dataDirectory.Length > 6 && dataDirectory[6].Size > 0;
                    _hasExceptionDirectory = dataDirectory.Length > 3 && dataDirectory[3].Size > 0;
                    _hasLoadConfigDirectory = dataDirectory.Length > 10 && dataDirectory[10].Size > 0;
                    _hasClrDirectory = dataDirectory.Length > 14 && dataDirectory[14].Size > 0;
                    if (dataDirectory.Length > 4)
                    {
                        _certificateTableOffset = dataDirectory[4].VirtualAddress;
                        _certificateTableSize = dataDirectory[4].Size;
                    }

                    int checksumOffset = (int)header.e_lfanew +
                                         sizeof(uint) +
                                         Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) +
                                         GetOptionalHeaderChecksumOffset(peHeader.Magic);
                    int optionalHeaderSize = peHeader.FileHeader.SizeOfOptionalHeader;
                    int checksumFieldOffset = GetOptionalHeaderChecksumOffset(peHeader.Magic);
                    _checksumFieldOffset = checksumOffset;
                    if (_options.ComputeChecksum)
                    {
                        if (checksumFieldOffset + 4 <= optionalHeaderSize &&
                            checksumOffset >= 0 &&
                            checksumOffset + 4 <= PEFileStream.Length)
                        {
                            _computedChecksum = ComputeChecksum(PEFileStream, checksumOffset);
                        }
                        else
                        {
                            Warn(ParseIssueCategory.Checksum, "Checksum field offset is outside file bounds.");
                        }
                    }

                    bool hasClrDirectory = _hasClrDirectory;
                    if (_options.EnableAssemblyAnalysis && _hasClrDirectory && !string.IsNullOrWhiteSpace(_filePath))
                    {
                        try
                        {
                            AnalyzeAssembly analyzer = new AnalyzeAssembly(_filePath);
                            _obfuscationPercentage = analyzer.ObfuscationPercentage;
                            _isDotNetFile = analyzer.IsDotNetFile || _hasClrDirectory;
                            _isObfuscated = analyzer.IsObfuscated;
                            _assemblyReferenceInfos = analyzer.AssemblyReferenceInfos.ToList();
                        }
                        catch (Exception ex)
                        {
                            Warn(ParseIssueCategory.AssemblyAnalysis, $"AnalyzeAssembly failed: {ex.Message}");
                            _obfuscationPercentage = 0.0;
                            _isDotNetFile = _hasClrDirectory;
                            _isObfuscated = false;
                            _assemblyReferenceInfos.Clear();
                        }
                    }
                    else
                    {
                        _isDotNetFile = _hasClrDirectory;
                        _obfuscationPercentage = 0.0;
                        _isObfuscated = false;
                        _assemblyReferenceInfos.Clear();
                    }

                    List<IMAGE_SECTION_HEADER> sections = new List<IMAGE_SECTION_HEADER>();
                    int sectionTableSize = peHeader.FileHeader.NumberOfSections * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
                    if (!TrySetPosition(PEFileStream.Position, sectionTableSize))
                    {
                        Fail(ParseIssueCategory.Sections, "Section table exceeds file bounds.");
                        return;
                    }

                    for (int i = 0; i < peHeader.FileHeader.NumberOfSections; i++)
                    {                       
                        sections.Add(new IMAGE_SECTION_HEADER(PEFile));
                    }

                    _sections = sections;
                    ValidateSectionNameEncoding(sections);

                    ValidateSections(header, peHeader, sections, dataDirectory);
                    ValidateImageCoffDeprecation(peHeader.FileHeader, sections);
                    BuildSectionPermissionInfos(sections);
                    BuildDataDirectoryInfos(dataDirectory, sections, isPe32Plus);
                    ParseCoffSymbolTable(peHeader.FileHeader.PointerToSymbolTable, peHeader.FileHeader.NumberOfSymbols, sections);
                    ParseCoffLineNumbers(sections);
                    ParseCoffRelocations(sections);
                    BuildSectionHeaderInfos(sections);
                    BuildSectionDirectoryCoverage(_dataDirectoryInfos, sections);

                    for (int i = 0; i < dataDirectory.Length; i++)
                    {
                        // skip empty directories
                        if (dataDirectory[i].Size == 0) { continue; }

                        switch (i)
                        {
                            case 0:
                                // Export Table                               

                                // Read the export directory table
                                buffer = new byte[Marshal.SizeOf(new EXPORT_DIRECTORY_TABLE())];
                                EXPORT_DIRECTORY_TABLE edt = new EXPORT_DIRECTORY_TABLE();
                                if (!TryGetFileOffset(sections, dataDirectory[i].VirtualAddress, out long exportTableOffset))
                                {
                                    Warn(ParseIssueCategory.Exports, "Export table RVA not mapped to a section.");
                                    break;
                                }

                                if (!TrySetPosition(exportTableOffset, buffer.Length))
                                {
                                    Warn(ParseIssueCategory.Exports, "Export table offset outside file bounds.");
                                    break;
                                }

                                ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                                edt = (ByteArrayToStructure<EXPORT_DIRECTORY_TABLE>(buffer));

                                _exportDllName = string.Empty;
                                if (edt.NameRVA != 0 &&
                                    TryGetFileOffset(sections, edt.NameRVA, out long exportTableNameOffset) &&
                                    TryReadNullTerminatedString(exportTableNameOffset, out string exportTableName) &&
                                    !string.IsNullOrWhiteSpace(exportTableName))
                                {
                                    _exportDllName = exportTableName;
                                }

                                Dictionary<uint, string> exportNamesByIndex = new Dictionary<uint, string>();
                                if (edt.NumberOfNamePointers > 0)
                                {
                                    if (!TryGetFileOffset(sections, edt.NamePointerRVA, out long namePtrOffset))
                                    {
                                        Warn(ParseIssueCategory.Exports, "Export name pointer RVA not mapped to a section.");
                                        break;
                                    }

                                    long pointerBytes = edt.NumberOfNamePointers * sizeof(UInt32);
                                    if (pointerBytes > int.MaxValue || !TrySetPosition(namePtrOffset, (int)pointerBytes))
                                    {
                                        Warn(ParseIssueCategory.Exports, "Export name pointer table outside file bounds.");
                                        break;
                                    }

                                    List<UInt32> namePointers = new List<uint>();
                                    for (int j = 0; j < edt.NumberOfNamePointers; j++)
                                    {
                                        namePointers.Add(PEFile.ReadUInt32());
                                    }

                                    if (!TryGetFileOffset(sections, edt.OrdinalTableRVA, out long ordinalTableOffset))
                                    {
                                        Warn(ParseIssueCategory.Exports, "Export ordinal table RVA not mapped to a section.");
                                        break;
                                    }

                                    long ordinalBytes = edt.NumberOfNamePointers * sizeof(ushort);
                                    if (ordinalBytes > int.MaxValue || !TrySetPosition(ordinalTableOffset, (int)ordinalBytes))
                                    {
                                        Warn(ParseIssueCategory.Exports, "Export ordinal table outside file bounds.");
                                        break;
                                    }

                                    List<ushort> nameOrdinals = new List<ushort>();
                                    for (int j = 0; j < edt.NumberOfNamePointers; j++)
                                    {
                                        nameOrdinals.Add(PEFile.ReadUInt16());
                                    }

                                    bool exportNameFailure = false;
                                    for (int j = 0; j < namePointers.Count; j++)
                                    {
                                        uint ptr = namePointers[j];
                                        if (!TryGetFileOffset(sections, ptr, out long exportNameOffset))
                                        {
                                            exportNameFailure = true;
                                            continue;
                                        }

                                        if (TryReadNullTerminatedString(exportNameOffset, out string exportName) &&
                                            !string.IsNullOrWhiteSpace(exportName))
                                        {
                                            exports.Add(exportName);
                                            if (j < nameOrdinals.Count)
                                            {
                                                ushort ordinalIndex = nameOrdinals[j];
                                                if (ordinalIndex >= edt.AddressTableEntries)
                                                {
                                                    _exportOrdinalOutOfRangeCount++;
                                                    exportNameFailure = true;
                                                }
                                                else
                                                {
                                                    exportNamesByIndex[ordinalIndex] = exportName;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            exportNameFailure = true;
                                        }
                                    }

                                    if (exportNameFailure)
                                    {
                                        Warn(ParseIssueCategory.Exports, "One or more export names could not be read.");
                                    }
                                }

                                if (edt.AddressTableEntries > 0)
                                {
                                    if (!TryGetFileOffset(sections, edt.ExportAddressTableRVA, out long addrTableOffset))
                                    {
                                        Warn(ParseIssueCategory.Exports, "Export address table RVA not mapped to a section.");
                                        break;
                                    }

                                    long addressBytes = edt.AddressTableEntries * sizeof(UInt32);
                                    if (addressBytes > int.MaxValue || !TrySetPosition(addrTableOffset, (int)addressBytes))
                                    {
                                        Warn(ParseIssueCategory.Exports, "Export address table outside file bounds.");
                                        break;
                                    }

                                    List<uint> addressTable = new List<uint>();
                                    for (int j = 0; j < edt.AddressTableEntries; j++)
                                    {
                                        addressTable.Add(PEFile.ReadUInt32());
                                    }

                                    for (int j = 0; j < addressTable.Count; j++)
                                    {
                                        uint ordinal = edt.OrdinalBase + (uint)j;
                                        exportNamesByIndex.TryGetValue((uint)j, out string exportName);
                                        uint addressRva = addressTable[j];
                                        bool isForwarder = false;
                                        string forwarder = string.Empty;
                                        if (dataDirectory[i].Size > 0)
                                        {
                                            ulong exportStart = dataDirectory[i].VirtualAddress;
                                            ulong exportEnd = exportStart + dataDirectory[i].Size;
                                            if (addressRva >= exportStart && addressRva < exportEnd)
                                            {
                                                isForwarder = true;
                                                if (TryGetFileOffset(sections, addressRva, out long forwarderOffset))
                                                {
                                                    if (TryReadNullTerminatedString(forwarderOffset, out string forwarderName))
                                                    {
                                                        forwarder = forwarderName ?? string.Empty;
                                                    }
                                                }
                                            }
                                        }

                                        _exportEntries.Add(new ExportEntry(exportName ?? string.Empty, ordinal, addressRva, isForwarder, forwarder));
                                    }
                                }

                                break;
                            case 1:
                                // Import Table
                                buffer = new byte[Marshal.SizeOf(new IMPORT_DIRECTORY_TABLE())];
                                List<IMPORT_DIRECTORY_TABLE> idt = new List<IMPORT_DIRECTORY_TABLE>();
                                if (!TryGetFileOffset(sections, dataDirectory[i].VirtualAddress, out long importTableOffset))
                                {
                                    Warn(ParseIssueCategory.Imports, "Import table RVA not mapped to a section.");
                                    break;
                                }

                                if (!TryGetIntSize(dataDirectory[i].Size, out int importTableSize))
                                {
                                    Warn(ParseIssueCategory.Imports, "Import table size exceeds supported limits.");
                                    break;
                                }

                                // Read the Import directory table
                                int importEntrySize = Marshal.SizeOf(typeof(IMPORT_DIRECTORY_TABLE));
                                int importEntryCount = importTableSize / importEntrySize;
                                for (int j = 0; j < importEntryCount; j++)
                                {
                                    long entryOffset = importTableOffset + (j * importEntrySize);
                                    if (!TrySetPosition(entryOffset, importEntrySize))
                                    {
                                        Warn(ParseIssueCategory.Imports, "Import table entry outside file bounds.");
                                        break;
                                    }

                                    ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                                    IMPORT_DIRECTORY_TABLE entry = ByteArrayToStructure<IMPORT_DIRECTORY_TABLE>(buffer);
                                    if (entry.LookupTableVirtualAddress == 0 &&
                                        entry.TimeDateStamp == 0 &&
                                        entry.FowarderChain == 0 &&
                                        entry.NameRVA == 0 &&
                                        entry.ImportAddressTableRVA == 0)
                                    {
                                        break;
                                    }

                                    idt.Add(entry);
                                }
                                
                                // Read the import names
                                foreach (IMPORT_DIRECTORY_TABLE table in idt)
                                {
                                    if (!TryGetFileOffset(sections, table.NameRVA, out long importNameOffset))
                                    {
                                        Warn(ParseIssueCategory.Imports, "Import name RVA not mapped to a section.");
                                        continue;
                                    }

                                    if (TryReadNullTerminatedString(importNameOffset, out string importName) &&
                                        !string.IsNullOrWhiteSpace(importName))
                                    {
                                        imports.Add(importName);
                                        ImportThunkParseStats intStats = new ImportThunkParseStats(0, 0, true);
                                        ImportThunkParseStats iatStats = new ImportThunkParseStats(0, 0, true);

                                        if (table.LookupTableVirtualAddress != 0)
                                        {
                                            intStats = ParseImportThunks(
                                                importName,
                                                table.LookupTableVirtualAddress,
                                                ImportThunkSource.ImportNameTable,
                                                sections,
                                                isPe32Plus,
                                                _importEntries);
                                        }

                                        if (table.ImportAddressTableRVA != 0 &&
                                            table.ImportAddressTableRVA != table.LookupTableVirtualAddress)
                                        {
                                            iatStats = ParseImportThunks(
                                                importName,
                                                table.ImportAddressTableRVA,
                                                ImportThunkSource.ImportAddressTable,
                                                sections,
                                                isPe32Plus,
                                                _importEntries);
                                        }

                                        _importDescriptorInternals.Add(new ImportDescriptorInternal(
                                            importName,
                                            table.TimeDateStamp,
                                            table.LookupTableVirtualAddress,
                                            table.ImportAddressTableRVA,
                                            intStats.NullThunkCount,
                                            iatStats.NullThunkCount,
                                            intStats.Terminated,
                                            iatStats.Terminated));
                                    }
                                }
                                
                                break;
                            case 2:
                                // Resource Table                                
                                if (_options != null && _options.LazyParseDataDirectories)
                                {
                                    break;
                                }

                                ParseResourceDirectoryTable(dataDirectory[i], sections);
                                _resourcesParsed = true;
                                break;
                            case 3:
                                // Exception Table -> The .pdata Section
                                if (_options != null && _options.LazyParseDataDirectories)
                                {
                                    break;
                                }

                                ParseExceptionDirectory(dataDirectory[i], sections);
                                _exceptionParsed = true;
                                break;
                            case 4:
                                // Certificate Table -> The attribute certificate table
                                _certificates.Clear();
                                _certificate = null;
                                _certificateEntries.Clear();
                                if (!TryGetIntSize(dataDirectory[i].Size, out int certSize) ||
                                    certSize < (sizeof(UInt32) + sizeof(CertificateRevision) + sizeof(CertificateType)))
                                {
                                    Warn(ParseIssueCategory.Certificates, "Certificate table size is invalid.");
                                    break;
                                }

                                if (!TrySetPosition(dataDirectory[i].VirtualAddress, certSize))
                                {
                                    Warn(ParseIssueCategory.Certificates, "Certificate table offset outside file bounds.");
                                    break;
                                }

                                buffer = new byte[certSize];
                                ReadExactly(PEFileStream, buffer, 0, buffer.Length);

                                int headerSize = Marshal.SizeOf(typeof(CertificateTableHeader));
                                int offset = 0;
                                Dictionary<string, string> authenticodeHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                                HashSet<uint> seenRevisionTypePairs = new HashSet<uint>();
                                HashSet<ushort> seenRevisionValues = new HashSet<ushort>();
                                HashSet<ushort> seenTypeValues = new HashSet<ushort>();
                                bool strictCertificateUniqueness = IsStrictCertificateUniquenessModeEnabled();
                                while (offset + headerSize <= buffer.Length)
                                {
                                    byte[] tmp = new byte[headerSize];
                                    Array.Copy(buffer, offset, tmp, 0, headerSize);
                                    CertificateTableHeader certHeader = ByteArrayToStructure<CertificateTableHeader>(tmp);

                                    if (certHeader.dwLength < headerSize)
                                    {
                                        Warn(ParseIssueCategory.Certificates, "Certificate entry length is invalid.");
                                        break;
                                    }

                                    if (certHeader.dwLength > int.MaxValue)
                                    {
                                        Warn(ParseIssueCategory.Certificates, "Certificate entry length exceeds supported limits.");
                                        break;
                                    }

                                    int entryLength = (int)certHeader.dwLength;
                                    if (offset + entryLength > buffer.Length)
                                    {
                                        Warn(ParseIssueCategory.Certificates, "Certificate entry exceeds certificate table size.");
                                        break;
                                    }

                                    int certDataLength = entryLength - headerSize;
                                    if (certDataLength <= 0)
                                    {
                                        Warn(ParseIssueCategory.Certificates, "Certificate entry does not contain certificate data.");
                                        break;
                                    }

                                    byte[] certData = new byte[certDataLength];
                                    Array.Copy(buffer, offset + headerSize, certData, 0, certDataLength);
                                    _certificates.Add(certData);
                                    CertificateTypeKind typeKind = (CertificateTypeKind)certHeader.wCertificateType;
                                    ushort revisionValue = (ushort)certHeader.wRevision;
                                    if (certHeader.wRevision != CertificateRevision.WIN_CERT_REVISION_1_0 &&
                                        certHeader.wRevision != CertificateRevision.WIN_CERT_REVISION_2_0)
                                    {
                                        Warn(ParseIssueCategory.Certificates, $"Certificate entry has unknown revision 0x{revisionValue:X4}.");
                                    }

                                    ushort typeValue = (ushort)certHeader.wCertificateType;
                                    uint uniquenessKey = ((uint)revisionValue << 16) | typeValue;
                                    if (!seenRevisionTypePairs.Add(uniquenessKey))
                                    {
                                        Warn(
                                            ParseIssueCategory.Certificates,
                                            $"SPEC violation: Duplicate WIN_CERTIFICATE (wRevision=0x{revisionValue:X4}, wCertificateType=0x{typeValue:X4}) entry detected.");
                                    }

                                    bool duplicateRevision = !seenRevisionValues.Add(revisionValue);
                                    bool duplicateType = !seenTypeValues.Add(typeValue);
                                    if (duplicateRevision)
                                    {
                                        Warn(
                                            ParseIssueCategory.Certificates,
                                            $"SPEC violation: Duplicate WIN_CERTIFICATE wRevision 0x{revisionValue:X4} detected.");
                                    }
                                    if (duplicateType)
                                    {
                                        Warn(
                                            ParseIssueCategory.Certificates,
                                            $"SPEC violation: Duplicate WIN_CERTIFICATE wCertificateType 0x{typeValue:X4} detected.");
                                    }
                                    if (strictCertificateUniqueness && duplicateRevision)
                                    {
                                        Fail(
                                            ParseIssueCategory.Certificates,
                                            $"SPEC strict violation: Duplicate WIN_CERTIFICATE wRevision 0x{revisionValue:X4} detected.");
                                    }
                                    if (strictCertificateUniqueness && duplicateType)
                                    {
                                        Fail(
                                            ParseIssueCategory.Certificates,
                                            $"SPEC strict violation: Duplicate WIN_CERTIFICATE wCertificateType 0x{typeValue:X4} detected.");
                                    }

                                    int aligned = Align8(entryLength);
                                    if (entryLength % 8 != 0)
                                    {
                                        Warn(ParseIssueCategory.Certificates, $"Certificate entry length {entryLength} is not 8-byte aligned.");
                                    }

                                    if (aligned <= 0)
                                    {
                                        break;
                                    }

                                    if (offset + aligned > buffer.Length)
                                    {
                                        Warn(ParseIssueCategory.Certificates, "Certificate entry alignment exceeds certificate table size.");
                                        break;
                                    }

                                    Pkcs7SignerInfo[] pkcs7Signers = Array.Empty<Pkcs7SignerInfo>();
                                    string pkcs7Error = string.Empty;
                                    AuthenticodeVerificationResult[] authenticodeResults = Array.Empty<AuthenticodeVerificationResult>();
                                    CertificateTypeMetadataInfo typeMetadata = BuildCertificateTypeMetadata(typeKind, certData);
                                    if (typeKind == CertificateTypeKind.Unknown || typeKind == CertificateTypeKind.Reserved1)
                                    {
                                        Warn(ParseIssueCategory.Certificates, $"Certificate entry has unrecognized type 0x{typeValue:X4}.");
                                    }

                                    if (typeKind == CertificateTypeKind.X509 && !typeMetadata.Parsed)
                                    {
                                        Warn(ParseIssueCategory.Certificates, "X509 certificate metadata could not be fully decoded.");
                                    }

                                    if (_options.ParseCertificateSigners &&
                                        typeKind == CertificateTypeKind.PkcsSignedData)
                                    {
                                        CertificateUtilities.TryGetPkcs7SignerInfos(certData, _options?.AuthenticodePolicy, out pkcs7Signers, out pkcs7Error);
                                        if (_options.ComputeAuthenticode &&
                                            CertificateUtilities.TryGetAuthenticodeDigests(certData, out AuthenticodeDigestInfo[] digests, out string _))
                                        {
                                            List<AuthenticodeVerificationResult> results = new List<AuthenticodeVerificationResult>();
                                            foreach (AuthenticodeDigestInfo digest in digests)
                                            {
                                                if (!CertificateUtilities.TryGetHashAlgorithmName(digest.AlgorithmOid, out HashAlgorithmName algorithm))
                                                {
                                                    results.Add(new AuthenticodeVerificationResult(digest, string.Empty, false));
                                                    continue;
                                                }

                                                if (!authenticodeHashes.TryGetValue(algorithm.Name ?? digest.AlgorithmOid, out string computed))
                                                {
                                                    computed = ComputeAuthenticodeHash(algorithm, _checksumFieldOffset, _certificateTableOffset, _certificateTableSize);
                                                    authenticodeHashes[algorithm.Name ?? digest.AlgorithmOid] = computed;
                                                }

                                                string embedded = ToHex(digest.Digest);
                                                bool matches = !string.IsNullOrWhiteSpace(computed) &&
                                                               string.Equals(computed, embedded, StringComparison.OrdinalIgnoreCase);
                                                results.Add(new AuthenticodeVerificationResult(digest, computed, matches));
                                            }

                                            authenticodeResults = results.ToArray();
                                        }
                                    }

                                    AuthenticodeStatusInfo statusInfo = CertificateUtilities.BuildAuthenticodeStatus(pkcs7Signers, _options?.AuthenticodePolicy, _filePath);
                                    long entryOffset = _certificateTableOffset + offset;
                                    int padding = aligned - entryLength;
                                    _certificateEntries.Add(new CertificateEntry(
                                        typeKind,
                                        certData,
                                        certHeader.dwLength,
                                        revisionValue,
                                        aligned,
                                        padding,
                                        entryOffset,
                                        pkcs7Signers,
                                        pkcs7Error,
                                        authenticodeResults,
                                        statusInfo,
                                        typeMetadata));

                                    offset += aligned;
                                }

                                if (_certificates.Count > 0)
                                {
                                    _certificate = _certificates[0];
                                }

                                break;
                            case 5:
                                // Base Relocation Table -> The .reloc Section
                                if (_options != null && _options.LazyParseDataDirectories)
                                {
                                    break;
                                }

                                ParseBaseRelocationTable(dataDirectory[i], sections);
                                _relocationsParsed = true;
                                break;
                            case 6:
                                // Debug The .debug Section
                                if (_options != null && _options.LazyParseDataDirectories)
                                {
                                    break;
                                }

                                ParseDebugDirectory(dataDirectory[i], sections);
                                _debugParsed = true;
                                break;
                            case 7:
                                // Archive -> Reserved, must be 0
                                break;
                            case 8:
                                // Global Ptr -> The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero.
                                break;
                            case 9:
                                // TLS Table -> Thread Local Storage section
                                ParseTlsDirectory(dataDirectory[i], sections, isPe32Plus, peHeader.ImageBase);
                                break;
                            case 10:
                                // Load Config Table -> The load configuration table address and size 
                                if (_options != null && _options.LazyParseDataDirectories)
                                {
                                    break;
                                }

                                ParseLoadConfigDirectory(dataDirectory[i], sections, isPe32Plus);
                                _loadConfigParsed = true;
                                break;
                            case 11:
                                // Bound Import -> The bound import table address and size
                                ParseBoundImportTable(dataDirectory[i], sections);
                                break;
                            case 12:
                                // IAT -> Import Address Table
                                break;
                            case 13:
                                // Delay Import Descriptor -> Delay-Load Import Tables 
                                ParseDelayImportTable(dataDirectory[i], sections, isPe32Plus, peHeader.ImageBase);
                                break;
                            case 14:
                                // CLR Runtime Header -> The .cormeta Section (Object Only)
                                if (_options != null && _options.LazyParseDataDirectories)
                                {
                                    break;
                                }

                                ParseClrDirectory(dataDirectory[i], sections);
                                _clrParsed = true;
                                break;
                            case 15:
                                // Unknown
                                break;
                            default:
                                // Not supported or Implemented
                                break;
                        }
                    }

                    BuildImportDescriptorInfos();
                    ResolveExportForwarderChains();
                    ValidateImportExportConsistency();
                    ValidateRelocationHints();
                    ComputeDotNetRuntimeHint();
                    ComputeImportHash();
                    ComputeOverlayInfo(sections);
                    ComputeSectionEntropies(sections);
                    ComputePackingHints(sections);
                    ComputeCatalogSignatureInfo();
                    if (_options == null || !_options.LazyParseDataDirectories)
                    {
                        BuildExceptionDirectorySummary(sections);
                        ComputeSecurityFeatures(isPe32Plus);
                    }
                    
                }
                else
                {
                    // not a DOS-File
                    Fail(ParseIssueCategory.Header, "Invalid DOS signature.");
                }
            }
            catch (PECOFFParseException)
            {
                if (_options != null && _options.StrictMode)
                {
                    throw;
                }
            }
            catch (Exception ex)
            {
                Fail($"Unexpected error while parsing PE: {ex.Message}");
                if (_options != null && _options.StrictMode)
                {
                    throw;
                }
            }
            

        }
        #endregion

        #region Win32API
        [DllImport("shell32.dll")]
        private static extern int DllGetVersion(ref DLLVERSIONINFO pdvi);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);
        #endregion
    }
}
