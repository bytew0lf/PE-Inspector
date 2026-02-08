using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

namespace PECoff
{
    public enum ParseIssueSeverity
    {
        Ignore = 0,
        Warning = 1,
        Error = 2
    }

    public enum ParseIssueCategory
    {
        General = 0,
        File = 1,
        Header = 2,
        OptionalHeader = 3,
        Sections = 4,
        Imports = 5,
        Exports = 6,
        Resources = 7,
        Certificates = 8,
        CLR = 9,
        Metadata = 10,
        Checksum = 11,
        AssemblyAnalysis = 12,
        Debug = 13,
        Relocations = 14,
        Tls = 15,
        LoadConfig = 16,
        Authenticode = 17
    }

    public enum ValidationProfile
    {
        Default = 0,
        Compatibility = 1,
        Strict = 2,
        Forensic = 3
    }

    public sealed class ParseIssue
    {
        public ParseIssueCategory Category { get; }
        public ParseIssueSeverity Severity { get; }
        public string Message { get; }

        public ParseIssue(ParseIssueCategory category, ParseIssueSeverity severity, string message)
        {
            Category = category;
            Severity = severity;
            Message = message ?? string.Empty;
        }
    }

    public sealed class PECOFFOptions
    {
        public bool StrictMode { get; init; }
        public ValidationProfile ValidationProfile { get; init; }
        public bool EnableAssemblyAnalysis { get; init; } = true;
        public bool ComputeHash { get; init; } = true;
        public bool ComputeImportHash { get; init; } = true;
        public bool ComputeChecksum { get; init; } = true;
        public bool ComputeSectionEntropy { get; init; } = true;
        public bool ParseCertificateSigners { get; init; } = true;
        public bool ComputeAuthenticode { get; init; } = true;
        public bool ComputeManagedResourceHashes { get; init; }
        public bool UseMemoryMappedFile { get; init; }
        public bool LazyParseDataDirectories { get; init; }
        public string ApiSetSchemaPath { get; init; } = string.Empty;
        public AuthenticodePolicy AuthenticodePolicy { get; init; } = new AuthenticodePolicy();
        public Dictionary<ParseIssueCategory, ParseIssueSeverity> IssuePolicy { get; init; } = new Dictionary<ParseIssueCategory, ParseIssueSeverity>();
        public Action<ParseIssue> IssueCallback { get; init; }

        public static PECOFFOptions PresetFast()
        {
            return new PECOFFOptions
            {
                EnableAssemblyAnalysis = false,
                ComputeHash = false,
                ComputeImportHash = false,
                ComputeChecksum = false,
                ComputeSectionEntropy = false,
                ParseCertificateSigners = false,
                ComputeAuthenticode = false,
                UseMemoryMappedFile = true,
                LazyParseDataDirectories = true
            };
        }

        public static PECOFFOptions PresetDefault()
        {
            return new PECOFFOptions();
        }

        public static PECOFFOptions PresetStrictSecurity()
        {
            return new PECOFFOptions
            {
                StrictMode = true,
                ParseCertificateSigners = true,
                ComputeAuthenticode = true,
                ComputeChecksum = true,
                AuthenticodePolicy = new AuthenticodePolicy
                {
                    RequireSignature = true,
                    RequireSignatureValid = true,
                    RequireChainValid = true,
                    RequireTimestamp = true,
                    RequireTimestampValid = true,
                    RequireCodeSigningEku = true,
                    EnableCertificateTransparencyLogCheck = true,
                    EnableCatalogSignatureCheck = true,
                    EnableTrustStoreCheck = true,
                    EnableWinTrustCheck = true,
                    RevocationMode = X509RevocationMode.Online,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot
                }
            };
        }
    }

    public sealed class AuthenticodePolicy
    {
        public bool RequireSignature { get; init; }
        public bool RequireSignatureValid { get; init; }
        public bool RequireChainValid { get; init; }
        public bool RequireTimestamp { get; init; }
        public bool RequireTimestampValid { get; init; }
        public bool RequireCodeSigningEku { get; init; }
        public bool RequireCertificateTransparency { get; init; }
        public bool EnableCertificateTransparencyLogCheck { get; init; }
        public bool EnableCatalogSignatureCheck { get; init; }
        public bool EnableTrustStoreCheck { get; init; } = true;
        public bool EnableWinTrustCheck { get; init; }
        public bool OfflineChainCheck { get; init; }
        public X509RevocationMode RevocationMode { get; init; } = X509RevocationMode.NoCheck;
        public X509RevocationFlag RevocationFlag { get; init; } = X509RevocationFlag.ExcludeRoot;
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
        public IReadOnlyList<ParseIssue> Issues { get; }
        public bool IsSuccess => Errors.Count == 0;

        public ParseResultSnapshot(IReadOnlyList<string> errors, IReadOnlyList<string> warnings, IReadOnlyList<ParseIssue> issues)
        {
            Errors = errors ?? Array.Empty<string>();
            Warnings = warnings ?? Array.Empty<string>();
            Issues = issues ?? Array.Empty<ParseIssue>();
        }
    }

    public enum DebugDirectoryType : uint
    {
        Unknown = 0,
        Coff = 1,
        CodeView = 2,
        Fpo = 3,
        Misc = 4,
        Exception = 5,
        Fixup = 6,
        OmapToSrc = 7,
        OmapFromSrc = 8,
        Borland = 9,
        Reserved10 = 10,
        Clsid = 11,
        VCFeature = 12,
        Pogo = 13,
        ILTCG = 14,
        MPX = 15,
        Repro = 16,
        EmbeddedPortablePdb = 17,
        Spgo = 18,
        PdbHash = 19,
        ExDllCharacteristics = 20
    }

    public sealed class DebugMiscInfo
    {
        public uint DataType { get; }
        public uint Length { get; }
        public bool IsUnicode { get; }
        public string Data { get; }

        public DebugMiscInfo(uint dataType, uint length, bool isUnicode, string data)
        {
            DataType = dataType;
            Length = length;
            IsUnicode = isUnicode;
            Data = data ?? string.Empty;
        }
    }

    public sealed class DebugOmapEntryInfo
    {
        public uint From { get; }
        public uint To { get; }

        public DebugOmapEntryInfo(uint from, uint to)
        {
            From = from;
            To = to;
        }
    }

    public sealed class DebugOmapInfo
    {
        public int TotalEntryCount { get; }
        public bool IsTruncated { get; }
        public IReadOnlyList<DebugOmapEntryInfo> Entries { get; }

        public DebugOmapInfo(int totalEntryCount, bool isTruncated, DebugOmapEntryInfo[] entries)
        {
            TotalEntryCount = totalEntryCount;
            IsTruncated = isTruncated;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<DebugOmapEntryInfo>());
        }
    }

    public sealed class DebugReproInfo
    {
        public uint DataLength { get; }
        public string Hash { get; }

        public DebugReproInfo(uint dataLength, string hash)
        {
            DataLength = dataLength;
            Hash = hash ?? string.Empty;
        }
    }

    public sealed class DebugEmbeddedPortablePdbInfo
    {
        public string Signature { get; }
        public uint UncompressedSize { get; }
        public uint CompressedSize { get; }
        public string PayloadHash { get; }
        public string Notes { get; }

        public DebugEmbeddedPortablePdbInfo(
            string signature,
            uint uncompressedSize,
            uint compressedSize,
            string payloadHash,
            string notes)
        {
            Signature = signature ?? string.Empty;
            UncompressedSize = uncompressedSize;
            CompressedSize = compressedSize;
            PayloadHash = payloadHash ?? string.Empty;
            Notes = notes ?? string.Empty;
        }
    }

    public sealed class DebugSpgoInfo
    {
        public uint DataLength { get; }
        public string Hash { get; }
        public string Preview { get; }

        public DebugSpgoInfo(uint dataLength, string hash, string preview)
        {
            DataLength = dataLength;
            Hash = hash ?? string.Empty;
            Preview = preview ?? string.Empty;
        }
    }

    public sealed class DebugPdbHashInfo
    {
        public uint Algorithm { get; }
        public string AlgorithmName { get; }
        public string Hash { get; }

        public DebugPdbHashInfo(uint algorithm, string algorithmName, string hash)
        {
            Algorithm = algorithm;
            AlgorithmName = algorithmName ?? string.Empty;
            Hash = hash ?? string.Empty;
        }
    }

    public sealed class DebugCoffInfo
    {
        public uint NumberOfSymbols { get; }
        public uint LvaToFirstSymbol { get; }
        public uint NumberOfLinenumbers { get; }
        public uint LvaToFirstLinenumber { get; }
        public uint RvaToFirstByteOfCode { get; }
        public uint RvaToLastByteOfCode { get; }
        public uint RvaToFirstByteOfData { get; }
        public uint RvaToLastByteOfData { get; }

        public DebugCoffInfo(
            uint numberOfSymbols,
            uint lvaToFirstSymbol,
            uint numberOfLinenumbers,
            uint lvaToFirstLinenumber,
            uint rvaToFirstByteOfCode,
            uint rvaToLastByteOfCode,
            uint rvaToFirstByteOfData,
            uint rvaToLastByteOfData)
        {
            NumberOfSymbols = numberOfSymbols;
            LvaToFirstSymbol = lvaToFirstSymbol;
            NumberOfLinenumbers = numberOfLinenumbers;
            LvaToFirstLinenumber = lvaToFirstLinenumber;
            RvaToFirstByteOfCode = rvaToFirstByteOfCode;
            RvaToLastByteOfCode = rvaToLastByteOfCode;
            RvaToFirstByteOfData = rvaToFirstByteOfData;
            RvaToLastByteOfData = rvaToLastByteOfData;
        }
    }

    public sealed class DebugClsidInfo
    {
        public Guid ClassId { get; }

        public DebugClsidInfo(Guid classId)
        {
            ClassId = classId;
        }
    }

    public sealed class DebugRawInfo
    {
        public uint DataLength { get; }
        public string Sha256 { get; }
        public string Preview { get; }

        public DebugRawInfo(uint dataLength, string sha256, string preview)
        {
            DataLength = dataLength;
            Sha256 = sha256 ?? string.Empty;
            Preview = preview ?? string.Empty;
        }
    }

    public sealed class DebugPogoEntryInfo
    {
        public uint Rva { get; }
        public uint Size { get; }
        public string Name { get; }

        public DebugPogoEntryInfo(uint rva, uint size, string name)
        {
            Rva = rva;
            Size = size;
            Name = name ?? string.Empty;
        }
    }

    public sealed class DebugPogoInfo
    {
        public string Signature { get; }
        public int TotalEntryCount { get; }
        public bool IsTruncated { get; }
        public IReadOnlyList<DebugPogoEntryInfo> Entries { get; }

        public DebugPogoInfo(string signature, int totalEntryCount, bool isTruncated, DebugPogoEntryInfo[] entries)
        {
            Signature = signature ?? string.Empty;
            TotalEntryCount = totalEntryCount;
            IsTruncated = isTruncated;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<DebugPogoEntryInfo>());
        }
    }

    public sealed class DebugVcFeatureInfo
    {
        public uint Flags { get; }
        public IReadOnlyList<string> FlagNames { get; }

        public DebugVcFeatureInfo(uint flags, string[] flagNames)
        {
            Flags = flags;
            FlagNames = Array.AsReadOnly(flagNames ?? Array.Empty<string>());
        }
    }

    public sealed class DebugExDllCharacteristicsInfo
    {
        public uint Characteristics { get; }
        public IReadOnlyList<string> FlagNames { get; }

        public DebugExDllCharacteristicsInfo(uint characteristics, string[] flagNames)
        {
            Characteristics = characteristics;
            FlagNames = Array.AsReadOnly(flagNames ?? Array.Empty<string>());
        }
    }

    public sealed class DebugFpoEntryInfo
    {
        public uint StartOffset { get; }
        public uint ProcedureSize { get; }
        public uint LocalBytes { get; }
        public ushort ParameterBytes { get; }
        public byte PrologSize { get; }
        public byte SavedRegisterCount { get; }
        public bool HasSeh { get; }
        public bool UsesBasePointer { get; }
        public byte FrameType { get; }

        public DebugFpoEntryInfo(
            uint startOffset,
            uint procedureSize,
            uint localBytes,
            ushort parameterBytes,
            byte prologSize,
            byte savedRegisterCount,
            bool hasSeh,
            bool usesBasePointer,
            byte frameType)
        {
            StartOffset = startOffset;
            ProcedureSize = procedureSize;
            LocalBytes = localBytes;
            ParameterBytes = parameterBytes;
            PrologSize = prologSize;
            SavedRegisterCount = savedRegisterCount;
            HasSeh = hasSeh;
            UsesBasePointer = usesBasePointer;
            FrameType = frameType;
        }
    }

    public sealed class DebugFpoInfo
    {
        public int TotalEntryCount { get; }
        public bool IsTruncated { get; }
        public IReadOnlyList<DebugFpoEntryInfo> Entries { get; }

        public DebugFpoInfo(int totalEntryCount, bool isTruncated, DebugFpoEntryInfo[] entries)
        {
            TotalEntryCount = totalEntryCount;
            IsTruncated = isTruncated;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<DebugFpoEntryInfo>());
        }
    }

    public sealed class DebugBorlandInfo
    {
        public uint Version { get; }
        public uint Flags { get; }
        public IReadOnlyList<uint> Offsets { get; }

        public DebugBorlandInfo(uint version, uint flags, uint[] offsets)
        {
            Version = version;
            Flags = flags;
            Offsets = Array.AsReadOnly(offsets ?? Array.Empty<uint>());
        }
    }

    public sealed class DebugReservedInfo
    {
        public uint Version { get; }
        public uint Flags { get; }
        public IReadOnlyList<uint> Offsets { get; }

        public DebugReservedInfo(uint version, uint flags, uint[] offsets)
        {
            Version = version;
            Flags = flags;
            Offsets = Array.AsReadOnly(offsets ?? Array.Empty<uint>());
        }
    }

    public sealed class DebugCodeViewInfo
    {
        public string Signature { get; }
        public Guid Guid { get; }
        public uint Age { get; }
        public string PdbPath { get; }
        public string PdbFileName { get; }
        public string PdbPathSanitized { get; }
        public string PdbId { get; }
        public uint PdbSignature { get; }
        public uint PdbTimeDateStamp { get; }
        public bool HasPdbTimeDateStamp { get; }
        public bool TimeDateStampMatches { get; }
        public bool IsRsds { get; }
        public bool IsNb10 { get; }
        public bool HasValidGuid { get; }
        public bool HasValidAge { get; }
        public bool HasPdbPath { get; }
        public bool PdbPathEndsWithPdb { get; }
        public bool PdbPathHasDirectory { get; }
        public bool IdentityLooksValid { get; }

        public DebugCodeViewInfo(
            string signature,
            Guid guid,
            uint age,
            string pdbPath,
            string pdbFileName,
            string pdbPathSanitized,
            string pdbId,
            uint pdbSignature,
            uint pdbTimeDateStamp,
            bool hasPdbTimeDateStamp,
            bool timeDateStampMatches,
            bool isRsds,
            bool isNb10,
            bool hasValidGuid,
            bool hasValidAge,
            bool hasPdbPath,
            bool pdbPathEndsWithPdb,
            bool pdbPathHasDirectory,
            bool identityLooksValid)
        {
            Signature = signature ?? string.Empty;
            Guid = guid;
            Age = age;
            PdbPath = pdbPath ?? string.Empty;
            PdbFileName = pdbFileName ?? string.Empty;
            PdbPathSanitized = pdbPathSanitized ?? string.Empty;
            PdbId = pdbId ?? string.Empty;
            PdbSignature = pdbSignature;
            PdbTimeDateStamp = pdbTimeDateStamp;
            HasPdbTimeDateStamp = hasPdbTimeDateStamp;
            TimeDateStampMatches = timeDateStampMatches;
            IsRsds = isRsds;
            IsNb10 = isNb10;
            HasValidGuid = hasValidGuid;
            HasValidAge = hasValidAge;
            HasPdbPath = hasPdbPath;
            PdbPathEndsWithPdb = pdbPathEndsWithPdb;
            PdbPathHasDirectory = pdbPathHasDirectory;
            IdentityLooksValid = identityLooksValid;
        }
    }

    public sealed class PdbDbiInfo
    {
        public int Signature { get; }
        public int Version { get; }
        public int Age { get; }
        public ushort GlobalStreamIndex { get; }
        public ushort PublicStreamIndex { get; }
        public ushort SymRecordStreamIndex { get; }
        public ushort Machine { get; }
        public ushort Flags { get; }
        public int ModuleInfoSize { get; }
        public int SectionContribSize { get; }
        public int SectionMapSize { get; }
        public int SourceInfoSize { get; }
        public int OptionalDbgHeaderSize { get; }
        public int TypeServerSize { get; }
        public int EcSubstreamSize { get; }
        public string Notes { get; }

        public PdbDbiInfo(
            int signature,
            int version,
            int age,
            ushort globalStreamIndex,
            ushort publicStreamIndex,
            ushort symRecordStreamIndex,
            ushort machine,
            ushort flags,
            int moduleInfoSize,
            int sectionContribSize,
            int sectionMapSize,
            int sourceInfoSize,
            int optionalDbgHeaderSize,
            int typeServerSize,
            int ecSubstreamSize,
            string notes)
        {
            Signature = signature;
            Version = version;
            Age = age;
            GlobalStreamIndex = globalStreamIndex;
            PublicStreamIndex = publicStreamIndex;
            SymRecordStreamIndex = symRecordStreamIndex;
            Machine = machine;
            Flags = flags;
            ModuleInfoSize = moduleInfoSize;
            SectionContribSize = sectionContribSize;
            SectionMapSize = sectionMapSize;
            SourceInfoSize = sourceInfoSize;
            OptionalDbgHeaderSize = optionalDbgHeaderSize;
            TypeServerSize = typeServerSize;
            EcSubstreamSize = ecSubstreamSize;
            Notes = notes ?? string.Empty;
        }
    }

    public sealed class PdbTpiInfo
    {
        public uint Version { get; }
        public uint HeaderSize { get; }
        public uint TypeIndexBegin { get; }
        public uint TypeIndexEnd { get; }
        public uint TypeRecordBytes { get; }
        public ushort HashStreamIndex { get; }
        public ushort HashAuxStreamIndex { get; }
        public uint HashKeySize { get; }
        public uint HashBucketCount { get; }
        public uint HashValueBufferLength { get; }
        public uint IndexOffsetBufferLength { get; }
        public uint HashAdjBufferLength { get; }
        public int TypeCount => TypeIndexEnd > TypeIndexBegin ? (int)(TypeIndexEnd - TypeIndexBegin) : 0;
        public string Notes { get; }

        public PdbTpiInfo(
            uint version,
            uint headerSize,
            uint typeIndexBegin,
            uint typeIndexEnd,
            uint typeRecordBytes,
            ushort hashStreamIndex,
            ushort hashAuxStreamIndex,
            uint hashKeySize,
            uint hashBucketCount,
            uint hashValueBufferLength,
            uint indexOffsetBufferLength,
            uint hashAdjBufferLength,
            string notes)
        {
            Version = version;
            HeaderSize = headerSize;
            TypeIndexBegin = typeIndexBegin;
            TypeIndexEnd = typeIndexEnd;
            TypeRecordBytes = typeRecordBytes;
            HashStreamIndex = hashStreamIndex;
            HashAuxStreamIndex = hashAuxStreamIndex;
            HashKeySize = hashKeySize;
            HashBucketCount = hashBucketCount;
            HashValueBufferLength = hashValueBufferLength;
            IndexOffsetBufferLength = indexOffsetBufferLength;
            HashAdjBufferLength = hashAdjBufferLength;
            Notes = notes ?? string.Empty;
        }
    }

    public sealed class PdbGsiInfo
    {
        public string Kind { get; }
        public int StreamIndex { get; }
        public uint StreamSize { get; }
        public uint Signature { get; }
        public uint Version { get; }
        public int NameCount { get; }
        public IReadOnlyList<string> Names { get; }
        public string Notes { get; }

        public PdbGsiInfo(
            string kind,
            int streamIndex,
            uint streamSize,
            uint signature,
            uint version,
            string[] names,
            string notes)
        {
            Kind = kind ?? string.Empty;
            StreamIndex = streamIndex;
            StreamSize = streamSize;
            Signature = signature;
            Version = version;
            Names = Array.AsReadOnly(names ?? Array.Empty<string>());
            NameCount = Names.Count;
            Notes = notes ?? string.Empty;
        }
    }

    public sealed class PdbInfo
    {
        public string Path { get; }
        public string Format { get; }
        public uint PageSize { get; }
        public uint StreamCount { get; }
        public uint DirectorySize { get; }
        public uint PdbSignature { get; }
        public Guid Guid { get; }
        public uint Age { get; }
        public int PublicSymbolCount { get; }
        public IReadOnlyList<string> PublicSymbols { get; }
        public PdbDbiInfo Dbi { get; }
        public PdbTpiInfo Tpi { get; }
        public PdbTpiInfo Ipi { get; }
        public PdbGsiInfo Publics { get; }
        public PdbGsiInfo Globals { get; }
        public string Notes { get; }

        public PdbInfo(
            string path,
            string format,
            uint pageSize,
            uint streamCount,
            uint directorySize,
            uint pdbSignature,
            Guid guid,
            uint age,
            int publicSymbolCount,
            string[] publicSymbols,
            PdbDbiInfo dbi,
            PdbTpiInfo tpi,
            PdbTpiInfo ipi,
            PdbGsiInfo publics,
            PdbGsiInfo globals,
            string notes)
        {
            Path = path ?? string.Empty;
            Format = format ?? string.Empty;
            PageSize = pageSize;
            StreamCount = streamCount;
            DirectorySize = directorySize;
            PdbSignature = pdbSignature;
            Guid = guid;
            Age = age;
            PublicSymbolCount = publicSymbolCount;
            PublicSymbols = Array.AsReadOnly(publicSymbols ?? Array.Empty<string>());
            Dbi = dbi;
            Tpi = tpi;
            Ipi = ipi;
            Publics = publics;
            Globals = globals;
            Notes = notes ?? string.Empty;
        }
    }

    public sealed class DebugDirectoryEntry
    {
        public uint Characteristics { get; }
        public uint TimeDateStamp { get; }
        public ushort MajorVersion { get; }
        public ushort MinorVersion { get; }
        public DebugDirectoryType Type { get; }
        public uint SizeOfData { get; }
        public uint AddressOfRawData { get; }
        public uint PointerToRawData { get; }
        public DebugCodeViewInfo CodeView { get; }
        public PdbInfo Pdb { get; }
        public DebugCoffInfo Coff { get; }
        public DebugPogoInfo Pogo { get; }
        public DebugVcFeatureInfo VcFeature { get; }
        public DebugExDllCharacteristicsInfo ExDllCharacteristics { get; }
        public DebugFpoInfo Fpo { get; }
        public DebugBorlandInfo Borland { get; }
        public DebugReservedInfo Reserved { get; }
        public DebugRawInfo Fixup { get; }
        public DebugMiscInfo Misc { get; }
        public DebugOmapInfo OmapToSource { get; }
        public DebugOmapInfo OmapFromSource { get; }
        public DebugReproInfo Repro { get; }
        public DebugEmbeddedPortablePdbInfo EmbeddedPortablePdb { get; }
        public DebugSpgoInfo Spgo { get; }
        public DebugPdbHashInfo PdbHash { get; }
        public DebugRawInfo Iltcg { get; }
        public DebugRawInfo Mpx { get; }
        public DebugClsidInfo Clsid { get; }
        public string Note { get; }

        public DebugDirectoryEntry(
            uint characteristics,
            uint timeDateStamp,
            ushort majorVersion,
            ushort minorVersion,
            DebugDirectoryType type,
            uint sizeOfData,
            uint addressOfRawData,
            uint pointerToRawData,
            DebugCodeViewInfo codeView,
            PdbInfo pdb,
            DebugCoffInfo coff,
            DebugPogoInfo pogo,
            DebugVcFeatureInfo vcFeature,
            DebugExDllCharacteristicsInfo exDllCharacteristics,
            DebugFpoInfo fpo,
            DebugBorlandInfo borland,
            DebugReservedInfo reserved,
            DebugRawInfo fixup,
            DebugMiscInfo misc,
            DebugOmapInfo omapToSource,
            DebugOmapInfo omapFromSource,
            DebugReproInfo repro,
            DebugEmbeddedPortablePdbInfo embeddedPortablePdb,
            DebugSpgoInfo spgo,
            DebugPdbHashInfo pdbHash,
            DebugRawInfo iltcg,
            DebugRawInfo mpx,
            DebugClsidInfo clsid,
            string note)
        {
            Characteristics = characteristics;
            TimeDateStamp = timeDateStamp;
            MajorVersion = majorVersion;
            MinorVersion = minorVersion;
            Type = type;
            SizeOfData = sizeOfData;
            AddressOfRawData = addressOfRawData;
            PointerToRawData = pointerToRawData;
            CodeView = codeView;
            Pdb = pdb;
            Coff = coff;
            Pogo = pogo;
            VcFeature = vcFeature;
            ExDllCharacteristics = exDllCharacteristics;
            Fpo = fpo;
            Borland = borland;
            Reserved = reserved;
            Fixup = fixup;
            Misc = misc;
            OmapToSource = omapToSource;
            OmapFromSource = omapFromSource;
            Repro = repro;
            EmbeddedPortablePdb = embeddedPortablePdb;
            Spgo = spgo;
            PdbHash = pdbHash;
            Iltcg = iltcg;
            Mpx = mpx;
            Clsid = clsid;
            Note = note ?? string.Empty;
        }
    }

    public sealed class RichHeaderEntry
    {
        public ushort ProductId { get; }
        public ushort BuildNumber { get; }
        public uint Count { get; }
        public uint RawCompId { get; }
        public string ProductName { get; }
        public string ToolchainVersion { get; }

        public RichHeaderEntry(
            ushort productId,
            ushort buildNumber,
            uint count,
            uint rawCompId,
            string productName,
            string toolchainVersion)
        {
            ProductId = productId;
            BuildNumber = buildNumber;
            Count = count;
            RawCompId = rawCompId;
            ProductName = productName ?? string.Empty;
            ToolchainVersion = toolchainVersion ?? string.Empty;
        }
    }

    public sealed class RichHeaderInfo
    {
        public uint Key { get; }
        public IReadOnlyList<RichHeaderEntry> Entries { get; }
        public IReadOnlyList<RichToolchainInfo> Toolchains { get; }

        public RichHeaderInfo(uint key, RichHeaderEntry[] entries, RichToolchainInfo[] toolchains)
        {
            Key = key;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<RichHeaderEntry>());
            Toolchains = Array.AsReadOnly(toolchains ?? Array.Empty<RichToolchainInfo>());
        }
    }

    public sealed class RichToolchainInfo
    {
        public string Version { get; }
        public string Name { get; }
        public uint TotalCount { get; }
        public IReadOnlyList<string> Tools { get; }

        public RichToolchainInfo(string version, string name, uint totalCount, string[] tools)
        {
            Version = version ?? string.Empty;
            Name = name ?? string.Empty;
            TotalCount = totalCount;
            Tools = Array.AsReadOnly(tools ?? Array.Empty<string>());
        }
    }

    public sealed class ExceptionFunctionInfo
    {
        public uint BeginAddress { get; }
        public uint EndAddress { get; }
        public uint UnwindInfoAddress { get; }

        public ExceptionFunctionInfo(uint beginAddress, uint endAddress, uint unwindInfoAddress)
        {
            BeginAddress = beginAddress;
            EndAddress = endAddress;
            UnwindInfoAddress = unwindInfoAddress;
        }
    }

    public sealed class UnwindCodeInfo
    {
        public byte CodeOffset { get; }
        public byte UnwindOp { get; }
        public byte OpInfo { get; }

        public UnwindCodeInfo(byte codeOffset, byte unwindOp, byte opInfo)
        {
            CodeOffset = codeOffset;
            UnwindOp = unwindOp;
            OpInfo = opInfo;
        }
    }

    public sealed class UnwindInfoDetail
    {
        public uint FunctionBegin { get; }
        public uint FunctionEnd { get; }
        public uint UnwindInfoAddress { get; }
        public byte Version { get; }
        public byte Flags { get; }
        public byte PrologSize { get; }
        public byte CodeCount { get; }
        public byte FrameRegister { get; }
        public byte FrameOffset { get; }
        public bool HasChainedInfo { get; }
        public bool PrologSizeExceedsFunction { get; }
        public IReadOnlyList<UnwindCodeInfo> UnwindCodes { get; }

        public UnwindInfoDetail(
            uint functionBegin,
            uint functionEnd,
            uint unwindInfoAddress,
            byte version,
            byte flags,
            byte prologSize,
            byte codeCount,
            byte frameRegister,
            byte frameOffset,
            bool hasChainedInfo,
            bool prologSizeExceedsFunction,
            UnwindCodeInfo[] unwindCodes)
        {
            FunctionBegin = functionBegin;
            FunctionEnd = functionEnd;
            UnwindInfoAddress = unwindInfoAddress;
            Version = version;
            Flags = flags;
            PrologSize = prologSize;
            CodeCount = codeCount;
            FrameRegister = frameRegister;
            FrameOffset = frameOffset;
            HasChainedInfo = hasChainedInfo;
            PrologSizeExceedsFunction = prologSizeExceedsFunction;
            UnwindCodes = Array.AsReadOnly(unwindCodes ?? Array.Empty<UnwindCodeInfo>());
        }
    }

    public sealed class Arm64UnwindInfoDetail
    {
        public uint FunctionBegin { get; }
        public uint FunctionEnd { get; }
        public uint UnwindInfoAddress { get; }
        public uint Header { get; }
        public int FunctionLengthBytes { get; }
        public byte Version { get; }
        public bool HasXFlag { get; }
        public bool HasEpilogFlag { get; }
        public int EpilogCount { get; }
        public int CodeWords { get; }
        public int SizeBytes { get; }
        public uint ExceptionHandlerRva { get; }
        public IReadOnlyList<Arm64EpilogScopeInfo> EpilogScopes { get; }
        public IReadOnlyList<Arm64UnwindCodeInfo> UnwindCodes { get; }
        public string RawPreview { get; }

        public Arm64UnwindInfoDetail(
            uint functionBegin,
            uint functionEnd,
            uint unwindInfoAddress,
            uint header,
            int functionLengthBytes,
            byte version,
            bool hasXFlag,
            bool hasEpilogFlag,
            int epilogCount,
            int codeWords,
            int sizeBytes,
            uint exceptionHandlerRva,
            Arm64EpilogScopeInfo[] epilogScopes,
            Arm64UnwindCodeInfo[] unwindCodes,
            string rawPreview)
        {
            FunctionBegin = functionBegin;
            FunctionEnd = functionEnd;
            UnwindInfoAddress = unwindInfoAddress;
            Header = header;
            FunctionLengthBytes = functionLengthBytes;
            Version = version;
            HasXFlag = hasXFlag;
            HasEpilogFlag = hasEpilogFlag;
            EpilogCount = epilogCount;
            CodeWords = codeWords;
            SizeBytes = sizeBytes;
            ExceptionHandlerRva = exceptionHandlerRva;
            EpilogScopes = Array.AsReadOnly(epilogScopes ?? Array.Empty<Arm64EpilogScopeInfo>());
            UnwindCodes = Array.AsReadOnly(unwindCodes ?? Array.Empty<Arm64UnwindCodeInfo>());
            RawPreview = rawPreview ?? string.Empty;
        }
    }

    public sealed class Arm64EpilogScopeInfo
    {
        public int StartOffsetBytes { get; }
        public int StartIndex { get; }
        public bool IsPacked { get; }
        public bool ReservedBitsValid { get; }
        public bool HasValidIndex { get; }
        public bool HasValidOffset { get; }

        public Arm64EpilogScopeInfo(
            int startOffsetBytes,
            int startIndex,
            bool isPacked,
            bool reservedBitsValid,
            bool hasValidIndex,
            bool hasValidOffset)
        {
            StartOffsetBytes = startOffsetBytes;
            StartIndex = startIndex;
            IsPacked = isPacked;
            ReservedBitsValid = reservedBitsValid;
            HasValidIndex = hasValidIndex;
            HasValidOffset = hasValidOffset;
        }
    }

    public sealed class Arm64UnwindCodeInfo
    {
        public int ByteIndex { get; }
        public int Length { get; }
        public string OpCode { get; }
        public string Details { get; }
        public string RawBytes { get; }

        public Arm64UnwindCodeInfo(int byteIndex, int length, string opCode, string details, string rawBytes)
        {
            ByteIndex = byteIndex;
            Length = length;
            OpCode = opCode ?? string.Empty;
            Details = details ?? string.Empty;
            RawBytes = rawBytes ?? string.Empty;
        }
    }

    public sealed class Arm32UnwindInfoDetail
    {
        public uint FunctionBegin { get; }
        public uint FunctionEnd { get; }
        public uint UnwindInfoAddress { get; }
        public uint Header { get; }
        public int FunctionLengthBytes { get; }
        public byte Version { get; }
        public bool HasExceptionData { get; }
        public bool HasEpilogFlag { get; }
        public bool IsFragment { get; }
        public int EpilogCount { get; }
        public int CodeWords { get; }
        public uint ReservedBits { get; }
        public bool ReservedBitsValid { get; }
        public uint ExceptionHandlerRva { get; }
        public IReadOnlyList<uint> EpilogScopes { get; }
        public IReadOnlyList<uint> UnwindCodeWords { get; }
        public int OpcodeCount { get; }
        public bool HasFinishOpcode { get; }
        public IReadOnlyList<string> OpcodeSummaries { get; }
        public string RawPreview { get; }

        public Arm32UnwindInfoDetail(
            uint functionBegin,
            uint functionEnd,
            uint unwindInfoAddress,
            uint header,
            int functionLengthBytes,
            byte version,
            bool hasExceptionData,
            bool hasEpilogFlag,
            bool isFragment,
            int epilogCount,
            int codeWords,
            uint reservedBits,
            bool reservedBitsValid,
            uint exceptionHandlerRva,
            uint[] epilogScopes,
            uint[] unwindCodeWords,
            int opcodeCount,
            bool hasFinishOpcode,
            string[] opcodeSummaries,
            string rawPreview)
        {
            FunctionBegin = functionBegin;
            FunctionEnd = functionEnd;
            UnwindInfoAddress = unwindInfoAddress;
            Header = header;
            FunctionLengthBytes = functionLengthBytes;
            Version = version;
            HasExceptionData = hasExceptionData;
            HasEpilogFlag = hasEpilogFlag;
            IsFragment = isFragment;
            EpilogCount = epilogCount;
            CodeWords = codeWords;
            ReservedBits = reservedBits;
            ReservedBitsValid = reservedBitsValid;
            ExceptionHandlerRva = exceptionHandlerRva;
            EpilogScopes = Array.AsReadOnly(epilogScopes ?? Array.Empty<uint>());
            UnwindCodeWords = Array.AsReadOnly(unwindCodeWords ?? Array.Empty<uint>());
            OpcodeCount = opcodeCount;
            HasFinishOpcode = hasFinishOpcode;
            OpcodeSummaries = Array.AsReadOnly(opcodeSummaries ?? Array.Empty<string>());
            RawPreview = rawPreview ?? string.Empty;
        }
    }

    public sealed class Ia64UnwindInfoDetail
    {
        public uint FunctionBegin { get; }
        public uint FunctionEnd { get; }
        public uint UnwindInfoAddress { get; }
        public uint Header { get; }
        public byte Version { get; }
        public byte Flags { get; }
        public int DescriptorCount { get; }
        public int TrailingBytes { get; }
        public string DescriptorPreview { get; }
        public int SizeBytes { get; }
        public string RawPreview { get; }

        public Ia64UnwindInfoDetail(
            uint functionBegin,
            uint functionEnd,
            uint unwindInfoAddress,
            uint header,
            byte version,
            byte flags,
            int descriptorCount,
            int trailingBytes,
            string descriptorPreview,
            int sizeBytes,
            string rawPreview)
        {
            FunctionBegin = functionBegin;
            FunctionEnd = functionEnd;
            UnwindInfoAddress = unwindInfoAddress;
            Header = header;
            Version = version;
            Flags = flags;
            DescriptorCount = descriptorCount;
            TrailingBytes = trailingBytes;
            DescriptorPreview = descriptorPreview ?? string.Empty;
            SizeBytes = sizeBytes;
            RawPreview = rawPreview ?? string.Empty;
        }
    }

    public sealed class UnwindInfoVersionCount
    {
        public byte Version { get; }
        public int Count { get; }

        public UnwindInfoVersionCount(byte version, int count)
        {
            Version = version;
            Count = count;
        }
    }

    public sealed class ExceptionDirectorySummary
    {
        public uint DirectoryRva { get; }
        public uint DirectorySize { get; }
        public string DirectorySection { get; }
        public bool DirectoryInPdata { get; }
        public int FunctionCount { get; }
        public int InvalidRangeCount { get; }
        public int OutOfRangeCount { get; }
        public int UnwindInfoCount { get; }
        public int UnwindInfoParseFailures { get; }
        public IReadOnlyList<UnwindInfoVersionCount> UnwindInfoVersions { get; }

        public ExceptionDirectorySummary(
            uint directoryRva,
            uint directorySize,
            string directorySection,
            bool directoryInPdata,
            int functionCount,
            int invalidRangeCount,
            int outOfRangeCount,
            int unwindInfoCount,
            int unwindInfoParseFailures,
            UnwindInfoVersionCount[] unwindInfoVersions)
        {
            DirectoryRva = directoryRva;
            DirectorySize = directorySize;
            DirectorySection = directorySection ?? string.Empty;
            DirectoryInPdata = directoryInPdata;
            FunctionCount = functionCount;
            InvalidRangeCount = invalidRangeCount;
            OutOfRangeCount = outOfRangeCount;
            UnwindInfoCount = unwindInfoCount;
            UnwindInfoParseFailures = unwindInfoParseFailures;
            UnwindInfoVersions = Array.AsReadOnly(unwindInfoVersions ?? Array.Empty<UnwindInfoVersionCount>());
        }
    }

    public sealed class DosRelocationEntry
    {
        public ushort Offset { get; }
        public ushort Segment { get; }
        public uint LinearAddress { get; }

        public DosRelocationEntry(ushort offset, ushort segment)
        {
            Offset = offset;
            Segment = segment;
            LinearAddress = (uint)(segment * 16 + offset);
        }
    }

    public sealed class DosRelocationInfo
    {
        public int DeclaredCount { get; }
        public uint TableOffset { get; }
        public bool IsTruncated { get; }
        public IReadOnlyList<DosRelocationEntry> Entries { get; }

        public DosRelocationInfo(int declaredCount, uint tableOffset, bool isTruncated, DosRelocationEntry[] entries)
        {
            DeclaredCount = declaredCount;
            TableOffset = tableOffset;
            IsTruncated = isTruncated;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<DosRelocationEntry>());
        }
    }

    public sealed class RelocationAnomalySummary
    {
        public int ZeroSizedBlockCount { get; }
        public int EmptyBlockCount { get; }
        public int InvalidBlockCount { get; }
        public int OrphanedBlockCount { get; }
        public int DiscardableBlockCount { get; }

        public RelocationAnomalySummary(
            int zeroSizedBlockCount,
            int emptyBlockCount,
            int invalidBlockCount,
            int orphanedBlockCount,
            int discardableBlockCount)
        {
            ZeroSizedBlockCount = zeroSizedBlockCount;
            EmptyBlockCount = emptyBlockCount;
            InvalidBlockCount = invalidBlockCount;
            OrphanedBlockCount = orphanedBlockCount;
            DiscardableBlockCount = discardableBlockCount;
        }
    }

    public sealed class BaseRelocationBlockInfo
    {
        public uint PageRva { get; }
        public uint BlockSize { get; }
        public int EntryCount { get; }
        public IReadOnlyList<int> TypeCounts { get; }
        public int ReservedTypeCount { get; }
        public int OutOfRangeCount { get; }
        public int UnmappedCount { get; }
        public bool IsPageAligned { get; }

        public BaseRelocationBlockInfo(
            uint pageRva,
            uint blockSize,
            int entryCount,
            int[] typeCounts,
            int reservedTypeCount,
            int outOfRangeCount,
            int unmappedCount,
            bool isPageAligned)
        {
            PageRva = pageRva;
            BlockSize = blockSize;
            EntryCount = entryCount;
            TypeCounts = typeCounts ?? Array.Empty<int>();
            ReservedTypeCount = reservedTypeCount;
            OutOfRangeCount = outOfRangeCount;
            UnmappedCount = unmappedCount;
            IsPageAligned = isPageAligned;
        }
    }

    public sealed class RelocationTypeSummary
    {
        public int Type { get; }
        public string Name { get; }
        public int Count { get; }

        public RelocationTypeSummary(int type, string name, int count)
        {
            Type = type;
            Name = name ?? string.Empty;
            Count = count;
        }
    }

    public sealed class RelocationSampleInfo
    {
        public uint Rva { get; }
        public int Type { get; }
        public string TypeName { get; }

        public RelocationSampleInfo(uint rva, int type, string typeName)
        {
            Rva = rva;
            Type = type;
            TypeName = typeName ?? string.Empty;
        }
    }

    public sealed class BaseRelocationSectionSummary
    {
        public string SectionName { get; }
        public uint SectionRva { get; }
        public uint SectionSize { get; }
        public int BlockCount { get; }
        public int EntryCount { get; }
        public IReadOnlyList<int> TypeCounts { get; }
        public int ReservedTypeCount { get; }
        public int OutOfRangeCount { get; }
        public int UnmappedCount { get; }
        public IReadOnlyList<RelocationTypeSummary> TopTypes { get; }
        public IReadOnlyList<RelocationSampleInfo> Samples { get; }

        public BaseRelocationSectionSummary(
            string sectionName,
            uint sectionRva,
            uint sectionSize,
            int blockCount,
            int entryCount,
            int[] typeCounts,
            int reservedTypeCount,
            int outOfRangeCount,
            int unmappedCount,
            RelocationTypeSummary[] topTypes,
            RelocationSampleInfo[] samples)
        {
            SectionName = sectionName ?? string.Empty;
            SectionRva = sectionRva;
            SectionSize = sectionSize;
            BlockCount = blockCount;
            EntryCount = entryCount;
            TypeCounts = Array.AsReadOnly(typeCounts ?? Array.Empty<int>());
            ReservedTypeCount = reservedTypeCount;
            OutOfRangeCount = outOfRangeCount;
            UnmappedCount = unmappedCount;
            TopTypes = Array.AsReadOnly(topTypes ?? Array.Empty<RelocationTypeSummary>());
            Samples = Array.AsReadOnly(samples ?? Array.Empty<RelocationSampleInfo>());
        }
    }

    public sealed class TlsInfo
    {
        public ulong StartAddressOfRawData { get; }
        public ulong EndAddressOfRawData { get; }
        public ulong AddressOfIndex { get; }
        public ulong AddressOfCallbacks { get; }
        public uint SizeOfZeroFill { get; }
        public uint Characteristics { get; }
        public uint RawDataSize { get; }
        public uint RawDataRva { get; }
        public bool RawDataMapped { get; }
        public string RawDataSectionName { get; }
        public int AlignmentBytes { get; }
        public TlsTemplateInfo Template { get; }
        public string RawDataSha256 { get; }
        public bool RawDataPreviewIsText { get; }
        public string RawDataPreview { get; }
        public IReadOnlyList<ulong> CallbackAddresses { get; }
        public IReadOnlyList<TlsCallbackInfo> CallbackInfos { get; }

        public TlsInfo(
            ulong startAddressOfRawData,
            ulong endAddressOfRawData,
            ulong addressOfIndex,
            ulong addressOfCallbacks,
            uint sizeOfZeroFill,
            uint characteristics,
            uint rawDataSize,
            uint rawDataRva,
            bool rawDataMapped,
            string rawDataSectionName,
            int alignmentBytes,
            TlsTemplateInfo template,
            string rawDataSha256,
            bool rawDataPreviewIsText,
            string rawDataPreview,
            ulong[] callbackAddresses,
            TlsCallbackInfo[] callbackInfos)
        {
            StartAddressOfRawData = startAddressOfRawData;
            EndAddressOfRawData = endAddressOfRawData;
            AddressOfIndex = addressOfIndex;
            AddressOfCallbacks = addressOfCallbacks;
            SizeOfZeroFill = sizeOfZeroFill;
            Characteristics = characteristics;
            RawDataSize = rawDataSize;
            RawDataRva = rawDataRva;
            RawDataMapped = rawDataMapped;
            RawDataSectionName = rawDataSectionName ?? string.Empty;
            AlignmentBytes = alignmentBytes;
            Template = template;
            RawDataSha256 = rawDataSha256 ?? string.Empty;
            RawDataPreviewIsText = rawDataPreviewIsText;
            RawDataPreview = rawDataPreview ?? string.Empty;
            CallbackAddresses = Array.AsReadOnly(callbackAddresses ?? Array.Empty<ulong>());
            CallbackInfos = Array.AsReadOnly(callbackInfos ?? Array.Empty<TlsCallbackInfo>());
        }
    }

    public sealed class TlsTemplateInfo
    {
        public uint RawDataSize { get; }
        public uint ZeroFillSize { get; }
        public uint TotalSize { get; }
        public bool RangeValid { get; }
        public uint RangeSize { get; }
        public bool SizeMatchesRange { get; }
        public bool IsAligned { get; }
        public string Notes { get; }
        public string Sha256 { get; }
        public bool PreviewIsText { get; }
        public string Preview { get; }

        public TlsTemplateInfo(
            uint rawDataSize,
            uint zeroFillSize,
            uint totalSize,
            bool rangeValid,
            uint rangeSize,
            bool sizeMatchesRange,
            bool isAligned,
            string notes,
            string sha256,
            bool previewIsText,
            string preview)
        {
            RawDataSize = rawDataSize;
            ZeroFillSize = zeroFillSize;
            TotalSize = totalSize;
            RangeValid = rangeValid;
            RangeSize = rangeSize;
            SizeMatchesRange = sizeMatchesRange;
            IsAligned = isAligned;
            Notes = notes ?? string.Empty;
            Sha256 = sha256 ?? string.Empty;
            PreviewIsText = previewIsText;
            Preview = preview ?? string.Empty;
        }
    }

    public sealed class TlsCallbackInfo
    {
        public ulong Address { get; }
        public uint Rva { get; }
        public string SymbolName { get; }
        public string SectionName { get; }
        public uint SectionRva { get; }
        public uint SectionOffset { get; }
        public string ResolutionSource { get; }

        public TlsCallbackInfo(
            ulong address,
            uint rva,
            string symbolName,
            string sectionName,
            uint sectionRva,
            uint sectionOffset,
            string resolutionSource)
        {
            Address = address;
            Rva = rva;
            SymbolName = symbolName ?? string.Empty;
            SectionName = sectionName ?? string.Empty;
            SectionRva = sectionRva;
            SectionOffset = sectionOffset;
            ResolutionSource = resolutionSource ?? string.Empty;
        }
    }

    public sealed class LoadConfigGuardFlagsInfo
    {
        public uint Value { get; }
        public IReadOnlyList<string> Flags { get; }
        public bool CfInstrumented { get; }
        public bool CfwInstrumented { get; }
        public bool CfFunctionTablePresent { get; }
        public bool SecurityCookieUnused { get; }
        public bool ProtectDelayLoadIat { get; }
        public bool DelayLoadIatInItsOwnSection { get; }
        public bool CfExportSuppressionInfoPresent { get; }
        public bool CfEnableExportSuppression { get; }
        public bool CfLongjumpTablePresent { get; }
        public bool RfInstrumented { get; }
        public bool RfEnable { get; }
        public bool RfStrict { get; }
        public bool RetpolinePresent { get; }
        public bool EhContinuationTablePresent { get; }
        public bool XfgEnabled { get; }
        public bool XfgTablePresent { get; }

        public LoadConfigGuardFlagsInfo(
            uint value,
            string[] flags,
            bool cfInstrumented,
            bool cfwInstrumented,
            bool cfFunctionTablePresent,
            bool securityCookieUnused,
            bool protectDelayLoadIat,
            bool delayLoadIatInItsOwnSection,
            bool cfExportSuppressionInfoPresent,
            bool cfEnableExportSuppression,
            bool cfLongjumpTablePresent,
            bool rfInstrumented,
            bool rfEnable,
            bool rfStrict,
            bool retpolinePresent,
            bool ehContinuationTablePresent,
            bool xfgEnabled,
            bool xfgTablePresent)
        {
            Value = value;
            Flags = Array.AsReadOnly(flags ?? Array.Empty<string>());
            CfInstrumented = cfInstrumented;
            CfwInstrumented = cfwInstrumented;
            CfFunctionTablePresent = cfFunctionTablePresent;
            SecurityCookieUnused = securityCookieUnused;
            ProtectDelayLoadIat = protectDelayLoadIat;
            DelayLoadIatInItsOwnSection = delayLoadIatInItsOwnSection;
            CfExportSuppressionInfoPresent = cfExportSuppressionInfoPresent;
            CfEnableExportSuppression = cfEnableExportSuppression;
            CfLongjumpTablePresent = cfLongjumpTablePresent;
            RfInstrumented = rfInstrumented;
            RfEnable = rfEnable;
            RfStrict = rfStrict;
            RetpolinePresent = retpolinePresent;
            EhContinuationTablePresent = ehContinuationTablePresent;
            XfgEnabled = xfgEnabled;
            XfgTablePresent = xfgTablePresent;
        }
    }

    public sealed class LoadConfigGlobalFlagsInfo
    {
        public uint Value { get; }
        public IReadOnlyList<string> Flags { get; }

        public LoadConfigGlobalFlagsInfo(uint value, string[] flags)
        {
            Value = value;
            Flags = Array.AsReadOnly(flags ?? Array.Empty<string>());
        }
    }

    public sealed class LoadConfigVersionInfo
    {
        public uint DeclaredSize { get; }
        public uint LimitBytes { get; }
        public uint ParsedBytes { get; }
        public uint TrailingBytes { get; }
        public string VersionHint { get; }
        public IReadOnlyList<string> FieldGroups { get; }
        public string TrailingHash { get; }
        public string TrailingPreview { get; }

        public LoadConfigVersionInfo(
            uint declaredSize,
            uint limitBytes,
            uint parsedBytes,
            uint trailingBytes,
            string versionHint,
            string[] fieldGroups,
            string trailingHash,
            string trailingPreview)
        {
            DeclaredSize = declaredSize;
            LimitBytes = limitBytes;
            ParsedBytes = parsedBytes;
            TrailingBytes = trailingBytes;
            VersionHint = versionHint ?? string.Empty;
            FieldGroups = Array.AsReadOnly(fieldGroups ?? Array.Empty<string>());
            TrailingHash = trailingHash ?? string.Empty;
            TrailingPreview = trailingPreview ?? string.Empty;
        }
    }

    public sealed class LoadConfigCodeIntegrityInfo
    {
        public ushort Flags { get; }
        public ushort Catalog { get; }
        public uint CatalogOffset { get; }
        public uint Reserved { get; }
        public IReadOnlyList<string> FlagNames { get; }

        public LoadConfigCodeIntegrityInfo(
            ushort flags,
            ushort catalog,
            uint catalogOffset,
            uint reserved,
            string[] flagNames)
        {
            Flags = flags;
            Catalog = catalog;
            CatalogOffset = catalogOffset;
            Reserved = reserved;
            FlagNames = Array.AsReadOnly(flagNames ?? Array.Empty<string>());
        }
    }

    public sealed class GuardRvaTableInfo
    {
        public string Name { get; }
        public ulong Pointer { get; }
        public ulong Count { get; }
        public uint EntrySize { get; }
        public bool IsMapped { get; }
        public string SectionName { get; }
        public bool SizeFits { get; }
        public bool IsTruncated { get; }
        public IReadOnlyList<uint> Entries { get; }

        public GuardRvaTableInfo(
            string name,
            ulong pointer,
            ulong count,
            uint entrySize,
            bool isMapped,
            string sectionName,
            bool sizeFits,
            bool isTruncated,
            uint[] entries)
        {
            Name = name ?? string.Empty;
            Pointer = pointer;
            Count = count;
            EntrySize = entrySize;
            IsMapped = isMapped;
            SectionName = sectionName ?? string.Empty;
            SizeFits = sizeFits;
            IsTruncated = isTruncated;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<uint>());
        }
    }

    public sealed class EnclaveConfigurationInfo
    {
        public uint Size { get; }
        public uint MinimumRequiredConfigSize { get; }
        public uint PolicyFlags { get; }
        public uint NumberOfImports { get; }
        public uint ImportListRva { get; }
        public uint ImportEntrySize { get; }
        public string FamilyId { get; }
        public string ImageId { get; }
        public uint ImageVersion { get; }
        public uint SecurityVersion { get; }
        public uint EnclaveSize { get; }
        public uint NumberOfThreads { get; }
        public uint EnclaveFlags { get; }
        public string SectionName { get; }
        public bool IsMapped { get; }
        public IReadOnlyList<string> PolicyFlagNames { get; }
        public IReadOnlyList<string> EnclaveFlagNames { get; }
        public IReadOnlyList<EnclaveImportInfo> Imports { get; }

        public EnclaveConfigurationInfo(
            uint size,
            uint minimumRequiredConfigSize,
            uint policyFlags,
            uint numberOfImports,
            uint importListRva,
            uint importEntrySize,
            string familyId,
            string imageId,
            uint imageVersion,
            uint securityVersion,
            uint enclaveSize,
            uint numberOfThreads,
            uint enclaveFlags,
            string sectionName,
            bool isMapped,
            string[] policyFlagNames,
            string[] enclaveFlagNames,
            EnclaveImportInfo[] imports)
        {
            Size = size;
            MinimumRequiredConfigSize = minimumRequiredConfigSize;
            PolicyFlags = policyFlags;
            NumberOfImports = numberOfImports;
            ImportListRva = importListRva;
            ImportEntrySize = importEntrySize;
            FamilyId = familyId ?? string.Empty;
            ImageId = imageId ?? string.Empty;
            ImageVersion = imageVersion;
            SecurityVersion = securityVersion;
            EnclaveSize = enclaveSize;
            NumberOfThreads = numberOfThreads;
            EnclaveFlags = enclaveFlags;
            SectionName = sectionName ?? string.Empty;
            IsMapped = isMapped;
            PolicyFlagNames = Array.AsReadOnly(policyFlagNames ?? Array.Empty<string>());
            EnclaveFlagNames = Array.AsReadOnly(enclaveFlagNames ?? Array.Empty<string>());
            Imports = Array.AsReadOnly(imports ?? Array.Empty<EnclaveImportInfo>());
        }
    }

    public sealed class EnclaveImportInfo
    {
        public int Index { get; }
        public uint MatchType { get; }
        public string MatchTypeName { get; }
        public uint MinimumSecurityVersion { get; }
        public string UniqueOrAuthorId { get; }
        public string FamilyId { get; }
        public string ImageId { get; }
        public uint ImportNameRva { get; }
        public string ImportName { get; }
        public uint Reserved { get; }

        public EnclaveImportInfo(
            int index,
            uint matchType,
            string matchTypeName,
            uint minimumSecurityVersion,
            string uniqueOrAuthorId,
            string familyId,
            string imageId,
            uint importNameRva,
            string importName,
            uint reserved)
        {
            Index = index;
            MatchType = matchType;
            MatchTypeName = matchTypeName ?? string.Empty;
            MinimumSecurityVersion = minimumSecurityVersion;
            UniqueOrAuthorId = uniqueOrAuthorId ?? string.Empty;
            FamilyId = familyId ?? string.Empty;
            ImageId = imageId ?? string.Empty;
            ImportNameRva = importNameRva;
            ImportName = importName ?? string.Empty;
            Reserved = reserved;
        }
    }

    public sealed class GuardFeatureInfo
    {
        public string Feature { get; }
        public bool Enabled { get; }
        public bool HasTable { get; }
        public bool HasPointer { get; }
        public string Notes { get; }

        public GuardFeatureInfo(string feature, bool enabled, bool hasTable, bool hasPointer, string notes)
        {
            Feature = feature ?? string.Empty;
            Enabled = enabled;
            HasTable = hasTable;
            HasPointer = hasPointer;
            Notes = notes ?? string.Empty;
        }
    }

    public sealed class LoadConfigInfo
    {
        public uint Size { get; }
        public LoadConfigVersionInfo VersionInfo { get; }
        public uint TimeDateStamp { get; }
        public ushort MajorVersion { get; }
        public ushort MinorVersion { get; }
        public uint GlobalFlagsClear { get; }
        public uint GlobalFlagsSet { get; }
        public LoadConfigGlobalFlagsInfo GlobalFlagsInfo { get; }
        public LoadConfigCodeIntegrityInfo CodeIntegrity { get; }
        public uint ProcessHeapFlags { get; }
        public uint CsdVersion { get; }
        public uint DependentLoadFlags { get; }
        public ulong SecurityCookie { get; }
        public ulong SeHandlerTable { get; }
        public uint SeHandlerCount { get; }
        public ulong GuardCfCheckFunctionPointer { get; }
        public ulong GuardCfDispatchFunctionPointer { get; }
        public ulong GuardCfFunctionTable { get; }
        public uint GuardCfFunctionCount { get; }
        public uint GuardFlags { get; }
        public LoadConfigGuardFlagsInfo GuardFlagsInfo { get; }
        public ulong DynamicValueRelocTable { get; }
        public uint DynamicValueRelocTableOffset { get; }
        public ushort DynamicValueRelocTableSection { get; }
        public ulong ChpeMetadataPointer { get; }
        public ulong GuardRFFailureRoutine { get; }
        public ulong GuardRFFailureRoutineFunctionPointer { get; }
        public ulong GuardRFVerifyStackPointerFunctionPointer { get; }
        public uint HotPatchTableOffset { get; }
        public ulong EnclaveConfigurationPointer { get; }
        public ulong VolatileMetadataPointer { get; }
        public ulong GuardEhContinuationTable { get; }
        public ulong GuardEhContinuationCount { get; }
        public ulong GuardXfgCheckFunctionPointer { get; }
        public ulong GuardXfgDispatchFunctionPointer { get; }
        public ulong GuardXfgTableDispatchFunctionPointer { get; }
        public GuardRvaTableInfo GuardCfFunctionTableInfo { get; }
        public GuardRvaTableInfo GuardAddressTakenIatTable { get; }
        public GuardRvaTableInfo GuardLongJumpTargetTable { get; }
        public IReadOnlyList<GuardFeatureInfo> GuardFeatureMatrix { get; }
        public IReadOnlyList<GuardTableSanityInfo> GuardTableSanity { get; }
        public SehHandlerTableInfo SehHandlerTable { get; }
        public EnclaveConfigurationInfo EnclaveConfiguration { get; }

        public LoadConfigInfo(
            uint size,
            LoadConfigVersionInfo versionInfo,
            uint timeDateStamp,
            ushort majorVersion,
            ushort minorVersion,
            uint globalFlagsClear,
            uint globalFlagsSet,
            LoadConfigGlobalFlagsInfo globalFlagsInfo,
            LoadConfigCodeIntegrityInfo codeIntegrity,
            uint processHeapFlags,
            uint csdVersion,
            uint dependentLoadFlags,
            ulong securityCookie,
            ulong seHandlerTable,
            uint seHandlerCount,
            ulong guardCfCheckFunctionPointer,
            ulong guardCfDispatchFunctionPointer,
            ulong guardCfFunctionTable,
            uint guardCfFunctionCount,
            uint guardFlags,
            LoadConfigGuardFlagsInfo guardFlagsInfo,
            ulong dynamicValueRelocTable,
            uint dynamicValueRelocTableOffset,
            ushort dynamicValueRelocTableSection,
            ulong chpeMetadataPointer,
            ulong guardRFFailureRoutine,
            ulong guardRFFailureRoutineFunctionPointer,
            ulong guardRFVerifyStackPointerFunctionPointer,
            uint hotPatchTableOffset,
            ulong enclaveConfigurationPointer,
            ulong volatileMetadataPointer,
            ulong guardEhContinuationTable,
            ulong guardEhContinuationCount,
            ulong guardXfgCheckFunctionPointer,
            ulong guardXfgDispatchFunctionPointer,
            ulong guardXfgTableDispatchFunctionPointer,
            GuardRvaTableInfo guardCfFunctionTableInfo,
            GuardRvaTableInfo guardAddressTakenIatTable,
            GuardRvaTableInfo guardLongJumpTargetTable,
            GuardFeatureInfo[] guardFeatureMatrix,
            GuardTableSanityInfo[] guardTableSanity,
            SehHandlerTableInfo sehHandlerTable,
            EnclaveConfigurationInfo enclaveConfiguration)
        {
            Size = size;
            VersionInfo = versionInfo;
            TimeDateStamp = timeDateStamp;
            MajorVersion = majorVersion;
            MinorVersion = minorVersion;
            GlobalFlagsClear = globalFlagsClear;
            GlobalFlagsSet = globalFlagsSet;
            GlobalFlagsInfo = globalFlagsInfo;
            CodeIntegrity = codeIntegrity;
            ProcessHeapFlags = processHeapFlags;
            CsdVersion = csdVersion;
            DependentLoadFlags = dependentLoadFlags;
            SecurityCookie = securityCookie;
            SeHandlerTable = seHandlerTable;
            SeHandlerCount = seHandlerCount;
            GuardCfCheckFunctionPointer = guardCfCheckFunctionPointer;
            GuardCfDispatchFunctionPointer = guardCfDispatchFunctionPointer;
            GuardCfFunctionTable = guardCfFunctionTable;
            GuardCfFunctionCount = guardCfFunctionCount;
            GuardFlags = guardFlags;
            GuardFlagsInfo = guardFlagsInfo;
            DynamicValueRelocTable = dynamicValueRelocTable;
            DynamicValueRelocTableOffset = dynamicValueRelocTableOffset;
            DynamicValueRelocTableSection = dynamicValueRelocTableSection;
            ChpeMetadataPointer = chpeMetadataPointer;
            GuardRFFailureRoutine = guardRFFailureRoutine;
            GuardRFFailureRoutineFunctionPointer = guardRFFailureRoutineFunctionPointer;
            GuardRFVerifyStackPointerFunctionPointer = guardRFVerifyStackPointerFunctionPointer;
            HotPatchTableOffset = hotPatchTableOffset;
            EnclaveConfigurationPointer = enclaveConfigurationPointer;
            VolatileMetadataPointer = volatileMetadataPointer;
            GuardEhContinuationTable = guardEhContinuationTable;
            GuardEhContinuationCount = guardEhContinuationCount;
            GuardXfgCheckFunctionPointer = guardXfgCheckFunctionPointer;
            GuardXfgDispatchFunctionPointer = guardXfgDispatchFunctionPointer;
            GuardXfgTableDispatchFunctionPointer = guardXfgTableDispatchFunctionPointer;
            GuardCfFunctionTableInfo = guardCfFunctionTableInfo;
            GuardAddressTakenIatTable = guardAddressTakenIatTable;
            GuardLongJumpTargetTable = guardLongJumpTargetTable;
            GuardFeatureMatrix = Array.AsReadOnly(guardFeatureMatrix ?? Array.Empty<GuardFeatureInfo>());
            GuardTableSanity = Array.AsReadOnly(guardTableSanity ?? Array.Empty<GuardTableSanityInfo>());
            SehHandlerTable = sehHandlerTable;
            EnclaveConfiguration = enclaveConfiguration;
        }
    }

    public sealed class SehHandlerTableInfo
    {
        public ulong TableAddress { get; }
        public uint HandlerCount { get; }
        public bool IsMapped { get; }
        public string SectionName { get; }
        public IReadOnlyList<uint> HandlerRvas { get; }
        public IReadOnlyList<SehHandlerEntryInfo> Entries { get; }

        public SehHandlerTableInfo(
            ulong tableAddress,
            uint handlerCount,
            bool isMapped,
            string sectionName,
            uint[] handlerRvas,
            SehHandlerEntryInfo[] entries)
        {
            TableAddress = tableAddress;
            HandlerCount = handlerCount;
            IsMapped = isMapped;
            SectionName = sectionName ?? string.Empty;
            HandlerRvas = Array.AsReadOnly(handlerRvas ?? Array.Empty<uint>());
            Entries = Array.AsReadOnly(entries ?? Array.Empty<SehHandlerEntryInfo>());
        }
    }

    public sealed class SehHandlerEntryInfo
    {
        public uint Rva { get; }
        public string SectionName { get; }
        public string SymbolName { get; }
        public string ResolutionSource { get; }

        public SehHandlerEntryInfo(uint rva, string sectionName, string symbolName, string resolutionSource)
        {
            Rva = rva;
            SectionName = sectionName ?? string.Empty;
            SymbolName = symbolName ?? string.Empty;
            ResolutionSource = resolutionSource ?? string.Empty;
        }
    }

    public sealed class GuardTableSanityInfo
    {
        public string Name { get; }
        public bool PointerPresent { get; }
        public bool CountPresent { get; }
        public bool MappedToSection { get; }
        public string SectionName { get; }
        public uint SectionRva { get; }
        public uint SectionSize { get; }
        public uint EstimatedSize { get; }
        public bool SizeFits { get; }
        public string Notes { get; }

        public GuardTableSanityInfo(
            string name,
            bool pointerPresent,
            bool countPresent,
            bool mappedToSection,
            string sectionName,
            uint sectionRva,
            uint sectionSize,
            uint estimatedSize,
            bool sizeFits,
            string notes)
        {
            Name = name ?? string.Empty;
            PointerPresent = pointerPresent;
            CountPresent = countPresent;
            MappedToSection = mappedToSection;
            SectionName = sectionName ?? string.Empty;
            SectionRva = sectionRva;
            SectionSize = sectionSize;
            EstimatedSize = estimatedSize;
            SizeFits = sizeFits;
            Notes = notes ?? string.Empty;
        }
    }

    public sealed class VersionFixedFileInfo
    {
        public string FileVersion { get; }
        public string ProductVersion { get; }
        public uint FileFlagsMask { get; }
        public uint FileFlags { get; }
        public IReadOnlyList<string> FileFlagNames { get; }
        public uint FileOs { get; }
        public string FileOsName { get; }
        public uint FileType { get; }
        public string FileTypeName { get; }
        public uint FileSubtype { get; }
        public string FileSubtypeName { get; }
        public uint FileDateMs { get; }
        public uint FileDateLs { get; }

        public VersionFixedFileInfo(
            string fileVersion,
            string productVersion,
            uint fileFlagsMask,
            uint fileFlags,
            string[] fileFlagNames,
            uint fileOs,
            string fileOsName,
            uint fileType,
            string fileTypeName,
            uint fileSubtype,
            string fileSubtypeName,
            uint fileDateMs,
            uint fileDateLs)
        {
            FileVersion = fileVersion ?? string.Empty;
            ProductVersion = productVersion ?? string.Empty;
            FileFlagsMask = fileFlagsMask;
            FileFlags = fileFlags;
            FileFlagNames = Array.AsReadOnly(fileFlagNames ?? Array.Empty<string>());
            FileOs = fileOs;
            FileOsName = fileOsName ?? string.Empty;
            FileType = fileType;
            FileTypeName = fileTypeName ?? string.Empty;
            FileSubtype = fileSubtype;
            FileSubtypeName = fileSubtypeName ?? string.Empty;
            FileDateMs = fileDateMs;
            FileDateLs = fileDateLs;
        }
    }

    public sealed class VersionInfoDetails
    {
        public VersionFixedFileInfo FixedFileInfo { get; }
        public uint FixedFileInfoSignature { get; }
        public bool FixedFileInfoSignatureValid { get; }
        public ushort ResourceLength { get; }
        public ushort ResourceValueLength { get; }
        public ushort ResourceType { get; }
        public string ResourceKey { get; }
        public int ExtraDataBytes { get; }
        public string ExtraDataPreview { get; }
        public IReadOnlyDictionary<string, string> StringValues { get; }
        public IReadOnlyList<VersionStringTableInfo> StringTables { get; }
        public uint? Translation { get; }
        public IReadOnlyList<VersionTranslationInfo> Translations { get; }
        public string TranslationText { get; }

        public VersionInfoDetails(
            VersionFixedFileInfo fixedFileInfo,
            uint fixedFileInfoSignature,
            bool fixedFileInfoSignatureValid,
            ushort resourceLength,
            ushort resourceValueLength,
            ushort resourceType,
            string resourceKey,
            int extraDataBytes,
            string extraDataPreview,
            IReadOnlyDictionary<string, string> stringValues,
            VersionStringTableInfo[] stringTables,
            uint? translation,
            VersionTranslationInfo[] translations,
            string translationText)
        {
            FixedFileInfo = fixedFileInfo;
            FixedFileInfoSignature = fixedFileInfoSignature;
            FixedFileInfoSignatureValid = fixedFileInfoSignatureValid;
            ResourceLength = resourceLength;
            ResourceValueLength = resourceValueLength;
            ResourceType = resourceType;
            ResourceKey = resourceKey ?? string.Empty;
            ExtraDataBytes = extraDataBytes;
            ExtraDataPreview = extraDataPreview ?? string.Empty;
            StringValues = stringValues ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            StringTables = Array.AsReadOnly(stringTables ?? Array.Empty<VersionStringTableInfo>());
            Translation = translation;
            Translations = Array.AsReadOnly(translations ?? Array.Empty<VersionTranslationInfo>());
            TranslationText = translationText ?? string.Empty;
        }
    }

    public sealed class VersionStringTableInfo
    {
        public string Key { get; }
        public ushort LanguageId { get; }
        public ushort CodePage { get; }
        public IReadOnlyDictionary<string, string> Values { get; }

        public VersionStringTableInfo(string key, ushort languageId, ushort codePage, IReadOnlyDictionary<string, string> values)
        {
            Key = key ?? string.Empty;
            LanguageId = languageId;
            CodePage = codePage;
            Values = values ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public sealed class ResourceStringCoverageInfo
    {
        public ushort LanguageId { get; }
        public string CultureName { get; }
        public int BlockCount { get; }
        public int StringCount { get; }
        public uint MinBlockId { get; }
        public uint MaxBlockId { get; }
        public int MissingBlockCount { get; }
        public IReadOnlyList<uint> MissingBlocks { get; }
        public bool IsBestMatch { get; }

        public ResourceStringCoverageInfo(
            ushort languageId,
            string cultureName,
            int blockCount,
            int stringCount,
            uint minBlockId,
            uint maxBlockId,
            int missingBlockCount,
            uint[] missingBlocks,
            bool isBestMatch)
        {
            LanguageId = languageId;
            CultureName = cultureName ?? string.Empty;
            BlockCount = blockCount;
            StringCount = stringCount;
            MinBlockId = minBlockId;
            MaxBlockId = maxBlockId;
            MissingBlockCount = missingBlockCount;
            MissingBlocks = Array.AsReadOnly(missingBlocks ?? Array.Empty<uint>());
            IsBestMatch = isBestMatch;
        }
    }

    public sealed class VersionTranslationInfo
    {
        public ushort LanguageId { get; }
        public ushort CodePage { get; }
        public uint Value { get; }
        public string CultureName { get; }
        public string DisplayName { get; }

        public VersionTranslationInfo(ushort languageId, ushort codePage, uint value, string cultureName, string displayName)
        {
            LanguageId = languageId;
            CodePage = codePage;
            Value = value;
            CultureName = cultureName ?? string.Empty;
            DisplayName = displayName ?? string.Empty;
        }
    }

    public sealed class IconEntryInfo
    {
        public byte Width { get; }
        public byte Height { get; }
        public byte ColorCount { get; }
        public byte Reserved { get; }
        public ushort Planes { get; }
        public ushort BitCount { get; }
        public uint BytesInRes { get; }
        public ushort ResourceId { get; }
        public bool IsPng { get; }
        public uint PngWidth { get; }
        public uint PngHeight { get; }

        public IconEntryInfo(
            byte width,
            byte height,
            byte colorCount,
            byte reserved,
            ushort planes,
            ushort bitCount,
            uint bytesInRes,
            ushort resourceId,
            bool isPng,
            uint pngWidth,
            uint pngHeight)
        {
            Width = width;
            Height = height;
            ColorCount = colorCount;
            Reserved = reserved;
            Planes = planes;
            BitCount = bitCount;
            BytesInRes = bytesInRes;
            ResourceId = resourceId;
            IsPng = isPng;
            PngWidth = pngWidth;
            PngHeight = pngHeight;
        }
    }

    public sealed class IconGroupInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public ushort HeaderReserved { get; }
        public ushort HeaderType { get; }
        public ushort DeclaredEntryCount { get; }
        public int EntrySize { get; }
        public bool HeaderValid { get; }
        public bool EntriesTruncated { get; }
        public IReadOnlyList<IconEntryInfo> Entries { get; }
        public byte[] IcoData { get; }

        public IconGroupInfo(
            uint nameId,
            ushort languageId,
            ushort headerReserved,
            ushort headerType,
            ushort declaredEntryCount,
            int entrySize,
            bool headerValid,
            bool entriesTruncated,
            IconEntryInfo[] entries,
            byte[] icoData)
        {
            NameId = nameId;
            LanguageId = languageId;
            HeaderReserved = headerReserved;
            HeaderType = headerType;
            DeclaredEntryCount = declaredEntryCount;
            EntrySize = entrySize;
            HeaderValid = headerValid;
            EntriesTruncated = entriesTruncated;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<IconEntryInfo>());
            IcoData = icoData ?? Array.Empty<byte>();
        }
    }

    public sealed class StrongNameSignatureInfo
    {
        public uint Rva { get; }
        public uint Size { get; }
        public byte[] Data { get; }

        public StrongNameSignatureInfo(uint rva, uint size, byte[] data)
        {
            Rva = rva;
            Size = size;
            Data = data ?? Array.Empty<byte>();
        }
    }

    public sealed class StrongNameValidationInfo
    {
        public bool SignedFlag { get; }
        public bool HasSignature { get; }
        public uint SignatureRva { get; }
        public uint SignatureSize { get; }
        public int DataSize { get; }
        public bool SizeMatches { get; }
        public IReadOnlyList<string> Issues { get; }

        public StrongNameValidationInfo(
            bool signedFlag,
            bool hasSignature,
            uint signatureRva,
            uint signatureSize,
            int dataSize,
            bool sizeMatches,
            string[] issues)
        {
            SignedFlag = signedFlag;
            HasSignature = hasSignature;
            SignatureRva = signatureRva;
            SignatureSize = signatureSize;
            DataSize = dataSize;
            SizeMatches = sizeMatches;
            Issues = Array.AsReadOnly(issues ?? Array.Empty<string>());
        }
    }

    public sealed class AuthenticodeDigestInfo
    {
        public string AlgorithmOid { get; }
        public string AlgorithmName { get; }
        public byte[] Digest { get; }

        public AuthenticodeDigestInfo(string algorithmOid, string algorithmName, byte[] digest)
        {
            AlgorithmOid = algorithmOid ?? string.Empty;
            AlgorithmName = algorithmName ?? string.Empty;
            Digest = digest ?? Array.Empty<byte>();
        }
    }

    public sealed class AuthenticodeVerificationResult
    {
        public AuthenticodeDigestInfo EmbeddedDigest { get; }
        public string ComputedHash { get; }
        public bool Matches { get; }

        public AuthenticodeVerificationResult(AuthenticodeDigestInfo embeddedDigest, string computedHash, bool matches)
        {
            EmbeddedDigest = embeddedDigest;
            ComputedHash = computedHash ?? string.Empty;
            Matches = matches;
        }
    }

    public sealed class SubsystemInfo
    {
        public ushort Value { get; }
        public string Name { get; }
        public bool IsGui { get; }
        public bool IsConsole { get; }

        public SubsystemInfo(ushort value, string name, bool isGui, bool isConsole)
        {
            Value = value;
            Name = name ?? string.Empty;
            IsGui = isGui;
            IsConsole = isConsole;
        }
    }

    public sealed class DllCharacteristicsInfo
    {
        public ushort Value { get; }
        public string[] Flags { get; }
        public bool NxCompat { get; }
        public bool AslrEnabled { get; }
        public bool GuardCf { get; }
        public bool HighEntropyVa { get; }

        public DllCharacteristicsInfo(
            ushort value,
            string[] flags,
            bool nxCompat,
            bool aslrEnabled,
            bool guardCf,
            bool highEntropyVa)
        {
            Value = value;
            Flags = flags ?? Array.Empty<string>();
            NxCompat = nxCompat;
            AslrEnabled = aslrEnabled;
            GuardCf = guardCf;
            HighEntropyVa = highEntropyVa;
        }
    }

    public sealed class SecurityFeaturesInfo
    {
        public bool NxCompat { get; }
        public bool AslrEnabled { get; }
        public bool HighEntropyVa { get; }
        public bool GuardCf { get; }
        public bool HasSecurityCookie { get; }
        public bool HasSeHandlerTable { get; }
        public bool SafeSeh { get; }
        public bool NoSeh { get; }

        public SecurityFeaturesInfo(
            bool nxCompat,
            bool aslrEnabled,
            bool highEntropyVa,
            bool guardCf,
            bool hasSecurityCookie,
            bool hasSeHandlerTable,
            bool safeSeh,
            bool noSeh)
        {
            NxCompat = nxCompat;
            AslrEnabled = aslrEnabled;
            HighEntropyVa = highEntropyVa;
            GuardCf = guardCf;
            HasSecurityCookie = hasSecurityCookie;
            HasSeHandlerTable = hasSeHandlerTable;
            SafeSeh = safeSeh;
            NoSeh = noSeh;
        }
    }

    public sealed class CoffObjectInfo
    {
        public ushort Machine { get; }
        public string MachineName { get; }
        public ushort SectionCount { get; }
        public bool IsBigObj { get; }
        public uint BigObjSectionCount { get; }
        public uint BigObjFlags { get; }
        public uint BigObjMetaDataSize { get; }
        public uint BigObjMetaDataOffset { get; }
        public string BigObjClassId { get; }
        public uint TimeDateStamp { get; }
        public DateTimeOffset? TimeDateStampUtc { get; }
        public uint PointerToSymbolTable { get; }
        public uint NumberOfSymbols { get; }
        public ushort OptionalHeaderSize { get; }
        public ushort Characteristics { get; }
        public IReadOnlyList<string> CharacteristicsFlags { get; }

        public CoffObjectInfo(
            ushort machine,
            string machineName,
            ushort sectionCount,
            bool isBigObj,
            uint bigObjSectionCount,
            uint bigObjFlags,
            uint bigObjMetaDataSize,
            uint bigObjMetaDataOffset,
            string bigObjClassId,
            uint timeDateStamp,
            DateTimeOffset? timeDateStampUtc,
            uint pointerToSymbolTable,
            uint numberOfSymbols,
            ushort optionalHeaderSize,
            ushort characteristics,
            string[] characteristicsFlags)
        {
            Machine = machine;
            MachineName = machineName ?? string.Empty;
            SectionCount = sectionCount;
            IsBigObj = isBigObj;
            BigObjSectionCount = bigObjSectionCount;
            BigObjFlags = bigObjFlags;
            BigObjMetaDataSize = bigObjMetaDataSize;
            BigObjMetaDataOffset = bigObjMetaDataOffset;
            BigObjClassId = bigObjClassId ?? string.Empty;
            TimeDateStamp = timeDateStamp;
            TimeDateStampUtc = timeDateStampUtc;
            PointerToSymbolTable = pointerToSymbolTable;
            NumberOfSymbols = numberOfSymbols;
            OptionalHeaderSize = optionalHeaderSize;
            Characteristics = characteristics;
            CharacteristicsFlags = Array.AsReadOnly(characteristicsFlags ?? Array.Empty<string>());
        }
    }

    public sealed class CoffArchiveSymbolTableInfo
    {
        public int SymbolCount { get; }
        public int NameTableSize { get; }

        public CoffArchiveSymbolTableInfo(int symbolCount, int nameTableSize)
        {
            SymbolCount = symbolCount;
            NameTableSize = nameTableSize;
        }
    }

    public sealed class CoffImportObjectInfo
    {
        public ushort Version { get; }
        public ushort Machine { get; }
        public string MachineName { get; }
        public uint TimeDateStamp { get; }
        public uint SizeOfData { get; }
        public ushort OrdinalOrHint { get; }
        public ushort Type { get; }
        public string TypeName { get; }
        public ushort NameType { get; }
        public string NameTypeName { get; }
        public string SymbolName { get; }
        public string DllName { get; }

        public CoffImportObjectInfo(
            ushort version,
            ushort machine,
            string machineName,
            uint timeDateStamp,
            uint sizeOfData,
            ushort ordinalOrHint,
            ushort type,
            string typeName,
            ushort nameType,
            string nameTypeName,
            string symbolName,
            string dllName)
        {
            Version = version;
            Machine = machine;
            MachineName = machineName ?? string.Empty;
            TimeDateStamp = timeDateStamp;
            SizeOfData = sizeOfData;
            OrdinalOrHint = ordinalOrHint;
            Type = type;
            TypeName = typeName ?? string.Empty;
            NameType = nameType;
            NameTypeName = nameTypeName ?? string.Empty;
            SymbolName = symbolName ?? string.Empty;
            DllName = dllName ?? string.Empty;
        }
    }

    public sealed class CoffArchiveMemberInfo
    {
        public string Name { get; }
        public long DataOffset { get; }
        public long Size { get; }
        public uint TimeDateStamp { get; }
        public int UserId { get; }
        public int GroupId { get; }
        public string Mode { get; }
        public bool IsSymbolTable { get; }
        public bool IsLongNameTable { get; }
        public bool IsImportObject { get; }
        public CoffImportObjectInfo ImportObject { get; }

        public CoffArchiveMemberInfo(
            string name,
            long dataOffset,
            long size,
            uint timeDateStamp,
            int userId,
            int groupId,
            string mode,
            bool isSymbolTable,
            bool isLongNameTable,
            bool isImportObject,
            CoffImportObjectInfo importObject)
        {
            Name = name ?? string.Empty;
            DataOffset = dataOffset;
            Size = size;
            TimeDateStamp = timeDateStamp;
            UserId = userId;
            GroupId = groupId;
            Mode = mode ?? string.Empty;
            IsSymbolTable = isSymbolTable;
            IsLongNameTable = isLongNameTable;
            IsImportObject = isImportObject;
            ImportObject = importObject;
        }
    }

    public sealed class CoffArchiveInfo
    {
        public string Signature { get; }
        public int MemberCount { get; }
        public CoffArchiveSymbolTableInfo SymbolTable { get; }
        public IReadOnlyList<CoffArchiveMemberInfo> Members { get; }

        public CoffArchiveInfo(
            string signature,
            int memberCount,
            CoffArchiveSymbolTableInfo symbolTable,
            CoffArchiveMemberInfo[] members)
        {
            Signature = signature ?? string.Empty;
            MemberCount = memberCount;
            SymbolTable = symbolTable;
            Members = Array.AsReadOnly(members ?? Array.Empty<CoffArchiveMemberInfo>());
        }
    }

    public sealed class TeDataDirectoryInfo
    {
        public string Name { get; }
        public uint VirtualAddress { get; }
        public uint Size { get; }
        public bool IsPresent { get; }

        public TeDataDirectoryInfo(string name, uint virtualAddress, uint size, bool isPresent)
        {
            Name = name ?? string.Empty;
            VirtualAddress = virtualAddress;
            Size = size;
            IsPresent = isPresent;
        }
    }

    public sealed class TeImageInfo
    {
        public ushort Machine { get; }
        public string MachineName { get; }
        public byte SectionCount { get; }
        public byte Subsystem { get; }
        public string SubsystemName { get; }
        public ushort StrippedSize { get; }
        public ushort HeaderSize { get; }
        public uint SectionTableOffset { get; }
        public uint SectionTableSize { get; }
        public uint AddressOfEntryPoint { get; }
        public uint BaseOfCode { get; }
        public ulong ImageBase { get; }
        public IReadOnlyList<TeDataDirectoryInfo> DataDirectories { get; }

        public TeImageInfo(
            ushort machine,
            string machineName,
            byte sectionCount,
            byte subsystem,
            string subsystemName,
            ushort strippedSize,
            ushort headerSize,
            uint sectionTableOffset,
            uint sectionTableSize,
            uint addressOfEntryPoint,
            uint baseOfCode,
            ulong imageBase,
            TeDataDirectoryInfo[] dataDirectories)
        {
            Machine = machine;
            MachineName = machineName ?? string.Empty;
            SectionCount = sectionCount;
            Subsystem = subsystem;
            SubsystemName = subsystemName ?? string.Empty;
            StrippedSize = strippedSize;
            HeaderSize = headerSize;
            SectionTableOffset = sectionTableOffset;
            SectionTableSize = sectionTableSize;
            AddressOfEntryPoint = addressOfEntryPoint;
            BaseOfCode = baseOfCode;
            ImageBase = imageBase;
            DataDirectories = Array.AsReadOnly(dataDirectories ?? Array.Empty<TeDataDirectoryInfo>());
        }
    }

    public sealed class DataDirectoryInfo
    {
        public int Index { get; }
        public string Name { get; }
        public uint VirtualAddress { get; }
        public uint Size { get; }
        public bool IsPresent { get; }
        public bool IsMapped { get; }
        public string SectionName { get; }
        public uint SectionRva { get; }
        public uint SectionSize { get; }

        public DataDirectoryInfo(
            int index,
            string name,
            uint virtualAddress,
            uint size,
            bool isMapped,
            string sectionName,
            uint sectionRva,
            uint sectionSize)
        {
            Index = index;
            Name = name ?? string.Empty;
            VirtualAddress = virtualAddress;
            Size = size;
            IsPresent = size > 0;
            IsMapped = isMapped;
            SectionName = sectionName ?? string.Empty;
            SectionRva = sectionRva;
            SectionSize = sectionSize;
        }
    }

    public sealed class DataDirectoryValidationInfo
    {
        public int Index { get; }
        public string Name { get; }
        public uint VirtualAddress { get; }
        public uint Size { get; }
        public bool IsPresent { get; }
        public bool IsMapped { get; }
        public bool IsFullyMapped { get; }
        public string SectionName { get; }
        public uint SectionRva { get; }
        public uint SectionSize { get; }
        public uint DirectoryEndRva { get; }
        public uint SectionEndRva { get; }
        public uint MinimumSize { get; }
        public uint EntrySize { get; }
        public bool SizeAligned { get; }
        public bool SizePlausible { get; }
        public bool UsesFileOffset { get; }
        public string Notes { get; }

        public DataDirectoryValidationInfo(
            int index,
            string name,
            uint virtualAddress,
            uint size,
            bool isMapped,
            bool isFullyMapped,
            string sectionName,
            uint sectionRva,
            uint sectionSize,
            uint directoryEndRva,
            uint sectionEndRva,
            uint minimumSize,
            uint entrySize,
            bool sizeAligned,
            bool sizePlausible,
            bool usesFileOffset,
            string notes)
        {
            Index = index;
            Name = name ?? string.Empty;
            VirtualAddress = virtualAddress;
            Size = size;
            IsPresent = size > 0;
            IsMapped = isMapped;
            IsFullyMapped = isFullyMapped;
            SectionName = sectionName ?? string.Empty;
            SectionRva = sectionRva;
            SectionSize = sectionSize;
            DirectoryEndRva = directoryEndRva;
            SectionEndRva = sectionEndRva;
            MinimumSize = minimumSize;
            EntrySize = entrySize;
            SizeAligned = sizeAligned;
            SizePlausible = sizePlausible;
            UsesFileOffset = usesFileOffset;
            Notes = notes ?? string.Empty;
        }
    }

    public sealed class ArchitectureDirectoryInfo
    {
        public uint VirtualAddress { get; }
        public uint Size { get; }
        public bool IsMapped { get; }
        public string SectionName { get; }
        public bool Parsed { get; }
        public uint Magic { get; }
        public uint MajorVersion { get; }
        public uint MinorVersion { get; }
        public uint SizeOfData { get; }
        public uint FirstEntryRva { get; }
        public uint NumberOfEntries { get; }
        public int ParsedEntryCount { get; }
        public bool EntriesTruncated { get; }
        public IReadOnlyList<ArchitectureDirectoryEntryInfo> Entries { get; }

        public ArchitectureDirectoryInfo(
            uint virtualAddress,
            uint size,
            bool isMapped,
            string sectionName,
            bool parsed,
            uint magic,
            uint majorVersion,
            uint minorVersion,
            uint sizeOfData,
            uint firstEntryRva,
            uint numberOfEntries,
            int parsedEntryCount,
            bool entriesTruncated,
            ArchitectureDirectoryEntryInfo[] entries)
        {
            VirtualAddress = virtualAddress;
            Size = size;
            IsMapped = isMapped;
            SectionName = sectionName ?? string.Empty;
            Parsed = parsed;
            Magic = magic;
            MajorVersion = majorVersion;
            MinorVersion = minorVersion;
            SizeOfData = sizeOfData;
            FirstEntryRva = firstEntryRva;
            NumberOfEntries = numberOfEntries;
            ParsedEntryCount = parsedEntryCount;
            EntriesTruncated = entriesTruncated;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<ArchitectureDirectoryEntryInfo>());
        }
    }

    public sealed class ArchitectureDirectoryEntryInfo
    {
        public uint FixupRva { get; }
        public uint NewInstruction { get; }
        public bool FixupMapped { get; }
        public string FixupSectionName { get; }

        public ArchitectureDirectoryEntryInfo(
            uint fixupRva,
            uint newInstruction,
            bool fixupMapped,
            string fixupSectionName)
        {
            FixupRva = fixupRva;
            NewInstruction = newInstruction;
            FixupMapped = fixupMapped;
            FixupSectionName = fixupSectionName ?? string.Empty;
        }
    }

    public sealed class GlobalPtrDirectoryInfo
    {
        public uint VirtualAddress { get; }
        public uint Size { get; }
        public bool IsMapped { get; }
        public string SectionName { get; }
        public bool ValueMapped { get; }
        public ulong Value { get; }
        public bool HasRva { get; }
        public uint Rva { get; }
        public string RvaKind { get; }
        public bool RvaMapped { get; }
        public string RvaSectionName { get; }

        public GlobalPtrDirectoryInfo(
            uint virtualAddress,
            uint size,
            bool isMapped,
            string sectionName,
            bool valueMapped,
            ulong value,
            bool hasRva,
            uint rva,
            string rvaKind,
            bool rvaMapped,
            string rvaSectionName)
        {
            VirtualAddress = virtualAddress;
            Size = size;
            IsMapped = isMapped;
            SectionName = sectionName ?? string.Empty;
            ValueMapped = valueMapped;
            Value = value;
            HasRva = hasRva;
            Rva = rva;
            RvaKind = rvaKind ?? string.Empty;
            RvaMapped = rvaMapped;
            RvaSectionName = rvaSectionName ?? string.Empty;
        }
    }

    public sealed class IatDirectoryInfo
    {
        public uint VirtualAddress { get; }
        public uint Size { get; }
        public bool IsMapped { get; }
        public string SectionName { get; }
        public uint EntryCount { get; }
        public uint EntrySize { get; }
        public bool SizeAligned { get; }
        public uint NonZeroEntryCount { get; }
        public uint ZeroEntryCount { get; }
        public uint SampleCount { get; }
        public bool SamplesTruncated { get; }
        public uint MappedEntryCount { get; }
        public IReadOnlyList<IatEntryInfo> Samples { get; }

        public IatDirectoryInfo(
            uint virtualAddress,
            uint size,
            bool isMapped,
            string sectionName,
            uint entryCount,
            uint entrySize,
            bool sizeAligned,
            uint nonZeroEntryCount,
            uint zeroEntryCount,
            uint sampleCount,
            bool samplesTruncated,
            uint mappedEntryCount,
            IatEntryInfo[] samples)
        {
            VirtualAddress = virtualAddress;
            Size = size;
            IsMapped = isMapped;
            SectionName = sectionName ?? string.Empty;
            EntryCount = entryCount;
            EntrySize = entrySize;
            SizeAligned = sizeAligned;
            NonZeroEntryCount = nonZeroEntryCount;
            ZeroEntryCount = zeroEntryCount;
            SampleCount = sampleCount;
            SamplesTruncated = samplesTruncated;
            MappedEntryCount = mappedEntryCount;
            Samples = Array.AsReadOnly(samples ?? Array.Empty<IatEntryInfo>());
        }
    }

    public sealed class IatEntryInfo
    {
        public uint Index { get; }
        public ulong Value { get; }
        public bool IsZero { get; }
        public bool HasRva { get; }
        public uint Rva { get; }
        public string RvaKind { get; }
        public bool Mapped { get; }
        public string SectionName { get; }

        public IatEntryInfo(
            uint index,
            ulong value,
            bool isZero,
            bool hasRva,
            uint rva,
            string rvaKind,
            bool mapped,
            string sectionName)
        {
            Index = index;
            Value = value;
            IsZero = isZero;
            HasRva = hasRva;
            Rva = rva;
            RvaKind = rvaKind ?? string.Empty;
            Mapped = mapped;
            SectionName = sectionName ?? string.Empty;
        }
    }

    public sealed class CoffStringTableEntry
    {
        public uint Offset { get; }
        public string Value { get; }

        public CoffStringTableEntry(uint offset, string value)
        {
            Offset = offset;
            Value = value ?? string.Empty;
        }
    }

    public sealed class CoffRelocationInfo
    {
        public string SectionName { get; }
        public int SectionIndex { get; }
        public uint VirtualAddress { get; }
        public uint SymbolIndex { get; }
        public string SymbolName { get; }
        public ushort Type { get; }
        public string TypeName { get; }
        public long FileOffset { get; }

        public CoffRelocationInfo(
            string sectionName,
            int sectionIndex,
            uint virtualAddress,
            uint symbolIndex,
            string symbolName,
            ushort type,
            string typeName,
            long fileOffset)
        {
            SectionName = sectionName ?? string.Empty;
            SectionIndex = sectionIndex;
            VirtualAddress = virtualAddress;
            SymbolIndex = symbolIndex;
            SymbolName = symbolName ?? string.Empty;
            Type = type;
            TypeName = typeName ?? string.Empty;
            FileOffset = fileOffset;
        }
    }

    public sealed class CoffAuxSymbolInfo
    {
        public string Kind { get; }
        public string FileName { get; }
        public uint TagIndex { get; }
        public uint TotalSize { get; }
        public uint PointerToLineNumber { get; }
        public uint PointerToNextFunction { get; }
        public ushort FunctionLineNumber { get; }
        public uint SectionLength { get; }
        public ushort RelocationCount { get; }
        public ushort LineNumberCount { get; }
        public uint Checksum { get; }
        public ushort SectionNumber { get; }
        public byte Selection { get; }
        public string SelectionName { get; }
        public string AssociatedSectionName { get; }
        public bool IsComdat { get; }
        public bool ComdatSelectionValid { get; }
        public string ComdatSelectionNote { get; }
        public uint WeakTagIndex { get; }
        public uint WeakCharacteristics { get; }
        public string WeakCharacteristicsName { get; }
        public string WeakDefaultSymbol { get; }
        public string RawPreview { get; }

        public CoffAuxSymbolInfo(
            string kind,
            string fileName,
            uint tagIndex,
            uint totalSize,
            uint pointerToLineNumber,
            uint pointerToNextFunction,
            ushort functionLineNumber,
            uint sectionLength,
            ushort relocationCount,
            ushort lineNumberCount,
            uint checksum,
            ushort sectionNumber,
            byte selection,
            string selectionName,
            string associatedSectionName,
            bool isComdat,
            bool comdatSelectionValid,
            string comdatSelectionNote,
            uint weakTagIndex,
            uint weakCharacteristics,
            string weakCharacteristicsName,
            string weakDefaultSymbol,
            string rawPreview)
        {
            Kind = kind ?? string.Empty;
            FileName = fileName ?? string.Empty;
            TagIndex = tagIndex;
            TotalSize = totalSize;
            PointerToLineNumber = pointerToLineNumber;
            PointerToNextFunction = pointerToNextFunction;
            FunctionLineNumber = functionLineNumber;
            SectionLength = sectionLength;
            RelocationCount = relocationCount;
            LineNumberCount = lineNumberCount;
            Checksum = checksum;
            SectionNumber = sectionNumber;
            Selection = selection;
            SelectionName = selectionName ?? string.Empty;
            AssociatedSectionName = associatedSectionName ?? string.Empty;
            IsComdat = isComdat;
            ComdatSelectionValid = comdatSelectionValid;
            ComdatSelectionNote = comdatSelectionNote ?? string.Empty;
            WeakTagIndex = weakTagIndex;
            WeakCharacteristics = weakCharacteristics;
            WeakCharacteristicsName = weakCharacteristicsName ?? string.Empty;
            WeakDefaultSymbol = weakDefaultSymbol ?? string.Empty;
            RawPreview = rawPreview ?? string.Empty;
        }
    }

    public sealed class CoffSymbolInfo
    {
        public int Index { get; }
        public string Name { get; }
        public uint Value { get; }
        public short SectionNumber { get; }
        public string SectionName { get; }
        public ushort Type { get; }
        public string TypeName { get; }
        public byte StorageClass { get; }
        public string StorageClassName { get; }
        public string ScopeName { get; }
        public byte AuxSymbolCount { get; }
        public byte[] AuxData { get; }
        public IReadOnlyList<CoffAuxSymbolInfo> AuxSymbols { get; }

        public CoffSymbolInfo(
            int index,
            string name,
            uint value,
            short sectionNumber,
            string sectionName,
            ushort type,
            string typeName,
            byte storageClass,
            string storageClassName,
            string scopeName,
            byte auxSymbolCount,
            byte[] auxData,
            CoffAuxSymbolInfo[] auxSymbols)
        {
            Index = index;
            Name = name ?? string.Empty;
            Value = value;
            SectionNumber = sectionNumber;
            SectionName = sectionName ?? string.Empty;
            Type = type;
            TypeName = typeName ?? string.Empty;
            StorageClass = storageClass;
            StorageClassName = storageClassName ?? string.Empty;
            ScopeName = scopeName ?? string.Empty;
            AuxSymbolCount = auxSymbolCount;
            AuxData = auxData ?? Array.Empty<byte>();
            AuxSymbols = Array.AsReadOnly(auxSymbols ?? Array.Empty<CoffAuxSymbolInfo>());
        }
    }

    public sealed class CoffLineNumberInfo
    {
        public string SectionName { get; }
        public int SectionIndex { get; }
        public uint VirtualAddress { get; }
        public uint SymbolIndex { get; }
        public ushort LineNumber { get; }
        public bool IsFunction { get; }
        public long FileOffset { get; }

        public CoffLineNumberInfo(
            string sectionName,
            int sectionIndex,
            uint virtualAddress,
            uint symbolIndex,
            ushort lineNumber,
            bool isFunction,
            long fileOffset)
        {
            SectionName = sectionName ?? string.Empty;
            SectionIndex = sectionIndex;
            VirtualAddress = virtualAddress;
            SymbolIndex = symbolIndex;
            LineNumber = lineNumber;
            IsFunction = isFunction;
            FileOffset = fileOffset;
        }
    }

    public sealed class AuthenticodeSignerStatusInfo
    {
        public string Subject { get; }
        public string Issuer { get; }
        public string Role { get; }
        public bool IsTimestampSigner { get; }
        public bool SignatureValid { get; }
        public bool ChainValid { get; }
        public bool HasCodeSigningEku { get; }
        public bool HasTimestampEku { get; }
        public bool HasCertificateTransparency { get; }
        public int CertificateTransparencyCount { get; }
        public int NestingLevel { get; }

        public AuthenticodeSignerStatusInfo(
            string subject,
            string issuer,
            string role,
            bool isTimestampSigner,
            bool signatureValid,
            bool chainValid,
            bool hasCodeSigningEku,
            bool hasTimestampEku,
            bool hasCertificateTransparency,
            int certificateTransparencyCount,
            int nestingLevel)
        {
            Subject = subject ?? string.Empty;
            Issuer = issuer ?? string.Empty;
            Role = role ?? string.Empty;
            IsTimestampSigner = isTimestampSigner;
            SignatureValid = signatureValid;
            ChainValid = chainValid;
            HasCodeSigningEku = hasCodeSigningEku;
            HasTimestampEku = hasTimestampEku;
            HasCertificateTransparency = hasCertificateTransparency;
            CertificateTransparencyCount = certificateTransparencyCount;
            NestingLevel = nestingLevel;
        }
    }

    public sealed class AuthenticodeTrustStoreInfo
    {
        public bool Performed { get; }
        public bool Verified { get; }
        public string Platform { get; }
        public bool TrustStoreEnabled { get; }
        public bool Offline { get; }
        public X509RevocationMode RevocationMode { get; }
        public X509RevocationFlag RevocationFlag { get; }
        public IReadOnlyList<string> Status { get; }

        public AuthenticodeTrustStoreInfo(
            bool performed,
            bool verified,
            string platform,
            bool trustStoreEnabled,
            bool offline,
            X509RevocationMode revocationMode,
            X509RevocationFlag revocationFlag,
            string[] status)
        {
            Performed = performed;
            Verified = verified;
            Platform = platform ?? string.Empty;
            TrustStoreEnabled = trustStoreEnabled;
            Offline = offline;
            RevocationMode = revocationMode;
            RevocationFlag = revocationFlag;
            Status = Array.AsReadOnly(status ?? Array.Empty<string>());
        }
    }

    public sealed class AuthenticodeStatusInfo
    {
        public int SignerCount { get; }
        public int TimestampSignerCount { get; }
        public int CertificateTransparencySignerCount { get; }
        public int CertificateTransparencyLogCount { get; }
        public bool HasSignature { get; }
        public bool SignatureValid { get; }
        public bool ChainValid { get; }
        public bool HasTimestamp { get; }
        public bool TimestampValid { get; }
        public IReadOnlyList<string> ChainStatus { get; }
        public IReadOnlyList<string> TimestampChainStatus { get; }
        public IReadOnlyList<string> CertificateTransparencyLogIds { get; }
        public WinTrustResultInfo WinTrust { get; }
        public AuthenticodeTrustStoreInfo TrustStore { get; }
        public bool CertificateTransparencyRequiredMet { get; }
        public bool PolicyCompliant { get; }
        public IReadOnlyList<string> PolicyFailures { get; }
        public IReadOnlyList<AuthenticodeSignerStatusInfo> SignerStatuses { get; }
        public AuthenticodePolicy Policy { get; }

        public AuthenticodeStatusInfo(
            int signerCount,
            int timestampSignerCount,
            int certificateTransparencySignerCount,
            int certificateTransparencyLogCount,
            bool hasSignature,
            bool signatureValid,
            bool chainValid,
            bool hasTimestamp,
            bool timestampValid,
            string[] chainStatus,
            string[] timestampChainStatus,
            string[] certificateTransparencyLogIds,
            WinTrustResultInfo winTrust,
            AuthenticodeTrustStoreInfo trustStore,
            bool certificateTransparencyRequiredMet,
            bool policyCompliant,
            string[] policyFailures,
            AuthenticodeSignerStatusInfo[] signerStatuses,
            AuthenticodePolicy policy)
        {
            SignerCount = signerCount;
            TimestampSignerCount = timestampSignerCount;
            CertificateTransparencySignerCount = certificateTransparencySignerCount;
            CertificateTransparencyLogCount = certificateTransparencyLogCount;
            HasSignature = hasSignature;
            SignatureValid = signatureValid;
            ChainValid = chainValid;
            HasTimestamp = hasTimestamp;
            TimestampValid = timestampValid;
            ChainStatus = Array.AsReadOnly(chainStatus ?? Array.Empty<string>());
            TimestampChainStatus = Array.AsReadOnly(timestampChainStatus ?? Array.Empty<string>());
            CertificateTransparencyLogIds = Array.AsReadOnly(certificateTransparencyLogIds ?? Array.Empty<string>());
            WinTrust = winTrust;
            TrustStore = trustStore;
            CertificateTransparencyRequiredMet = certificateTransparencyRequiredMet;
            PolicyCompliant = policyCompliant;
            PolicyFailures = Array.AsReadOnly(policyFailures ?? Array.Empty<string>());
            SignerStatuses = Array.AsReadOnly(signerStatuses ?? Array.Empty<AuthenticodeSignerStatusInfo>());
            Policy = policy ?? new AuthenticodePolicy();
        }
    }

    public sealed class WinTrustResultInfo
    {
        public string Status { get; }
        public int StatusCode { get; }
        public string Message { get; }

        public WinTrustResultInfo(string status, int statusCode, string message)
        {
            Status = status ?? string.Empty;
            StatusCode = statusCode;
            Message = message ?? string.Empty;
        }
    }

    public sealed class CatalogSignatureInfo
    {
        public bool Supported { get; }
        public bool Checked { get; }
        public bool IsSigned { get; }
        public bool TrustCheckPerformed { get; }
        public bool TrustVerified { get; }
        public string CatalogPath { get; }
        public string CatalogName { get; }
        public string Error { get; }
        public IReadOnlyList<Pkcs7SignerInfo> Signers { get; }
        public AuthenticodeStatusInfo Status { get; }

        public CatalogSignatureInfo(
            bool supported,
            bool @checked,
            bool isSigned,
            bool trustCheckPerformed,
            bool trustVerified,
            string catalogPath,
            string catalogName,
            string error,
            Pkcs7SignerInfo[] signers,
            AuthenticodeStatusInfo status)
        {
            Supported = supported;
            Checked = @checked;
            IsSigned = isSigned;
            TrustCheckPerformed = trustCheckPerformed;
            TrustVerified = trustVerified;
            CatalogPath = catalogPath ?? string.Empty;
            CatalogName = catalogName ?? string.Empty;
            Error = error ?? string.Empty;
            Signers = Array.AsReadOnly(signers ?? Array.Empty<Pkcs7SignerInfo>());
            Status = status;
        }
    }

    public sealed class OverlayInfo
    {
        public long StartOffset { get; }
        public long Size { get; }
        public bool HasOverlay => Size > 0;

        public OverlayInfo(long startOffset, long size)
        {
            StartOffset = startOffset < 0 ? 0 : startOffset;
            Size = size < 0 ? 0 : size;
        }
    }

    public sealed class OverlayContainerEntry
    {
        public string Name { get; }
        public long CompressedSize { get; }
        public long UncompressedSize { get; }
        public string CompressionMethod { get; }
        public ushort Flags { get; }
        public bool IsDirectory { get; }
        public string Notes { get; }

        public OverlayContainerEntry(
            string name,
            long compressedSize,
            long uncompressedSize,
            string compressionMethod,
            ushort flags,
            bool isDirectory,
            string notes)
        {
            Name = name ?? string.Empty;
            CompressedSize = compressedSize < 0 ? 0 : compressedSize;
            UncompressedSize = uncompressedSize < 0 ? 0 : uncompressedSize;
            CompressionMethod = compressionMethod ?? string.Empty;
            Flags = flags;
            IsDirectory = isDirectory;
            Notes = notes ?? string.Empty;
        }
    }

    public sealed class OverlayContainerInfo
    {
        public string Type { get; }
        public string Version { get; }
        public long Offset { get; }
        public long Size { get; }
        public int EntryCount { get; }
        public bool IsTruncated { get; }
        public string Notes { get; }
        public IReadOnlyList<OverlayContainerEntry> Entries { get; }

        public OverlayContainerInfo(
            string type,
            string version,
            long offset,
            long size,
            int entryCount,
            bool isTruncated,
            string notes,
            OverlayContainerEntry[] entries)
        {
            Type = type ?? string.Empty;
            Version = version ?? string.Empty;
            Offset = offset < 0 ? 0 : offset;
            Size = size < 0 ? 0 : size;
            EntryCount = entryCount < 0 ? 0 : entryCount;
            IsTruncated = isTruncated;
            Notes = notes ?? string.Empty;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<OverlayContainerEntry>());
        }
    }

    public sealed class PackingHintInfo
    {
        public string Kind { get; }
        public string Name { get; }
        public string Evidence { get; }

        public PackingHintInfo(string kind, string name, string evidence)
        {
            Kind = kind ?? string.Empty;
            Name = name ?? string.Empty;
            Evidence = evidence ?? string.Empty;
        }
    }

    public sealed class SectionEntropyInfo
    {
        public string Name { get; }
        public uint RawSize { get; }
        public double Entropy { get; }

        public SectionEntropyInfo(string name, uint rawSize, double entropy)
        {
            Name = name ?? string.Empty;
            RawSize = rawSize;
            Entropy = entropy;
        }
    }

    public sealed class SectionSlackInfo
    {
        public string SectionName { get; }
        public long FileOffset { get; }
        public int Size { get; }
        public int NonZeroCount { get; }
        public int SampledBytes { get; }

        public SectionSlackInfo(string sectionName, long fileOffset, int size, int nonZeroCount, int sampledBytes)
        {
            SectionName = sectionName ?? string.Empty;
            FileOffset = fileOffset;
            Size = size;
            NonZeroCount = nonZeroCount;
            SampledBytes = sampledBytes;
        }
    }

    public sealed class SectionGapInfo
    {
        public string PreviousSection { get; }
        public string NextSection { get; }
        public long FileOffset { get; }
        public int Size { get; }
        public int NonZeroCount { get; }
        public int SampledBytes { get; }

        public SectionGapInfo(
            string previousSection,
            string nextSection,
            long fileOffset,
            int size,
            int nonZeroCount,
            int sampledBytes)
        {
            PreviousSection = previousSection ?? string.Empty;
            NextSection = nextSection ?? string.Empty;
            FileOffset = fileOffset;
            Size = size;
            NonZeroCount = nonZeroCount;
            SampledBytes = sampledBytes;
        }
    }

    public sealed class SectionPermissionInfo
    {
        public string Name { get; }
        public uint Characteristics { get; }
        public IReadOnlyList<string> Flags { get; }
        public bool IsReadable { get; }
        public bool IsWritable { get; }
        public bool IsExecutable { get; }
        public bool IsCode { get; }
        public bool IsInitializedData { get; }
        public bool IsUninitializedData { get; }
        public bool IsDiscardable { get; }
        public bool IsShared { get; }
        public bool HasSuspiciousPermissions { get; }
        public bool HasMismatch { get; }

        public SectionPermissionInfo(
            string name,
            uint characteristics,
            string[] flags,
            bool isReadable,
            bool isWritable,
            bool isExecutable,
            bool isCode,
            bool isInitializedData,
            bool isUninitializedData,
            bool isDiscardable,
            bool isShared,
            bool hasSuspiciousPermissions,
            bool hasMismatch)
        {
            Name = name ?? string.Empty;
            Characteristics = characteristics;
            Flags = Array.AsReadOnly(flags ?? Array.Empty<string>());
            IsReadable = isReadable;
            IsWritable = isWritable;
            IsExecutable = isExecutable;
            IsCode = isCode;
            IsInitializedData = isInitializedData;
            IsUninitializedData = isUninitializedData;
            IsDiscardable = isDiscardable;
            IsShared = isShared;
            HasSuspiciousPermissions = hasSuspiciousPermissions;
            HasMismatch = hasMismatch;
        }
    }

    public sealed class SectionHeaderInfo
    {
        public string Name { get; }
        public int Index { get; }
        public uint VirtualAddress { get; }
        public uint VirtualSize { get; }
        public uint RawPointer { get; }
        public uint RawSize { get; }
        public uint Characteristics { get; }
        public IReadOnlyList<string> Flags { get; }
        public bool IsReadable { get; }
        public bool IsWritable { get; }
        public bool IsExecutable { get; }
        public bool IsCode { get; }
        public bool IsInitializedData { get; }
        public bool IsUninitializedData { get; }
        public bool IsDiscardable { get; }
        public bool IsShared { get; }
        public bool RawPointerAligned { get; }
        public bool RawSizeAligned { get; }
        public bool VirtualAddressAligned { get; }
        public bool RawDataInFileBounds { get; }
        public bool HasRawData { get; }
        public bool HasVirtualData { get; }
        public uint VirtualPadding { get; }
        public uint RawPadding { get; }
        public bool HasSizeMismatch { get; }
        public bool HasSuspiciousPermissions { get; }
        public bool HasMismatch { get; }
        public int RelocationCount { get; }
        public int LineNumberCount { get; }

        public SectionHeaderInfo(
            string name,
            int index,
            uint virtualAddress,
            uint virtualSize,
            uint rawPointer,
            uint rawSize,
            uint characteristics,
            string[] flags,
            bool isReadable,
            bool isWritable,
            bool isExecutable,
            bool isCode,
            bool isInitializedData,
            bool isUninitializedData,
            bool isDiscardable,
            bool isShared,
            bool rawPointerAligned,
            bool rawSizeAligned,
            bool virtualAddressAligned,
            bool rawDataInFileBounds,
            bool hasRawData,
            bool hasVirtualData,
            uint virtualPadding,
            uint rawPadding,
            bool hasSizeMismatch,
            bool hasSuspiciousPermissions,
            bool hasMismatch,
            int relocationCount,
            int lineNumberCount)
        {
            Name = name ?? string.Empty;
            Index = index;
            VirtualAddress = virtualAddress;
            VirtualSize = virtualSize;
            RawPointer = rawPointer;
            RawSize = rawSize;
            Characteristics = characteristics;
            Flags = Array.AsReadOnly(flags ?? Array.Empty<string>());
            IsReadable = isReadable;
            IsWritable = isWritable;
            IsExecutable = isExecutable;
            IsCode = isCode;
            IsInitializedData = isInitializedData;
            IsUninitializedData = isUninitializedData;
            IsDiscardable = isDiscardable;
            IsShared = isShared;
            RawPointerAligned = rawPointerAligned;
            RawSizeAligned = rawSizeAligned;
            VirtualAddressAligned = virtualAddressAligned;
            RawDataInFileBounds = rawDataInFileBounds;
            HasRawData = hasRawData;
            HasVirtualData = hasVirtualData;
            VirtualPadding = virtualPadding;
            RawPadding = rawPadding;
            HasSizeMismatch = hasSizeMismatch;
            HasSuspiciousPermissions = hasSuspiciousPermissions;
            HasMismatch = hasMismatch;
            RelocationCount = relocationCount;
            LineNumberCount = lineNumberCount;
        }
    }

    public sealed class SectionDirectoryInfo
    {
        public string SectionName { get; }
        public IReadOnlyList<string> Directories { get; }

        public SectionDirectoryInfo(string sectionName, string[] directories)
        {
            SectionName = sectionName ?? string.Empty;
            Directories = Array.AsReadOnly(directories ?? Array.Empty<string>());
        }
    }

    public sealed class ApiSetResolutionInfo
    {
        public bool IsApiSet { get; }
        public bool IsResolved { get; }
        public bool UsedFallback { get; }
        public string ApiSetName { get; }
        public string ResolutionSource { get; }
        public string ResolutionConfidence { get; }
        public IReadOnlyList<string> Targets { get; }
        public IReadOnlyList<string> CanonicalTargets { get; }

        public ApiSetResolutionInfo(
            bool isApiSet,
            bool isResolved,
            bool usedFallback,
            string apiSetName,
            string resolutionSource,
            string resolutionConfidence,
            string[] targets,
            string[] canonicalTargets)
        {
            IsApiSet = isApiSet;
            IsResolved = isResolved;
            UsedFallback = usedFallback;
            ApiSetName = apiSetName ?? string.Empty;
            ResolutionSource = resolutionSource ?? string.Empty;
            ResolutionConfidence = resolutionConfidence ?? string.Empty;
            Targets = Array.AsReadOnly(targets ?? Array.Empty<string>());
            CanonicalTargets = Array.AsReadOnly(canonicalTargets ?? Array.Empty<string>());
        }
    }

    public sealed class ApiSetSchemaInfo
    {
        public bool Loaded { get; }
        public int Version { get; }
        public string Flavor { get; }
        public string SourcePath { get; }

        public ApiSetSchemaInfo(bool loaded, int version, string flavor, string sourcePath)
        {
            Loaded = loaded;
            Version = version;
            Flavor = flavor ?? string.Empty;
            SourcePath = sourcePath ?? string.Empty;
        }
    }

    public sealed class ImportDescriptorInfo
    {
        public string DllName { get; }
        public uint TimeDateStamp { get; }
        public uint ImportNameTableRva { get; }
        public uint ImportAddressTableRva { get; }
        public bool IsBound { get; }
        public uint BoundTimeDateStamp { get; }
        public bool IsBoundStale { get; }
        public int IntCount { get; }
        public int IatCount { get; }
        public int IntNullThunkCount { get; }
        public int IatNullThunkCount { get; }
        public bool IntTerminated { get; }
        public bool IatTerminated { get; }
        public IReadOnlyList<string> IntOnlyFunctions { get; }
        public IReadOnlyList<string> IatOnlyFunctions { get; }
        public ApiSetResolutionInfo ApiSetResolution { get; }

        public ImportDescriptorInfo(
            string dllName,
            uint timeDateStamp,
            uint importNameTableRva,
            uint importAddressTableRva,
            bool isBound,
            uint boundTimeDateStamp,
            bool isBoundStale,
            int intCount,
            int iatCount,
            int intNullThunkCount,
            int iatNullThunkCount,
            bool intTerminated,
            bool iatTerminated,
            string[] intOnlyFunctions,
            string[] iatOnlyFunctions,
            ApiSetResolutionInfo apiSetResolution)
        {
            DllName = dllName ?? string.Empty;
            TimeDateStamp = timeDateStamp;
            ImportNameTableRva = importNameTableRva;
            ImportAddressTableRva = importAddressTableRva;
            IsBound = isBound;
            BoundTimeDateStamp = boundTimeDateStamp;
            IsBoundStale = isBoundStale;
            IntCount = intCount;
            IatCount = iatCount;
            IntNullThunkCount = intNullThunkCount;
            IatNullThunkCount = iatNullThunkCount;
            IntTerminated = intTerminated;
            IatTerminated = iatTerminated;
            IntOnlyFunctions = Array.AsReadOnly(intOnlyFunctions ?? Array.Empty<string>());
            IatOnlyFunctions = Array.AsReadOnly(iatOnlyFunctions ?? Array.Empty<string>());
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

    public sealed class ExportAnomalySummary
    {
        public int DuplicateNameCount { get; }
        public int DuplicateOrdinalCount { get; }
        public int OrdinalOutOfRangeCount { get; }
        public int ForwarderMissingTargetCount { get; }

        public ExportAnomalySummary(
            int duplicateNameCount,
            int duplicateOrdinalCount,
            int ordinalOutOfRangeCount,
            int forwarderMissingTargetCount)
        {
            DuplicateNameCount = duplicateNameCount;
            DuplicateOrdinalCount = duplicateOrdinalCount;
            OrdinalOutOfRangeCount = ordinalOutOfRangeCount;
            ForwarderMissingTargetCount = forwarderMissingTargetCount;
        }
    }

    public sealed class MetadataTableCountInfo
    {
        public int TableIndex { get; }
        public string TableName { get; }
        public int Count { get; }
        public uint FirstToken { get; }
        public uint LastToken { get; }

        public MetadataTableCountInfo(int tableIndex, string tableName, int count, uint firstToken, uint lastToken)
        {
            TableIndex = tableIndex;
            TableName = tableName ?? string.Empty;
            Count = count;
            FirstToken = firstToken;
            LastToken = lastToken;
        }
    }

    public sealed class ClrTokenReferenceCount
    {
        public string Target { get; }
        public int Count { get; }

        public ClrTokenReferenceCount(string target, int count)
        {
            Target = target ?? string.Empty;
            Count = count;
        }
    }

    public sealed class ClrTokenReferenceInfo
    {
        public string Name { get; }
        public IReadOnlyList<ClrTokenReferenceCount> Counts { get; }

        public ClrTokenReferenceInfo(string name, ClrTokenReferenceCount[] counts)
        {
            Name = name ?? string.Empty;
            Counts = Array.AsReadOnly(counts ?? Array.Empty<ClrTokenReferenceCount>());
        }
    }

    public sealed class ClrMethodBodySummaryInfo
    {
        public int MethodCount { get; }
        public int MethodBodyCount { get; }
        public int TinyHeaderCount { get; }
        public int FatHeaderCount { get; }
        public int InvalidHeaderCount { get; }
        public int TotalIlBytes { get; }
        public int MaxIlBytes { get; }
        public int AverageIlBytes { get; }

        public ClrMethodBodySummaryInfo(
            int methodCount,
            int methodBodyCount,
            int tinyHeaderCount,
            int fatHeaderCount,
            int invalidHeaderCount,
            int totalIlBytes,
            int maxIlBytes,
            int averageIlBytes)
        {
            MethodCount = methodCount;
            MethodBodyCount = methodBodyCount;
            TinyHeaderCount = tinyHeaderCount;
            FatHeaderCount = fatHeaderCount;
            InvalidHeaderCount = invalidHeaderCount;
            TotalIlBytes = totalIlBytes;
            MaxIlBytes = maxIlBytes;
            AverageIlBytes = averageIlBytes;
        }
    }

    public sealed class ReadyToRunSectionInfo
    {
        public uint Type { get; }
        public uint Rva { get; }
        public uint Size { get; }
        public string Name { get; }

        public ReadyToRunSectionInfo(uint type, uint rva, uint size, string name)
        {
            Type = type;
            Rva = rva;
            Size = size;
            Name = name ?? string.Empty;
        }
    }

    public sealed class ReadyToRunInfo
    {
        public uint Signature { get; }
        public string SignatureText { get; }
        public ushort MajorVersion { get; }
        public ushort MinorVersion { get; }
        public uint Flags { get; }
        public int SectionCount { get; }
        public int EntryPointSectionCount { get; }
        public uint EntryPointSectionTotalSize { get; }
        public IReadOnlyList<ReadyToRunSectionInfo> Sections { get; }

        public ReadyToRunInfo(
            uint signature,
            string signatureText,
            ushort majorVersion,
            ushort minorVersion,
            uint flags,
            int sectionCount,
            int entryPointSectionCount,
            uint entryPointSectionTotalSize,
            ReadyToRunSectionInfo[] sections)
        {
            Signature = signature;
            SignatureText = signatureText ?? string.Empty;
            MajorVersion = majorVersion;
            MinorVersion = minorVersion;
            Flags = flags;
            SectionCount = sectionCount;
            EntryPointSectionCount = entryPointSectionCount;
            EntryPointSectionTotalSize = entryPointSectionTotalSize;
            Sections = Array.AsReadOnly(sections ?? Array.Empty<ReadyToRunSectionInfo>());
        }
    }

    public sealed class MessageTableEntryInfo
    {
        public uint Id { get; }
        public string Text { get; }
        public bool IsUnicode { get; }
        public ushort Length { get; }
        public ushort Flags { get; }

        public MessageTableEntryInfo(uint id, string text, bool isUnicode, ushort length, ushort flags)
        {
            Id = id;
            Text = text ?? string.Empty;
            IsUnicode = isUnicode;
            Length = length;
            Flags = flags;
        }
    }

    public sealed class ResourceMessageTableInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public uint MinId { get; }
        public uint MaxId { get; }
        public IReadOnlyList<MessageTableEntryInfo> Entries { get; }

        public ResourceMessageTableInfo(
            uint nameId,
            ushort languageId,
            uint minId,
            uint maxId,
            MessageTableEntryInfo[] entries)
        {
            NameId = nameId;
            LanguageId = languageId;
            MinId = minId;
            MaxId = maxId;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<MessageTableEntryInfo>());
        }
    }

    public sealed class ResourceDialogInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public bool IsExtended { get; }
        public uint Style { get; }
        public uint ExtendedStyle { get; }
        public ushort ControlCount { get; }
        public short X { get; }
        public short Y { get; }
        public short Cx { get; }
        public short Cy { get; }
        public string Menu { get; }
        public string WindowClass { get; }
        public string Title { get; }
        public ushort? FontPointSize { get; }
        public string FontFace { get; }

        public ResourceDialogInfo(
            uint nameId,
            ushort languageId,
            bool isExtended,
            uint style,
            uint extendedStyle,
            ushort controlCount,
            short x,
            short y,
            short cx,
            short cy,
            string menu,
            string windowClass,
            string title,
            ushort? fontPointSize,
            string fontFace)
        {
            NameId = nameId;
            LanguageId = languageId;
            IsExtended = isExtended;
            Style = style;
            ExtendedStyle = extendedStyle;
            ControlCount = controlCount;
            X = x;
            Y = y;
            Cx = cx;
            Cy = cy;
            Menu = menu ?? string.Empty;
            WindowClass = windowClass ?? string.Empty;
            Title = title ?? string.Empty;
            FontPointSize = fontPointSize;
            FontFace = fontFace ?? string.Empty;
        }
    }

    public sealed class ResourceAcceleratorEntryInfo
    {
        public byte Flags { get; }
        public ushort Key { get; }
        public ushort Command { get; }
        public bool IsLast { get; }
        public string[] FlagNames { get; }

        public ResourceAcceleratorEntryInfo(byte flags, ushort key, ushort command, bool isLast, string[] flagNames)
        {
            Flags = flags;
            Key = key;
            Command = command;
            IsLast = isLast;
            FlagNames = flagNames ?? Array.Empty<string>();
        }
    }

    public sealed class ResourceAcceleratorTableInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public IReadOnlyList<ResourceAcceleratorEntryInfo> Entries { get; }

        public ResourceAcceleratorTableInfo(uint nameId, ushort languageId, ResourceAcceleratorEntryInfo[] entries)
        {
            NameId = nameId;
            LanguageId = languageId;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<ResourceAcceleratorEntryInfo>());
        }
    }

    public sealed class ResourceMenuInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public bool IsExtended { get; }
        public int ItemCount { get; }
        public IReadOnlyList<string> ItemTexts { get; }

        public ResourceMenuInfo(uint nameId, ushort languageId, bool isExtended, int itemCount, string[] itemTexts)
        {
            NameId = nameId;
            LanguageId = languageId;
            IsExtended = isExtended;
            ItemCount = itemCount;
            ItemTexts = Array.AsReadOnly(itemTexts ?? Array.Empty<string>());
        }
    }

    public sealed class ResourceToolbarInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public ushort Version { get; }
        public ushort Width { get; }
        public ushort Height { get; }
        public ushort ItemCount { get; }
        public IReadOnlyList<ushort> ItemIds { get; }

        public ResourceToolbarInfo(
            uint nameId,
            ushort languageId,
            ushort version,
            ushort width,
            ushort height,
            ushort itemCount,
            ushort[] itemIds)
        {
            NameId = nameId;
            LanguageId = languageId;
            Version = version;
            Width = width;
            Height = height;
            ItemCount = itemCount;
            ItemIds = Array.AsReadOnly(itemIds ?? Array.Empty<ushort>());
        }
    }

    public sealed class ResourceFontInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public uint Size { get; }
        public string Format { get; }
        public string FaceName { get; }

        public ResourceFontInfo(uint nameId, ushort languageId, uint size, string format, string faceName)
        {
            NameId = nameId;
            LanguageId = languageId;
            Size = size;
            Format = format ?? string.Empty;
            FaceName = faceName ?? string.Empty;
        }
    }

    public sealed class ResourceFontDirEntryInfo
    {
        public ushort Ordinal { get; }
        public string FaceName { get; }

        public ResourceFontDirEntryInfo(ushort ordinal, string faceName)
        {
            Ordinal = ordinal;
            FaceName = faceName ?? string.Empty;
        }
    }

    public sealed class ResourceFontDirInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public ushort FontCount { get; }
        public IReadOnlyList<ResourceFontDirEntryInfo> Entries { get; }

        public ResourceFontDirInfo(uint nameId, ushort languageId, ushort fontCount, ResourceFontDirEntryInfo[] entries)
        {
            NameId = nameId;
            LanguageId = languageId;
            FontCount = fontCount;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<ResourceFontDirEntryInfo>());
        }
    }

    public sealed class ResourceDlgInitEntryInfo
    {
        public ushort ControlId { get; }
        public ushort Message { get; }
        public ushort DataLength { get; }
        public string DataPreview { get; }

        public ResourceDlgInitEntryInfo(ushort controlId, ushort message, ushort dataLength, string dataPreview)
        {
            ControlId = controlId;
            Message = message;
            DataLength = dataLength;
            DataPreview = dataPreview ?? string.Empty;
        }
    }

    public sealed class ResourceDlgInitInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public IReadOnlyList<ResourceDlgInitEntryInfo> Entries { get; }

        public ResourceDlgInitInfo(uint nameId, ushort languageId, ResourceDlgInitEntryInfo[] entries)
        {
            NameId = nameId;
            LanguageId = languageId;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<ResourceDlgInitEntryInfo>());
        }
    }

    public sealed class ResourceAnimatedInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public string Format { get; }
        public uint FrameCount { get; }
        public uint StepCount { get; }
        public uint Width { get; }
        public uint Height { get; }
        public uint BitCount { get; }
        public uint Planes { get; }
        public uint JifRate { get; }
        public uint Flags { get; }
        public IReadOnlyList<string> ChunkTypes { get; }

        public ResourceAnimatedInfo(
            uint nameId,
            ushort languageId,
            string format,
            uint frameCount,
            uint stepCount,
            uint width,
            uint height,
            uint bitCount,
            uint planes,
            uint jifRate,
            uint flags,
            string[] chunkTypes)
        {
            NameId = nameId;
            LanguageId = languageId;
            Format = format ?? string.Empty;
            FrameCount = frameCount;
            StepCount = stepCount;
            Width = width;
            Height = height;
            BitCount = bitCount;
            Planes = planes;
            JifRate = jifRate;
            Flags = flags;
            ChunkTypes = Array.AsReadOnly(chunkTypes ?? Array.Empty<string>());
        }
    }

    public sealed class ResourceRcDataInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public uint Size { get; }
        public bool IsText { get; }
        public string Format { get; }
        public string FormatDetails { get; }
        public string TextPreview { get; }
        public double Entropy { get; }

        public ResourceRcDataInfo(
            uint nameId,
            ushort languageId,
            uint size,
            bool isText,
            string format,
            string formatDetails,
            string textPreview,
            double entropy)
        {
            NameId = nameId;
            LanguageId = languageId;
            Size = size;
            IsText = isText;
            Format = format ?? string.Empty;
            FormatDetails = formatDetails ?? string.Empty;
            TextPreview = textPreview ?? string.Empty;
            Entropy = entropy;
        }
    }

    public sealed class ResourceRawInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public uint Size { get; }
        public string Sha256 { get; }
        public bool IsText { get; }
        public string Preview { get; }

        public ResourceRawInfo(uint nameId, ushort languageId, uint size, string sha256, bool isText, string preview)
        {
            NameId = nameId;
            LanguageId = languageId;
            Size = size;
            Sha256 = sha256 ?? string.Empty;
            IsText = isText;
            Preview = preview ?? string.Empty;
        }
    }

    public sealed class ManifestSchemaInfo
    {
        public string RootElement { get; }
        public string Namespace { get; }
        public string ManifestVersion { get; }
        public string AssemblyIdentityName { get; }
        public string AssemblyIdentityVersion { get; }
        public string AssemblyIdentityArchitecture { get; }
        public string AssemblyIdentityType { get; }
        public string AssemblyIdentityLanguage { get; }
        public string RequestedExecutionLevel { get; }
        public string UiAccess { get; }
        public string DpiAware { get; }
        public string DpiAwareness { get; }
        public string UiLanguage { get; }
        public bool IsValid { get; }
        public IReadOnlyList<string> ValidationMessages { get; }

        public ManifestSchemaInfo(
            string rootElement,
            string schemaNamespace,
            string manifestVersion,
            string assemblyIdentityName,
            string assemblyIdentityVersion,
            string assemblyIdentityArchitecture,
            string assemblyIdentityType,
            string assemblyIdentityLanguage,
            string requestedExecutionLevel,
            string uiAccess,
            string dpiAware,
            string dpiAwareness,
            string uiLanguage,
            bool isValid,
            string[] validationMessages)
        {
            RootElement = rootElement ?? string.Empty;
            Namespace = schemaNamespace ?? string.Empty;
            ManifestVersion = manifestVersion ?? string.Empty;
            AssemblyIdentityName = assemblyIdentityName ?? string.Empty;
            AssemblyIdentityVersion = assemblyIdentityVersion ?? string.Empty;
            AssemblyIdentityArchitecture = assemblyIdentityArchitecture ?? string.Empty;
            AssemblyIdentityType = assemblyIdentityType ?? string.Empty;
            AssemblyIdentityLanguage = assemblyIdentityLanguage ?? string.Empty;
            RequestedExecutionLevel = requestedExecutionLevel ?? string.Empty;
            UiAccess = uiAccess ?? string.Empty;
            DpiAware = dpiAware ?? string.Empty;
            DpiAwareness = dpiAwareness ?? string.Empty;
            UiLanguage = uiLanguage ?? string.Empty;
            IsValid = isValid;
            ValidationMessages = Array.AsReadOnly(validationMessages ?? Array.Empty<string>());
        }
    }

    public sealed class PECOFFResult
    {
        public const int CurrentSchemaVersion = 28;

        public int SchemaVersion { get; }
        public string FilePath { get; }
        public ParseResultSnapshot ParseResult { get; }
        public string ImageKind { get; }
        public CoffObjectInfo CoffObject { get; }
        public CoffArchiveInfo CoffArchive { get; }
        public TeImageInfo TeImage { get; }
        public string Hash { get; }
        public string ImportHash { get; }
        public bool IsDotNetFile { get; }
        public string DotNetRuntimeHint { get; }
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
        public VersionInfoDetails VersionInfoDetails { get; }
        public uint FileAlignment { get; }
        public uint SectionAlignment { get; }
        public uint SizeOfHeaders { get; }
        public DosRelocationInfo DosRelocations { get; }
        public OverlayInfo OverlayInfo { get; }
        public IReadOnlyList<OverlayContainerInfo> OverlayContainers { get; }
        public IReadOnlyList<PackingHintInfo> PackingHints { get; }
        public IReadOnlyList<SectionEntropyInfo> SectionEntropies { get; }
        public IReadOnlyList<SectionSlackInfo> SectionSlacks { get; }
        public IReadOnlyList<SectionGapInfo> SectionGaps { get; }
        public IReadOnlyList<SectionPermissionInfo> SectionPermissions { get; }
        public IReadOnlyList<SectionHeaderInfo> SectionHeaders { get; }
        public IReadOnlyList<SectionDirectoryInfo> SectionDirectoryCoverage { get; }
        public IReadOnlyList<string> UnmappedDataDirectories { get; }
        public uint OptionalHeaderChecksum { get; }
        public uint ComputedChecksum { get; }
        public bool IsChecksumValid { get; }
        public uint TimeDateStamp { get; }
        public DateTimeOffset? TimeDateStampUtc { get; }
        public SubsystemInfo Subsystem { get; }
        public DllCharacteristicsInfo DllCharacteristics { get; }
        public SecurityFeaturesInfo SecurityFeatures { get; }
        public IReadOnlyList<DataDirectoryInfo> DataDirectories { get; }
        public IReadOnlyList<DataDirectoryValidationInfo> DataDirectoryValidations { get; }
        public ArchitectureDirectoryInfo ArchitectureDirectory { get; }
        public GlobalPtrDirectoryInfo GlobalPtrDirectory { get; }
        public IatDirectoryInfo IatDirectory { get; }
        public bool HasCertificate { get; }
        public byte[] Certificate { get; }
        public IReadOnlyList<byte[]> Certificates { get; }
        public IReadOnlyList<CertificateEntry> CertificateEntries { get; }
        public CatalogSignatureInfo CatalogSignature { get; }
        public IReadOnlyList<ResourceEntry> Resources { get; }
        public IReadOnlyList<ResourceStringTableInfo> ResourceStringTables { get; }
        public IReadOnlyList<ResourceStringCoverageInfo> ResourceStringCoverage { get; }
        public IReadOnlyList<ResourceMessageTableInfo> ResourceMessageTables { get; }
        public IReadOnlyList<ResourceDialogInfo> ResourceDialogs { get; }
        public IReadOnlyList<ResourceAcceleratorTableInfo> ResourceAccelerators { get; }
        public IReadOnlyList<ResourceMenuInfo> ResourceMenus { get; }
        public IReadOnlyList<ResourceToolbarInfo> ResourceToolbars { get; }
        public IReadOnlyList<ResourceManifestInfo> ResourceManifests { get; }
        public IReadOnlyList<ResourceLocaleCoverageInfo> ResourceLocaleCoverage { get; }
        public IReadOnlyList<ResourceBitmapInfo> ResourceBitmaps { get; }
        public IReadOnlyList<ResourceIconInfo> ResourceIcons { get; }
        public IReadOnlyList<ResourceCursorInfo> ResourceCursors { get; }
        public IReadOnlyList<ResourceCursorGroupInfo> ResourceCursorGroups { get; }
        public IReadOnlyList<ResourceFontInfo> ResourceFonts { get; }
        public IReadOnlyList<ResourceFontDirInfo> ResourceFontDirectories { get; }
        public IReadOnlyList<ResourceDlgInitInfo> ResourceDlgInit { get; }
        public IReadOnlyList<ResourceAnimatedInfo> ResourceAnimatedCursors { get; }
        public IReadOnlyList<ResourceAnimatedInfo> ResourceAnimatedIcons { get; }
        public IReadOnlyList<ResourceRcDataInfo> ResourceRcData { get; }
        public IReadOnlyList<ResourceRawInfo> ResourceHtml { get; }
        public IReadOnlyList<ResourceRawInfo> ResourceDlgInclude { get; }
        public IReadOnlyList<ResourceRawInfo> ResourcePlugAndPlay { get; }
        public IReadOnlyList<ResourceRawInfo> ResourceVxd { get; }
        public IReadOnlyList<IconGroupInfo> IconGroups { get; }
        public ClrMetadataInfo ClrMetadata { get; }
        public StrongNameSignatureInfo StrongNameSignature { get; }
        public StrongNameValidationInfo StrongNameValidation { get; }
        public ReadyToRunInfo ReadyToRun { get; }
        public IReadOnlyList<string> Imports { get; }
        public IReadOnlyList<ImportEntry> ImportEntries { get; }
        public IReadOnlyList<ImportDescriptorInfo> ImportDescriptors { get; }
        public IReadOnlyList<ImportEntry> DelayImportEntries { get; }
        public IReadOnlyList<DelayImportDescriptorInfo> DelayImportDescriptors { get; }
        public IReadOnlyList<string> Exports { get; }
        public IReadOnlyList<ExportEntry> ExportEntries { get; }
        public ExportAnomalySummary ExportAnomalies { get; }
        public IReadOnlyList<BoundImportEntry> BoundImports { get; }
        public IReadOnlyList<DebugDirectoryEntry> DebugDirectories { get; }
        public IReadOnlyList<BaseRelocationBlockInfo> BaseRelocations { get; }
        public IReadOnlyList<BaseRelocationSectionSummary> BaseRelocationSections { get; }
        public RelocationAnomalySummary RelocationAnomalies { get; }
        public ApiSetSchemaInfo ApiSetSchema { get; }
        public IReadOnlyList<ExceptionFunctionInfo> ExceptionFunctions { get; }
        public ExceptionDirectorySummary ExceptionSummary { get; }
        public IReadOnlyList<UnwindInfoDetail> UnwindInfoDetails { get; }
        public IReadOnlyList<Arm64UnwindInfoDetail> Arm64UnwindInfoDetails { get; }
        public IReadOnlyList<Arm32UnwindInfoDetail> Arm32UnwindInfoDetails { get; }
        public IReadOnlyList<Ia64UnwindInfoDetail> Ia64UnwindInfoDetails { get; }
        public RichHeaderInfo RichHeader { get; }
        public TlsInfo TlsInfo { get; }
        public LoadConfigInfo LoadConfig { get; }
        public IReadOnlyList<string> AssemblyReferences { get; }
        public IReadOnlyList<AssemblyReferenceInfo> AssemblyReferenceInfos { get; }
        public IReadOnlyList<CoffRelocationInfo> CoffRelocations { get; }
        public IReadOnlyList<CoffSymbolInfo> CoffSymbols { get; }
        public IReadOnlyList<CoffStringTableEntry> CoffStringTable { get; }
        public IReadOnlyList<CoffLineNumberInfo> CoffLineNumbers { get; }

        internal PECOFFResult(
            string filePath,
            ParseResultSnapshot parseResult,
            string imageKind,
            CoffObjectInfo coffObject,
            CoffArchiveInfo coffArchive,
            TeImageInfo teImage,
            string hash,
            string importHash,
            bool isDotNetFile,
            string dotNetRuntimeHint,
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
            VersionInfoDetails versionInfoDetails,
            uint fileAlignment,
            uint sectionAlignment,
            uint sizeOfHeaders,
            DosRelocationInfo dosRelocations,
            OverlayInfo overlayInfo,
            OverlayContainerInfo[] overlayContainers,
            PackingHintInfo[] packingHints,
            SectionEntropyInfo[] sectionEntropies,
            SectionSlackInfo[] sectionSlacks,
            SectionGapInfo[] sectionGaps,
            SectionPermissionInfo[] sectionPermissions,
            SectionHeaderInfo[] sectionHeaders,
            SectionDirectoryInfo[] sectionDirectoryCoverage,
            string[] unmappedDataDirectories,
            uint optionalHeaderChecksum,
            uint computedChecksum,
            bool isChecksumValid,
            uint timeDateStamp,
            DateTimeOffset? timeDateStampUtc,
            SubsystemInfo subsystem,
            DllCharacteristicsInfo dllCharacteristics,
            SecurityFeaturesInfo securityFeatures,
            DataDirectoryInfo[] dataDirectories,
            DataDirectoryValidationInfo[] dataDirectoryValidations,
            ArchitectureDirectoryInfo architectureDirectory,
            GlobalPtrDirectoryInfo globalPtrDirectory,
            IatDirectoryInfo iatDirectory,
            bool hasCertificate,
            byte[] certificate,
            byte[][] certificates,
            CertificateEntry[] certificateEntries,
            CatalogSignatureInfo catalogSignature,
            ResourceEntry[] resources,
            ResourceStringTableInfo[] resourceStringTables,
            ResourceStringCoverageInfo[] resourceStringCoverage,
            ResourceMessageTableInfo[] resourceMessageTables,
            ResourceDialogInfo[] resourceDialogs,
            ResourceAcceleratorTableInfo[] resourceAccelerators,
            ResourceMenuInfo[] resourceMenus,
            ResourceToolbarInfo[] resourceToolbars,
            ResourceManifestInfo[] resourceManifests,
            ResourceLocaleCoverageInfo[] resourceLocaleCoverage,
            ResourceBitmapInfo[] resourceBitmaps,
            ResourceIconInfo[] resourceIcons,
            ResourceCursorInfo[] resourceCursors,
            ResourceCursorGroupInfo[] resourceCursorGroups,
            ResourceFontInfo[] resourceFonts,
            ResourceFontDirInfo[] resourceFontDirectories,
            ResourceDlgInitInfo[] resourceDlgInit,
            ResourceAnimatedInfo[] resourceAnimatedCursors,
            ResourceAnimatedInfo[] resourceAnimatedIcons,
            ResourceRcDataInfo[] resourceRcData,
            ResourceRawInfo[] resourceHtml,
            ResourceRawInfo[] resourceDlgInclude,
            ResourceRawInfo[] resourcePlugAndPlay,
            ResourceRawInfo[] resourceVxd,
            IconGroupInfo[] iconGroups,
            ClrMetadataInfo clrMetadata,
            StrongNameSignatureInfo strongNameSignature,
            StrongNameValidationInfo strongNameValidation,
            ReadyToRunInfo readyToRun,
            string[] imports,
            ImportEntry[] importEntries,
            ImportDescriptorInfo[] importDescriptors,
            ImportEntry[] delayImportEntries,
            DelayImportDescriptorInfo[] delayImportDescriptors,
            string[] exports,
            ExportEntry[] exportEntries,
            ExportAnomalySummary exportAnomalies,
            BoundImportEntry[] boundImports,
            DebugDirectoryEntry[] debugDirectories,
            BaseRelocationBlockInfo[] baseRelocations,
            BaseRelocationSectionSummary[] baseRelocationSections,
            RelocationAnomalySummary relocationAnomalies,
            ApiSetSchemaInfo apiSetSchema,
            ExceptionFunctionInfo[] exceptionFunctions,
            ExceptionDirectorySummary exceptionSummary,
            UnwindInfoDetail[] unwindInfoDetails,
            Arm64UnwindInfoDetail[] arm64UnwindInfoDetails,
            Arm32UnwindInfoDetail[] arm32UnwindInfoDetails,
            Ia64UnwindInfoDetail[] ia64UnwindInfoDetails,
            RichHeaderInfo richHeader,
            TlsInfo tlsInfo,
            LoadConfigInfo loadConfig,
            string[] assemblyReferences,
            AssemblyReferenceInfo[] assemblyReferenceInfos,
            CoffRelocationInfo[] coffRelocations,
            CoffSymbolInfo[] coffSymbols,
            CoffStringTableEntry[] coffStringTable,
            CoffLineNumberInfo[] coffLineNumbers)
        {
            SchemaVersion = CurrentSchemaVersion;
            FilePath = filePath ?? string.Empty;
            ParseResult = parseResult ?? new ParseResultSnapshot(Array.Empty<string>(), Array.Empty<string>(), Array.Empty<ParseIssue>());
            ImageKind = imageKind ?? string.Empty;
            CoffObject = coffObject;
            CoffArchive = coffArchive;
            TeImage = teImage;
            Hash = hash ?? string.Empty;
            ImportHash = importHash ?? string.Empty;
            IsDotNetFile = isDotNetFile;
            DotNetRuntimeHint = dotNetRuntimeHint ?? string.Empty;
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
            VersionInfoDetails = versionInfoDetails;
            FileAlignment = fileAlignment;
            SectionAlignment = sectionAlignment;
            SizeOfHeaders = sizeOfHeaders;
            DosRelocations = dosRelocations ?? new DosRelocationInfo(0, 0, false, Array.Empty<DosRelocationEntry>());
            OverlayInfo = overlayInfo ?? new OverlayInfo(0, 0);
            OverlayContainers = Array.AsReadOnly(overlayContainers ?? Array.Empty<OverlayContainerInfo>());
            PackingHints = Array.AsReadOnly(packingHints ?? Array.Empty<PackingHintInfo>());
            SectionEntropies = Array.AsReadOnly(sectionEntropies ?? Array.Empty<SectionEntropyInfo>());
            SectionSlacks = Array.AsReadOnly(sectionSlacks ?? Array.Empty<SectionSlackInfo>());
            SectionGaps = Array.AsReadOnly(sectionGaps ?? Array.Empty<SectionGapInfo>());
            SectionPermissions = Array.AsReadOnly(sectionPermissions ?? Array.Empty<SectionPermissionInfo>());
            SectionHeaders = Array.AsReadOnly(sectionHeaders ?? Array.Empty<SectionHeaderInfo>());
            SectionDirectoryCoverage = Array.AsReadOnly(sectionDirectoryCoverage ?? Array.Empty<SectionDirectoryInfo>());
            UnmappedDataDirectories = Array.AsReadOnly(unmappedDataDirectories ?? Array.Empty<string>());
            OptionalHeaderChecksum = optionalHeaderChecksum;
            ComputedChecksum = computedChecksum;
            IsChecksumValid = isChecksumValid;
            TimeDateStamp = timeDateStamp;
            TimeDateStampUtc = timeDateStampUtc;
            Subsystem = subsystem;
            DllCharacteristics = dllCharacteristics;
            SecurityFeatures = securityFeatures;
            DataDirectories = Array.AsReadOnly(dataDirectories ?? Array.Empty<DataDirectoryInfo>());
            DataDirectoryValidations = Array.AsReadOnly(dataDirectoryValidations ?? Array.Empty<DataDirectoryValidationInfo>());
            ArchitectureDirectory = architectureDirectory;
            GlobalPtrDirectory = globalPtrDirectory;
            IatDirectory = iatDirectory;
            HasCertificate = hasCertificate;
            Certificate = certificate ?? Array.Empty<byte>();
            Certificates = Array.AsReadOnly(certificates ?? Array.Empty<byte[]>());
            CertificateEntries = Array.AsReadOnly(certificateEntries ?? Array.Empty<CertificateEntry>());
            CatalogSignature = catalogSignature;
            Resources = Array.AsReadOnly(resources ?? Array.Empty<ResourceEntry>());
            ResourceStringTables = Array.AsReadOnly(resourceStringTables ?? Array.Empty<ResourceStringTableInfo>());
            ResourceStringCoverage = Array.AsReadOnly(resourceStringCoverage ?? Array.Empty<ResourceStringCoverageInfo>());
            ResourceMessageTables = Array.AsReadOnly(resourceMessageTables ?? Array.Empty<ResourceMessageTableInfo>());
            ResourceDialogs = Array.AsReadOnly(resourceDialogs ?? Array.Empty<ResourceDialogInfo>());
            ResourceAccelerators = Array.AsReadOnly(resourceAccelerators ?? Array.Empty<ResourceAcceleratorTableInfo>());
            ResourceMenus = Array.AsReadOnly(resourceMenus ?? Array.Empty<ResourceMenuInfo>());
            ResourceToolbars = Array.AsReadOnly(resourceToolbars ?? Array.Empty<ResourceToolbarInfo>());
            ResourceManifests = Array.AsReadOnly(resourceManifests ?? Array.Empty<ResourceManifestInfo>());
            ResourceLocaleCoverage = Array.AsReadOnly(resourceLocaleCoverage ?? Array.Empty<ResourceLocaleCoverageInfo>());
            ResourceBitmaps = Array.AsReadOnly(resourceBitmaps ?? Array.Empty<ResourceBitmapInfo>());
            ResourceIcons = Array.AsReadOnly(resourceIcons ?? Array.Empty<ResourceIconInfo>());
            ResourceCursors = Array.AsReadOnly(resourceCursors ?? Array.Empty<ResourceCursorInfo>());
            ResourceCursorGroups = Array.AsReadOnly(resourceCursorGroups ?? Array.Empty<ResourceCursorGroupInfo>());
            ResourceFonts = Array.AsReadOnly(resourceFonts ?? Array.Empty<ResourceFontInfo>());
            ResourceFontDirectories = Array.AsReadOnly(resourceFontDirectories ?? Array.Empty<ResourceFontDirInfo>());
            ResourceDlgInit = Array.AsReadOnly(resourceDlgInit ?? Array.Empty<ResourceDlgInitInfo>());
            ResourceAnimatedCursors = Array.AsReadOnly(resourceAnimatedCursors ?? Array.Empty<ResourceAnimatedInfo>());
            ResourceAnimatedIcons = Array.AsReadOnly(resourceAnimatedIcons ?? Array.Empty<ResourceAnimatedInfo>());
            ResourceRcData = Array.AsReadOnly(resourceRcData ?? Array.Empty<ResourceRcDataInfo>());
            ResourceHtml = Array.AsReadOnly(resourceHtml ?? Array.Empty<ResourceRawInfo>());
            ResourceDlgInclude = Array.AsReadOnly(resourceDlgInclude ?? Array.Empty<ResourceRawInfo>());
            ResourcePlugAndPlay = Array.AsReadOnly(resourcePlugAndPlay ?? Array.Empty<ResourceRawInfo>());
            ResourceVxd = Array.AsReadOnly(resourceVxd ?? Array.Empty<ResourceRawInfo>());
            IconGroups = Array.AsReadOnly(iconGroups ?? Array.Empty<IconGroupInfo>());
            ClrMetadata = clrMetadata;
            StrongNameSignature = strongNameSignature;
            StrongNameValidation = strongNameValidation;
            ReadyToRun = readyToRun;
            Imports = Array.AsReadOnly(imports ?? Array.Empty<string>());
            ImportEntries = Array.AsReadOnly(importEntries ?? Array.Empty<ImportEntry>());
            ImportDescriptors = Array.AsReadOnly(importDescriptors ?? Array.Empty<ImportDescriptorInfo>());
            DelayImportEntries = Array.AsReadOnly(delayImportEntries ?? Array.Empty<ImportEntry>());
            DelayImportDescriptors = Array.AsReadOnly(delayImportDescriptors ?? Array.Empty<DelayImportDescriptorInfo>());
            Exports = Array.AsReadOnly(exports ?? Array.Empty<string>());
            ExportEntries = Array.AsReadOnly(exportEntries ?? Array.Empty<ExportEntry>());
            ExportAnomalies = exportAnomalies ?? new ExportAnomalySummary(0, 0, 0, 0);
            BoundImports = Array.AsReadOnly(boundImports ?? Array.Empty<BoundImportEntry>());
            DebugDirectories = Array.AsReadOnly(debugDirectories ?? Array.Empty<DebugDirectoryEntry>());
            BaseRelocations = Array.AsReadOnly(baseRelocations ?? Array.Empty<BaseRelocationBlockInfo>());
            BaseRelocationSections = Array.AsReadOnly(baseRelocationSections ?? Array.Empty<BaseRelocationSectionSummary>());
            RelocationAnomalies = relocationAnomalies ?? new RelocationAnomalySummary(0, 0, 0, 0, 0);
            ApiSetSchema = apiSetSchema ?? new ApiSetSchemaInfo(false, 0, string.Empty, string.Empty);
            ExceptionFunctions = Array.AsReadOnly(exceptionFunctions ?? Array.Empty<ExceptionFunctionInfo>());
            ExceptionSummary = exceptionSummary;
            UnwindInfoDetails = Array.AsReadOnly(unwindInfoDetails ?? Array.Empty<UnwindInfoDetail>());
            Arm64UnwindInfoDetails = Array.AsReadOnly(arm64UnwindInfoDetails ?? Array.Empty<Arm64UnwindInfoDetail>());
            Arm32UnwindInfoDetails = Array.AsReadOnly(arm32UnwindInfoDetails ?? Array.Empty<Arm32UnwindInfoDetail>());
            Ia64UnwindInfoDetails = Array.AsReadOnly(ia64UnwindInfoDetails ?? Array.Empty<Ia64UnwindInfoDetail>());
            RichHeader = richHeader;
            TlsInfo = tlsInfo;
            LoadConfig = loadConfig;
            AssemblyReferences = Array.AsReadOnly(assemblyReferences ?? Array.Empty<string>());
            AssemblyReferenceInfos = Array.AsReadOnly(assemblyReferenceInfos ?? Array.Empty<AssemblyReferenceInfo>());
            CoffRelocations = Array.AsReadOnly(coffRelocations ?? Array.Empty<CoffRelocationInfo>());
            CoffSymbols = Array.AsReadOnly(coffSymbols ?? Array.Empty<CoffSymbolInfo>());
            CoffStringTable = Array.AsReadOnly(coffStringTable ?? Array.Empty<CoffStringTableEntry>());
            CoffLineNumbers = Array.AsReadOnly(coffLineNumbers ?? Array.Empty<CoffLineNumberInfo>());
        }

        public string ToJsonReport(bool includeBinary = false, bool indented = true, bool stableOrdering = true)
        {
            JsonSerializerOptions options = new JsonSerializerOptions { WriteIndented = indented };
            object certificateEntries = includeBinary
                ? (object)CertificateEntries
                : CertificateEntries.Select(entry => new
                {
                    entry.Type,
                    entry.DeclaredLength,
                    entry.Revision,
                    entry.AlignedLength,
                    entry.AlignmentPadding,
                    entry.FileOffset,
                    Size = entry.Data?.Length ?? 0,
                    entry.Pkcs7Error,
                    SignerCount = entry.Pkcs7SignerInfos?.Length ?? 0,
                    entry.AuthenticodeStatus
                }).ToArray();

            object iconGroups = includeBinary
                ? (object)IconGroups
                : IconGroups.Select(group => new
                {
                    group.NameId,
                    group.LanguageId,
                    group.HeaderReserved,
                    group.HeaderType,
                    group.DeclaredEntryCount,
                    group.EntrySize,
                    group.HeaderValid,
                    group.EntriesTruncated,
                    group.Entries,
                    IcoSize = group.IcoData?.Length ?? 0
                }).ToArray();

            object strongNameSignature = includeBinary
                ? (object)StrongNameSignature
                : (StrongNameSignature == null
                    ? null
                    : new
                    {
                        StrongNameSignature.Rva,
                        StrongNameSignature.Size,
                        DataSize = StrongNameSignature.Data?.Length ?? 0
                    });

            string[] imports = stableOrdering
                ? Imports.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray()
                : Imports.ToArray();
            string[] exports = stableOrdering
                ? Exports.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray()
                : Exports.ToArray();
            string[] assemblyRefs = stableOrdering
                ? AssemblyReferences.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray()
                : AssemblyReferences.ToArray();
            PackingHintInfo[] packingHints = stableOrdering
                ? PackingHints.OrderBy(hint => hint.Name, StringComparer.OrdinalIgnoreCase).ToArray()
                : PackingHints.ToArray();
            SectionEntropyInfo[] entropies = stableOrdering
                ? SectionEntropies.OrderBy(info => info.Name, StringComparer.OrdinalIgnoreCase).ToArray()
                : SectionEntropies.ToArray();
            SectionSlackInfo[] slacks = stableOrdering
                ? SectionSlacks.OrderBy(info => info.SectionName, StringComparer.OrdinalIgnoreCase).ToArray()
                : SectionSlacks.ToArray();
            SectionGapInfo[] gaps = stableOrdering
                ? SectionGaps.OrderBy(info => info.PreviousSection, StringComparer.OrdinalIgnoreCase).ToArray()
                : SectionGaps.ToArray();
            SectionPermissionInfo[] permissions = stableOrdering
                ? SectionPermissions.OrderBy(info => info.Name, StringComparer.OrdinalIgnoreCase).ToArray()
                : SectionPermissions.ToArray();
            SectionHeaderInfo[] sectionHeaders = stableOrdering
                ? SectionHeaders.OrderBy(info => info.Index).ToArray()
                : SectionHeaders.ToArray();
            SectionDirectoryInfo[] sectionDirectories = stableOrdering
                ? SectionDirectoryCoverage.OrderBy(info => info.SectionName, StringComparer.OrdinalIgnoreCase).ToArray()
                : SectionDirectoryCoverage.ToArray();
            string[] unmappedDirectories = stableOrdering
                ? UnmappedDataDirectories.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray()
                : UnmappedDataDirectories.ToArray();
            DataDirectoryValidationInfo[] directoryValidations = stableOrdering
                ? DataDirectoryValidations.OrderBy(info => info.Index).ToArray()
                : DataDirectoryValidations.ToArray();
            ResourceStringCoverageInfo[] stringCoverage = stableOrdering
                ? ResourceStringCoverage.OrderBy(info => info.LanguageId).ToArray()
                : ResourceStringCoverage.ToArray();
            ResourceLocaleCoverageInfo[] resourceCoverage = stableOrdering
                ? ResourceLocaleCoverage.OrderBy(info => info.ResourceKind, StringComparer.OrdinalIgnoreCase).ToArray()
                : ResourceLocaleCoverage.ToArray();

            var report = new
            {
                SchemaVersion,
                FilePath,
                ParseResult,
                ImageKind,
                CoffObject,
                TeImage,
                Hash,
                ImportHash,
                IsDotNetFile,
                DotNetRuntimeHint,
                IsObfuscated,
                ObfuscationPercentage,
                FileVersion,
                ProductVersion,
                CompanyName,
                FileDescription,
                InternalName,
                OriginalFilename,
                ProductName,
                Comments,
                LegalCopyright,
                LegalTrademarks,
                PrivateBuild,
                SpecialBuild,
                Language,
                VersionInfoDetails,
                FileAlignment,
                SectionAlignment,
                SizeOfHeaders,
                OverlayInfo,
                OverlayContainers,
                PackingHints = packingHints,
                SectionEntropies = entropies,
                SectionSlacks = slacks,
                SectionGaps = gaps,
                SectionPermissions = permissions,
                SectionHeaders = sectionHeaders,
                SectionDirectoryCoverage = sectionDirectories,
                UnmappedDataDirectories = unmappedDirectories,
                OptionalHeaderChecksum,
                ComputedChecksum,
                IsChecksumValid,
                TimeDateStamp,
                TimeDateStampUtc,
                Subsystem,
                DllCharacteristics,
                SecurityFeatures,
                DataDirectories,
                DataDirectoryValidations = directoryValidations,
                ArchitectureDirectory,
                GlobalPtrDirectory,
                IatDirectory,
                HasCertificate,
                CertificateEntries = certificateEntries,
                CatalogSignature,
                Resources,
                ResourceStringTables,
                ResourceStringCoverage = stringCoverage,
                ResourceMessageTables,
                ResourceDialogs,
                ResourceAccelerators,
                ResourceMenus,
                ResourceToolbars,
                ResourceManifests,
                ResourceLocaleCoverage = resourceCoverage,
                ResourceBitmaps,
                ResourceIcons,
                ResourceCursors,
                ResourceCursorGroups,
                ResourceFonts,
                ResourceFontDirectories,
                ResourceDlgInit,
                ResourceAnimatedCursors,
                ResourceAnimatedIcons,
                ResourceRcData,
                ResourceHtml,
                ResourceDlgInclude,
                ResourcePlugAndPlay,
                ResourceVxd,
                IconGroups = iconGroups,
                ClrMetadata,
                StrongNameSignature = strongNameSignature,
                StrongNameValidation,
                ReadyToRun,
                Imports = imports,
                ImportEntries,
                ImportDescriptors,
                DelayImportEntries,
                DelayImportDescriptors,
                Exports = exports,
                ExportEntries,
                ExportAnomalies,
                BoundImports,
                DebugDirectories,
                BaseRelocations,
                BaseRelocationSections,
                RelocationAnomalies,
                ApiSetSchema,
                ExceptionFunctions,
                ExceptionSummary,
                UnwindInfoDetails,
                Arm64UnwindInfoDetails,
                Arm32UnwindInfoDetails,
                Ia64UnwindInfoDetails,
                RichHeader,
                TlsInfo,
                LoadConfig,
                AssemblyReferences = assemblyRefs,
                AssemblyReferenceInfos,
                CoffRelocations,
                CoffSymbols,
                CoffStringTable,
                CoffLineNumbers
            };

            return JsonSerializer.Serialize(report, options);
        }
    }

    public sealed class ClrAssemblyReferenceInfo
    {
        public string Name { get; }
        public string Version { get; }
        public string Culture { get; }
        public string PublicKeyOrToken { get; }
        public string PublicKeyToken { get; }
        public bool IsPublicKey { get; }
        public string ResolutionHint { get; }
        public int Token { get; }
        public int RowId { get; }
        public string FullName { get; }

        public ClrAssemblyReferenceInfo(
            string name,
            string version,
            string culture,
            string publicKeyOrToken,
            string publicKeyToken,
            bool isPublicKey,
            string resolutionHint,
            int token,
            int rowId,
            string fullName)
        {
            Name = name ?? string.Empty;
            Version = version ?? string.Empty;
            Culture = culture ?? string.Empty;
            PublicKeyOrToken = publicKeyOrToken ?? string.Empty;
            PublicKeyToken = publicKeyToken ?? string.Empty;
            IsPublicKey = isPublicKey;
            ResolutionHint = resolutionHint ?? string.Empty;
            Token = token;
            RowId = rowId;
            FullName = fullName ?? string.Empty;
        }
    }

    public sealed class ResourceStringTableInfo
    {
        public uint BlockId { get; }
        public ushort LanguageId { get; }
        public string[] Strings { get; }

        public ResourceStringTableInfo(uint blockId, ushort languageId, string[] strings)
        {
            BlockId = blockId;
            LanguageId = languageId;
            Strings = strings ?? Array.Empty<string>();
        }
    }

    public sealed class ResourceLocaleCoverageInfo
    {
        public string ResourceKind { get; }
        public IReadOnlyList<ushort> LanguageIds { get; }
        public bool HasNeutralLanguage { get; }
        public bool HasLocalizedLanguage { get; }
        public bool MissingNeutralFallback { get; }

        public ResourceLocaleCoverageInfo(
            string resourceKind,
            ushort[] languageIds,
            bool hasNeutralLanguage,
            bool hasLocalizedLanguage,
            bool missingNeutralFallback)
        {
            ResourceKind = resourceKind ?? string.Empty;
            LanguageIds = Array.AsReadOnly(languageIds ?? Array.Empty<ushort>());
            HasNeutralLanguage = hasNeutralLanguage;
            HasLocalizedLanguage = hasLocalizedLanguage;
            MissingNeutralFallback = missingNeutralFallback;
        }
    }

    public sealed class ResourceManifestInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public uint TypeId { get; }
        public string TypeName { get; }
        public string Content { get; }
        public ManifestSchemaInfo Schema { get; }
        public bool IsMui { get; }

        public ResourceManifestInfo(
            uint nameId,
            ushort languageId,
            uint typeId,
            string typeName,
            string content,
            ManifestSchemaInfo schema,
            bool isMui)
        {
            NameId = nameId;
            LanguageId = languageId;
            TypeId = typeId;
            TypeName = typeName ?? string.Empty;
            Content = content ?? string.Empty;
            Schema = schema;
            IsMui = isMui;
        }
    }

    public sealed class ResourceBitmapInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public int Width { get; }
        public int Height { get; }
        public ushort BitCount { get; }
        public uint Compression { get; }
        public string CompressionName { get; }
        public uint ImageSize { get; }

        public ResourceBitmapInfo(
            uint nameId,
            ushort languageId,
            int width,
            int height,
            ushort bitCount,
            uint compression,
            string compressionName,
            uint imageSize)
        {
            NameId = nameId;
            LanguageId = languageId;
            Width = width;
            Height = height;
            BitCount = bitCount;
            Compression = compression;
            CompressionName = compressionName ?? string.Empty;
            ImageSize = imageSize;
        }
    }

    public sealed class ResourceIconInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public int Width { get; }
        public int Height { get; }
        public ushort BitCount { get; }
        public bool IsPng { get; }
        public uint PngWidth { get; }
        public uint PngHeight { get; }
        public uint Size { get; }

        public ResourceIconInfo(
            uint nameId,
            ushort languageId,
            int width,
            int height,
            ushort bitCount,
            bool isPng,
            uint pngWidth,
            uint pngHeight,
            uint size)
        {
            NameId = nameId;
            LanguageId = languageId;
            Width = width;
            Height = height;
            BitCount = bitCount;
            IsPng = isPng;
            PngWidth = pngWidth;
            PngHeight = pngHeight;
            Size = size;
        }
    }

    public sealed class ResourceCursorInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public ushort HotspotX { get; }
        public ushort HotspotY { get; }
        public int Width { get; }
        public int Height { get; }
        public ushort BitCount { get; }
        public bool IsPng { get; }
        public uint PngWidth { get; }
        public uint PngHeight { get; }
        public uint Size { get; }

        public ResourceCursorInfo(
            uint nameId,
            ushort languageId,
            ushort hotspotX,
            ushort hotspotY,
            int width,
            int height,
            ushort bitCount,
            bool isPng,
            uint pngWidth,
            uint pngHeight,
            uint size)
        {
            NameId = nameId;
            LanguageId = languageId;
            HotspotX = hotspotX;
            HotspotY = hotspotY;
            Width = width;
            Height = height;
            BitCount = bitCount;
            IsPng = isPng;
            PngWidth = pngWidth;
            PngHeight = pngHeight;
            Size = size;
        }
    }

    public sealed class ResourceCursorEntryInfo
    {
        public byte Width { get; }
        public byte Height { get; }
        public ushort HotspotX { get; }
        public ushort HotspotY { get; }
        public uint BytesInRes { get; }
        public ushort ResourceId { get; }
        public bool IsPng { get; }
        public uint PngWidth { get; }
        public uint PngHeight { get; }

        public ResourceCursorEntryInfo(
            byte width,
            byte height,
            ushort hotspotX,
            ushort hotspotY,
            uint bytesInRes,
            ushort resourceId,
            bool isPng,
            uint pngWidth,
            uint pngHeight)
        {
            Width = width;
            Height = height;
            HotspotX = hotspotX;
            HotspotY = hotspotY;
            BytesInRes = bytesInRes;
            ResourceId = resourceId;
            IsPng = isPng;
            PngWidth = pngWidth;
            PngHeight = pngHeight;
        }
    }

    public sealed class ResourceCursorGroupInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public ushort HeaderReserved { get; }
        public ushort HeaderType { get; }
        public ushort DeclaredEntryCount { get; }
        public int EntrySize { get; }
        public bool HeaderValid { get; }
        public bool EntriesTruncated { get; }
        public IReadOnlyList<ResourceCursorEntryInfo> Entries { get; }

        public ResourceCursorGroupInfo(
            uint nameId,
            ushort languageId,
            ushort headerReserved,
            ushort headerType,
            ushort declaredEntryCount,
            int entrySize,
            bool headerValid,
            bool entriesTruncated,
            ResourceCursorEntryInfo[] entries)
        {
            NameId = nameId;
            LanguageId = languageId;
            HeaderReserved = headerReserved;
            HeaderType = headerType;
            DeclaredEntryCount = declaredEntryCount;
            EntrySize = entrySize;
            HeaderValid = headerValid;
            EntriesTruncated = entriesTruncated;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<ResourceCursorEntryInfo>());
        }
    }
}
