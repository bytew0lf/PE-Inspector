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
                    EnableTrustStoreCheck = true,
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
        public bool EnableTrustStoreCheck { get; init; } = true;
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
        Repro = 16
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

        public RichHeaderInfo(uint key, RichHeaderEntry[] entries)
        {
            Key = key;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<RichHeaderEntry>());
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
        public int FunctionCount { get; }
        public int InvalidRangeCount { get; }
        public int OutOfRangeCount { get; }
        public int UnwindInfoCount { get; }
        public int UnwindInfoParseFailures { get; }
        public IReadOnlyList<UnwindInfoVersionCount> UnwindInfoVersions { get; }

        public ExceptionDirectorySummary(
            int functionCount,
            int invalidRangeCount,
            int outOfRangeCount,
            int unwindInfoCount,
            int unwindInfoParseFailures,
            UnwindInfoVersionCount[] unwindInfoVersions)
        {
            FunctionCount = functionCount;
            InvalidRangeCount = invalidRangeCount;
            OutOfRangeCount = outOfRangeCount;
            UnwindInfoCount = unwindInfoCount;
            UnwindInfoParseFailures = unwindInfoParseFailures;
            UnwindInfoVersions = Array.AsReadOnly(unwindInfoVersions ?? Array.Empty<UnwindInfoVersionCount>());
        }
    }

    public sealed class RelocationAnomalySummary
    {
        public int ZeroSizedBlockCount { get; }
        public int EmptyBlockCount { get; }
        public int InvalidBlockCount { get; }
        public int OrphanedBlockCount { get; }

        public RelocationAnomalySummary(int zeroSizedBlockCount, int emptyBlockCount, int invalidBlockCount, int orphanedBlockCount)
        {
            ZeroSizedBlockCount = zeroSizedBlockCount;
            EmptyBlockCount = emptyBlockCount;
            InvalidBlockCount = invalidBlockCount;
            OrphanedBlockCount = orphanedBlockCount;
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
        public IReadOnlyList<ulong> CallbackAddresses { get; }
        public IReadOnlyList<TlsCallbackInfo> CallbackInfos { get; }

        public TlsInfo(
            ulong startAddressOfRawData,
            ulong endAddressOfRawData,
            ulong addressOfIndex,
            ulong addressOfCallbacks,
            uint sizeOfZeroFill,
            uint characteristics,
            ulong[] callbackAddresses,
            TlsCallbackInfo[] callbackInfos)
        {
            StartAddressOfRawData = startAddressOfRawData;
            EndAddressOfRawData = endAddressOfRawData;
            AddressOfIndex = addressOfIndex;
            AddressOfCallbacks = addressOfCallbacks;
            SizeOfZeroFill = sizeOfZeroFill;
            Characteristics = characteristics;
            CallbackAddresses = Array.AsReadOnly(callbackAddresses ?? Array.Empty<ulong>());
            CallbackInfos = Array.AsReadOnly(callbackInfos ?? Array.Empty<TlsCallbackInfo>());
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
        public uint TimeDateStamp { get; }
        public ushort MajorVersion { get; }
        public ushort MinorVersion { get; }
        public uint GlobalFlagsClear { get; }
        public uint GlobalFlagsSet { get; }
        public LoadConfigGlobalFlagsInfo GlobalFlagsInfo { get; }
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
        public ulong ChpeMetadataPointer { get; }
        public ulong GuardEhContinuationTable { get; }
        public ulong GuardEhContinuationCount { get; }
        public ulong GuardXfgCheckFunctionPointer { get; }
        public ulong GuardXfgDispatchFunctionPointer { get; }
        public ulong GuardXfgTableDispatchFunctionPointer { get; }
        public IReadOnlyList<GuardFeatureInfo> GuardFeatureMatrix { get; }

        public LoadConfigInfo(
            uint size,
            uint timeDateStamp,
            ushort majorVersion,
            ushort minorVersion,
            uint globalFlagsClear,
            uint globalFlagsSet,
            LoadConfigGlobalFlagsInfo globalFlagsInfo,
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
            ulong chpeMetadataPointer,
            ulong guardEhContinuationTable,
            ulong guardEhContinuationCount,
            ulong guardXfgCheckFunctionPointer,
            ulong guardXfgDispatchFunctionPointer,
            ulong guardXfgTableDispatchFunctionPointer,
            GuardFeatureInfo[] guardFeatureMatrix)
        {
            Size = size;
            TimeDateStamp = timeDateStamp;
            MajorVersion = majorVersion;
            MinorVersion = minorVersion;
            GlobalFlagsClear = globalFlagsClear;
            GlobalFlagsSet = globalFlagsSet;
            GlobalFlagsInfo = globalFlagsInfo;
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
            ChpeMetadataPointer = chpeMetadataPointer;
            GuardEhContinuationTable = guardEhContinuationTable;
            GuardEhContinuationCount = guardEhContinuationCount;
            GuardXfgCheckFunctionPointer = guardXfgCheckFunctionPointer;
            GuardXfgDispatchFunctionPointer = guardXfgDispatchFunctionPointer;
            GuardXfgTableDispatchFunctionPointer = guardXfgTableDispatchFunctionPointer;
            GuardFeatureMatrix = Array.AsReadOnly(guardFeatureMatrix ?? Array.Empty<GuardFeatureInfo>());
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
        public IReadOnlyDictionary<string, string> StringValues { get; }
        public IReadOnlyList<VersionStringTableInfo> StringTables { get; }
        public uint? Translation { get; }
        public IReadOnlyList<VersionTranslationInfo> Translations { get; }
        public string TranslationText { get; }

        public VersionInfoDetails(
            VersionFixedFileInfo fixedFileInfo,
            IReadOnlyDictionary<string, string> stringValues,
            VersionStringTableInfo[] stringTables,
            uint? translation,
            VersionTranslationInfo[] translations,
            string translationText)
        {
            FixedFileInfo = fixedFileInfo;
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
        public IReadOnlyList<IconEntryInfo> Entries { get; }
        public byte[] IcoData { get; }

        public IconGroupInfo(uint nameId, ushort languageId, IconEntryInfo[] entries, byte[] icoData)
        {
            NameId = nameId;
            LanguageId = languageId;
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

    public sealed class AuthenticodeStatusInfo
    {
        public int SignerCount { get; }
        public int TimestampSignerCount { get; }
        public bool HasSignature { get; }
        public bool SignatureValid { get; }
        public bool ChainValid { get; }
        public bool HasTimestamp { get; }
        public bool TimestampValid { get; }
        public IReadOnlyList<string> ChainStatus { get; }
        public IReadOnlyList<string> TimestampChainStatus { get; }
        public bool PolicyCompliant { get; }
        public IReadOnlyList<string> PolicyFailures { get; }

        public AuthenticodeStatusInfo(
            int signerCount,
            int timestampSignerCount,
            bool hasSignature,
            bool signatureValid,
            bool chainValid,
            bool hasTimestamp,
            bool timestampValid,
            string[] chainStatus,
            string[] timestampChainStatus,
            bool policyCompliant,
            string[] policyFailures)
        {
            SignerCount = signerCount;
            TimestampSignerCount = timestampSignerCount;
            HasSignature = hasSignature;
            SignatureValid = signatureValid;
            ChainValid = chainValid;
            HasTimestamp = hasTimestamp;
            TimestampValid = timestampValid;
            ChainStatus = Array.AsReadOnly(chainStatus ?? Array.Empty<string>());
            TimestampChainStatus = Array.AsReadOnly(timestampChainStatus ?? Array.Empty<string>());
            PolicyCompliant = policyCompliant;
            PolicyFailures = Array.AsReadOnly(policyFailures ?? Array.Empty<string>());
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

        public ExportAnomalySummary(int duplicateNameCount, int duplicateOrdinalCount, int ordinalOutOfRangeCount)
        {
            DuplicateNameCount = duplicateNameCount;
            DuplicateOrdinalCount = duplicateOrdinalCount;
            OrdinalOutOfRangeCount = ordinalOutOfRangeCount;
        }
    }

    public sealed class MetadataTableCountInfo
    {
        public int TableIndex { get; }
        public string TableName { get; }
        public int Count { get; }

        public MetadataTableCountInfo(int tableIndex, string tableName, int count)
        {
            TableIndex = tableIndex;
            TableName = tableName ?? string.Empty;
            Count = count;
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

        public MessageTableEntryInfo(uint id, string text, bool isUnicode)
        {
            Id = id;
            Text = text ?? string.Empty;
            IsUnicode = isUnicode;
        }
    }

    public sealed class ResourceMessageTableInfo
    {
        public uint NameId { get; }
        public ushort LanguageId { get; }
        public IReadOnlyList<MessageTableEntryInfo> Entries { get; }

        public ResourceMessageTableInfo(uint nameId, ushort languageId, MessageTableEntryInfo[] entries)
        {
            NameId = nameId;
            LanguageId = languageId;
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
        public const int CurrentSchemaVersion = 7;

        public int SchemaVersion { get; }
        public string FilePath { get; }
        public ParseResultSnapshot ParseResult { get; }
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
        public OverlayInfo OverlayInfo { get; }
        public IReadOnlyList<PackingHintInfo> PackingHints { get; }
        public IReadOnlyList<SectionEntropyInfo> SectionEntropies { get; }
        public IReadOnlyList<SectionSlackInfo> SectionSlacks { get; }
        public IReadOnlyList<SectionGapInfo> SectionGaps { get; }
        public IReadOnlyList<SectionPermissionInfo> SectionPermissions { get; }
        public uint OptionalHeaderChecksum { get; }
        public uint ComputedChecksum { get; }
        public bool IsChecksumValid { get; }
        public uint TimeDateStamp { get; }
        public DateTimeOffset? TimeDateStampUtc { get; }
        public SubsystemInfo Subsystem { get; }
        public DllCharacteristicsInfo DllCharacteristics { get; }
        public SecurityFeaturesInfo SecurityFeatures { get; }
        public bool HasCertificate { get; }
        public byte[] Certificate { get; }
        public IReadOnlyList<byte[]> Certificates { get; }
        public IReadOnlyList<CertificateEntry> CertificateEntries { get; }
        public IReadOnlyList<ResourceEntry> Resources { get; }
        public IReadOnlyList<ResourceStringTableInfo> ResourceStringTables { get; }
        public IReadOnlyList<ResourceMessageTableInfo> ResourceMessageTables { get; }
        public IReadOnlyList<ResourceDialogInfo> ResourceDialogs { get; }
        public IReadOnlyList<ResourceAcceleratorTableInfo> ResourceAccelerators { get; }
        public IReadOnlyList<ResourceMenuInfo> ResourceMenus { get; }
        public IReadOnlyList<ResourceToolbarInfo> ResourceToolbars { get; }
        public IReadOnlyList<ResourceManifestInfo> ResourceManifests { get; }
        public IReadOnlyList<ResourceLocaleCoverageInfo> ResourceLocaleCoverage { get; }
        public IReadOnlyList<ResourceBitmapInfo> ResourceBitmaps { get; }
        public IReadOnlyList<ResourceCursorGroupInfo> ResourceCursorGroups { get; }
        public IReadOnlyList<IconGroupInfo> IconGroups { get; }
        public ClrMetadataInfo ClrMetadata { get; }
        public StrongNameSignatureInfo StrongNameSignature { get; }
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
        public RichHeaderInfo RichHeader { get; }
        public TlsInfo TlsInfo { get; }
        public LoadConfigInfo LoadConfig { get; }
        public IReadOnlyList<string> AssemblyReferences { get; }
        public IReadOnlyList<AssemblyReferenceInfo> AssemblyReferenceInfos { get; }

        internal PECOFFResult(
            string filePath,
            ParseResultSnapshot parseResult,
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
            OverlayInfo overlayInfo,
            PackingHintInfo[] packingHints,
            SectionEntropyInfo[] sectionEntropies,
            SectionSlackInfo[] sectionSlacks,
            SectionGapInfo[] sectionGaps,
            SectionPermissionInfo[] sectionPermissions,
            uint optionalHeaderChecksum,
            uint computedChecksum,
            bool isChecksumValid,
            uint timeDateStamp,
            DateTimeOffset? timeDateStampUtc,
            SubsystemInfo subsystem,
            DllCharacteristicsInfo dllCharacteristics,
            SecurityFeaturesInfo securityFeatures,
            bool hasCertificate,
            byte[] certificate,
            byte[][] certificates,
            CertificateEntry[] certificateEntries,
            ResourceEntry[] resources,
            ResourceStringTableInfo[] resourceStringTables,
            ResourceMessageTableInfo[] resourceMessageTables,
            ResourceDialogInfo[] resourceDialogs,
            ResourceAcceleratorTableInfo[] resourceAccelerators,
            ResourceMenuInfo[] resourceMenus,
            ResourceToolbarInfo[] resourceToolbars,
            ResourceManifestInfo[] resourceManifests,
            ResourceLocaleCoverageInfo[] resourceLocaleCoverage,
            ResourceBitmapInfo[] resourceBitmaps,
            ResourceCursorGroupInfo[] resourceCursorGroups,
            IconGroupInfo[] iconGroups,
            ClrMetadataInfo clrMetadata,
            StrongNameSignatureInfo strongNameSignature,
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
            RichHeaderInfo richHeader,
            TlsInfo tlsInfo,
            LoadConfigInfo loadConfig,
            string[] assemblyReferences,
            AssemblyReferenceInfo[] assemblyReferenceInfos)
        {
            SchemaVersion = CurrentSchemaVersion;
            FilePath = filePath ?? string.Empty;
            ParseResult = parseResult ?? new ParseResultSnapshot(Array.Empty<string>(), Array.Empty<string>(), Array.Empty<ParseIssue>());
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
            OverlayInfo = overlayInfo ?? new OverlayInfo(0, 0);
            PackingHints = Array.AsReadOnly(packingHints ?? Array.Empty<PackingHintInfo>());
            SectionEntropies = Array.AsReadOnly(sectionEntropies ?? Array.Empty<SectionEntropyInfo>());
            SectionSlacks = Array.AsReadOnly(sectionSlacks ?? Array.Empty<SectionSlackInfo>());
            SectionGaps = Array.AsReadOnly(sectionGaps ?? Array.Empty<SectionGapInfo>());
            SectionPermissions = Array.AsReadOnly(sectionPermissions ?? Array.Empty<SectionPermissionInfo>());
            OptionalHeaderChecksum = optionalHeaderChecksum;
            ComputedChecksum = computedChecksum;
            IsChecksumValid = isChecksumValid;
            TimeDateStamp = timeDateStamp;
            TimeDateStampUtc = timeDateStampUtc;
            Subsystem = subsystem;
            DllCharacteristics = dllCharacteristics;
            SecurityFeatures = securityFeatures;
            HasCertificate = hasCertificate;
            Certificate = certificate ?? Array.Empty<byte>();
            Certificates = Array.AsReadOnly(certificates ?? Array.Empty<byte[]>());
            CertificateEntries = Array.AsReadOnly(certificateEntries ?? Array.Empty<CertificateEntry>());
            Resources = Array.AsReadOnly(resources ?? Array.Empty<ResourceEntry>());
            ResourceStringTables = Array.AsReadOnly(resourceStringTables ?? Array.Empty<ResourceStringTableInfo>());
            ResourceMessageTables = Array.AsReadOnly(resourceMessageTables ?? Array.Empty<ResourceMessageTableInfo>());
            ResourceDialogs = Array.AsReadOnly(resourceDialogs ?? Array.Empty<ResourceDialogInfo>());
            ResourceAccelerators = Array.AsReadOnly(resourceAccelerators ?? Array.Empty<ResourceAcceleratorTableInfo>());
            ResourceMenus = Array.AsReadOnly(resourceMenus ?? Array.Empty<ResourceMenuInfo>());
            ResourceToolbars = Array.AsReadOnly(resourceToolbars ?? Array.Empty<ResourceToolbarInfo>());
            ResourceManifests = Array.AsReadOnly(resourceManifests ?? Array.Empty<ResourceManifestInfo>());
            ResourceLocaleCoverage = Array.AsReadOnly(resourceLocaleCoverage ?? Array.Empty<ResourceLocaleCoverageInfo>());
            ResourceBitmaps = Array.AsReadOnly(resourceBitmaps ?? Array.Empty<ResourceBitmapInfo>());
            ResourceCursorGroups = Array.AsReadOnly(resourceCursorGroups ?? Array.Empty<ResourceCursorGroupInfo>());
            IconGroups = Array.AsReadOnly(iconGroups ?? Array.Empty<IconGroupInfo>());
            ClrMetadata = clrMetadata;
            StrongNameSignature = strongNameSignature;
            ReadyToRun = readyToRun;
            Imports = Array.AsReadOnly(imports ?? Array.Empty<string>());
            ImportEntries = Array.AsReadOnly(importEntries ?? Array.Empty<ImportEntry>());
            ImportDescriptors = Array.AsReadOnly(importDescriptors ?? Array.Empty<ImportDescriptorInfo>());
            DelayImportEntries = Array.AsReadOnly(delayImportEntries ?? Array.Empty<ImportEntry>());
            DelayImportDescriptors = Array.AsReadOnly(delayImportDescriptors ?? Array.Empty<DelayImportDescriptorInfo>());
            Exports = Array.AsReadOnly(exports ?? Array.Empty<string>());
            ExportEntries = Array.AsReadOnly(exportEntries ?? Array.Empty<ExportEntry>());
            ExportAnomalies = exportAnomalies ?? new ExportAnomalySummary(0, 0, 0);
            BoundImports = Array.AsReadOnly(boundImports ?? Array.Empty<BoundImportEntry>());
            DebugDirectories = Array.AsReadOnly(debugDirectories ?? Array.Empty<DebugDirectoryEntry>());
            BaseRelocations = Array.AsReadOnly(baseRelocations ?? Array.Empty<BaseRelocationBlockInfo>());
            BaseRelocationSections = Array.AsReadOnly(baseRelocationSections ?? Array.Empty<BaseRelocationSectionSummary>());
            RelocationAnomalies = relocationAnomalies ?? new RelocationAnomalySummary(0, 0, 0, 0);
            ApiSetSchema = apiSetSchema ?? new ApiSetSchemaInfo(false, 0, string.Empty, string.Empty);
            ExceptionFunctions = Array.AsReadOnly(exceptionFunctions ?? Array.Empty<ExceptionFunctionInfo>());
            ExceptionSummary = exceptionSummary;
            UnwindInfoDetails = Array.AsReadOnly(unwindInfoDetails ?? Array.Empty<UnwindInfoDetail>());
            RichHeader = richHeader;
            TlsInfo = tlsInfo;
            LoadConfig = loadConfig;
            AssemblyReferences = Array.AsReadOnly(assemblyReferences ?? Array.Empty<string>());
            AssemblyReferenceInfos = Array.AsReadOnly(assemblyReferenceInfos ?? Array.Empty<AssemblyReferenceInfo>());
        }

        public string ToJsonReport(bool includeBinary = false, bool indented = true, bool stableOrdering = true)
        {
            JsonSerializerOptions options = new JsonSerializerOptions { WriteIndented = indented };
            object certificateEntries = includeBinary
                ? (object)CertificateEntries
                : CertificateEntries.Select(entry => new
                {
                    entry.Type,
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
            ResourceLocaleCoverageInfo[] resourceCoverage = stableOrdering
                ? ResourceLocaleCoverage.OrderBy(info => info.ResourceKind, StringComparer.OrdinalIgnoreCase).ToArray()
                : ResourceLocaleCoverage.ToArray();

            var report = new
            {
                SchemaVersion,
                FilePath,
                ParseResult,
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
                PackingHints = packingHints,
                SectionEntropies = entropies,
                SectionSlacks = slacks,
                SectionGaps = gaps,
                SectionPermissions = permissions,
                OptionalHeaderChecksum,
                ComputedChecksum,
                IsChecksumValid,
                TimeDateStamp,
                TimeDateStampUtc,
                Subsystem,
                DllCharacteristics,
                SecurityFeatures,
                HasCertificate,
                CertificateEntries = certificateEntries,
                Resources,
                ResourceStringTables,
                ResourceMessageTables,
                ResourceDialogs,
                ResourceAccelerators,
                ResourceMenus,
                ResourceToolbars,
                ResourceManifests,
                ResourceLocaleCoverage = resourceCoverage,
                ResourceBitmaps,
                ResourceCursorGroups,
                IconGroups = iconGroups,
                ClrMetadata,
                StrongNameSignature = strongNameSignature,
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
                RichHeader,
                TlsInfo,
                LoadConfig,
                AssemblyReferences = assemblyRefs,
                AssemblyReferenceInfos
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
        public IReadOnlyList<ResourceCursorEntryInfo> Entries { get; }

        public ResourceCursorGroupInfo(uint nameId, ushort languageId, ResourceCursorEntryInfo[] entries)
        {
            NameId = nameId;
            LanguageId = languageId;
            Entries = Array.AsReadOnly(entries ?? Array.Empty<ResourceCursorEntryInfo>());
        }
    }
}
