using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

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
        public bool EnableAssemblyAnalysis { get; init; } = true;
        public bool ComputeHash { get; init; } = true;
        public bool ComputeImportHash { get; init; } = true;
        public bool ComputeChecksum { get; init; } = true;
        public bool ComputeSectionEntropy { get; init; } = true;
        public bool ParseCertificateSigners { get; init; } = true;
        public bool ComputeAuthenticode { get; init; } = true;
        public bool UseMemoryMappedFile { get; init; }
        public Dictionary<ParseIssueCategory, ParseIssueSeverity> IssuePolicy { get; init; } = new Dictionary<ParseIssueCategory, ParseIssueSeverity>();
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
        public uint PdbSignature { get; }
        public uint PdbTimeDateStamp { get; }
        public bool HasPdbTimeDateStamp { get; }
        public bool TimeDateStampMatches { get; }

        public DebugCodeViewInfo(
            string signature,
            Guid guid,
            uint age,
            string pdbPath,
            uint pdbSignature,
            uint pdbTimeDateStamp,
            bool hasPdbTimeDateStamp,
            bool timeDateStampMatches)
        {
            Signature = signature ?? string.Empty;
            Guid = guid;
            Age = age;
            PdbPath = pdbPath ?? string.Empty;
            PdbSignature = pdbSignature;
            PdbTimeDateStamp = pdbTimeDateStamp;
            HasPdbTimeDateStamp = hasPdbTimeDateStamp;
            TimeDateStampMatches = timeDateStampMatches;
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

        public RichHeaderEntry(ushort productId, ushort buildNumber, uint count, uint rawCompId)
        {
            ProductId = productId;
            BuildNumber = buildNumber;
            Count = count;
            RawCompId = rawCompId;
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

    public sealed class BaseRelocationBlockInfo
    {
        public uint PageRva { get; }
        public uint BlockSize { get; }
        public int EntryCount { get; }
        public IReadOnlyList<int> TypeCounts { get; }

        public BaseRelocationBlockInfo(uint pageRva, uint blockSize, int entryCount, int[] typeCounts)
        {
            PageRva = pageRva;
            BlockSize = blockSize;
            EntryCount = entryCount;
            TypeCounts = typeCounts ?? Array.Empty<int>();
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

        public TlsInfo(
            ulong startAddressOfRawData,
            ulong endAddressOfRawData,
            ulong addressOfIndex,
            ulong addressOfCallbacks,
            uint sizeOfZeroFill,
            uint characteristics,
            ulong[] callbackAddresses)
        {
            StartAddressOfRawData = startAddressOfRawData;
            EndAddressOfRawData = endAddressOfRawData;
            AddressOfIndex = addressOfIndex;
            AddressOfCallbacks = addressOfCallbacks;
            SizeOfZeroFill = sizeOfZeroFill;
            Characteristics = characteristics;
            CallbackAddresses = Array.AsReadOnly(callbackAddresses ?? Array.Empty<ulong>());
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

        public LoadConfigInfo(
            uint size,
            uint timeDateStamp,
            ushort majorVersion,
            ushort minorVersion,
            uint globalFlagsClear,
            uint globalFlagsSet,
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
            uint guardFlags)
        {
            Size = size;
            TimeDateStamp = timeDateStamp;
            MajorVersion = majorVersion;
            MinorVersion = minorVersion;
            GlobalFlagsClear = globalFlagsClear;
            GlobalFlagsSet = globalFlagsSet;
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
        }
    }

    public sealed class VersionFixedFileInfo
    {
        public string FileVersion { get; }
        public string ProductVersion { get; }
        public uint FileFlagsMask { get; }
        public uint FileFlags { get; }
        public uint FileOs { get; }
        public uint FileType { get; }
        public uint FileSubtype { get; }
        public uint FileDateMs { get; }
        public uint FileDateLs { get; }

        public VersionFixedFileInfo(
            string fileVersion,
            string productVersion,
            uint fileFlagsMask,
            uint fileFlags,
            uint fileOs,
            uint fileType,
            uint fileSubtype,
            uint fileDateMs,
            uint fileDateLs)
        {
            FileVersion = fileVersion ?? string.Empty;
            ProductVersion = productVersion ?? string.Empty;
            FileFlagsMask = fileFlagsMask;
            FileFlags = fileFlags;
            FileOs = fileOs;
            FileType = fileType;
            FileSubtype = fileSubtype;
            FileDateMs = fileDateMs;
            FileDateLs = fileDateLs;
        }
    }

    public sealed class VersionInfoDetails
    {
        public VersionFixedFileInfo FixedFileInfo { get; }
        public IReadOnlyDictionary<string, string> StringValues { get; }
        public uint? Translation { get; }
        public string TranslationText { get; }

        public VersionInfoDetails(
            VersionFixedFileInfo fixedFileInfo,
            IReadOnlyDictionary<string, string> stringValues,
            uint? translation,
            string translationText)
        {
            FixedFileInfo = fixedFileInfo;
            StringValues = stringValues ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            Translation = translation;
            TranslationText = translationText ?? string.Empty;
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

        public IconEntryInfo(byte width, byte height, byte colorCount, byte reserved, ushort planes, ushort bitCount, uint bytesInRes, ushort resourceId)
        {
            Width = width;
            Height = height;
            ColorCount = colorCount;
            Reserved = reserved;
            Planes = planes;
            BitCount = bitCount;
            BytesInRes = bytesInRes;
            ResourceId = resourceId;
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
        public IReadOnlyList<ReadyToRunSectionInfo> Sections { get; }

        public ReadyToRunInfo(
            uint signature,
            string signatureText,
            ushort majorVersion,
            ushort minorVersion,
            uint flags,
            ReadyToRunSectionInfo[] sections)
        {
            Signature = signature;
            SignatureText = signatureText ?? string.Empty;
            MajorVersion = majorVersion;
            MinorVersion = minorVersion;
            Flags = flags;
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

    public sealed class ManifestSchemaInfo
    {
        public string RootElement { get; }
        public string Namespace { get; }
        public string ManifestVersion { get; }
        public string AssemblyIdentityName { get; }
        public string AssemblyIdentityVersion { get; }
        public string AssemblyIdentityArchitecture { get; }
        public string AssemblyIdentityType { get; }
        public string UiAccess { get; }

        public ManifestSchemaInfo(
            string rootElement,
            string schemaNamespace,
            string manifestVersion,
            string assemblyIdentityName,
            string assemblyIdentityVersion,
            string assemblyIdentityArchitecture,
            string assemblyIdentityType,
            string uiAccess)
        {
            RootElement = rootElement ?? string.Empty;
            Namespace = schemaNamespace ?? string.Empty;
            ManifestVersion = manifestVersion ?? string.Empty;
            AssemblyIdentityName = assemblyIdentityName ?? string.Empty;
            AssemblyIdentityVersion = assemblyIdentityVersion ?? string.Empty;
            AssemblyIdentityArchitecture = assemblyIdentityArchitecture ?? string.Empty;
            AssemblyIdentityType = assemblyIdentityType ?? string.Empty;
            UiAccess = uiAccess ?? string.Empty;
        }
    }

    public sealed class PECOFFResult
    {
        public string FilePath { get; }
        public ParseResultSnapshot ParseResult { get; }
        public string Hash { get; }
        public string ImportHash { get; }
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
        public VersionInfoDetails VersionInfoDetails { get; }
        public uint FileAlignment { get; }
        public uint SectionAlignment { get; }
        public uint SizeOfHeaders { get; }
        public OverlayInfo OverlayInfo { get; }
        public IReadOnlyList<SectionEntropyInfo> SectionEntropies { get; }
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
        public IReadOnlyList<ResourceManifestInfo> ResourceManifests { get; }
        public IReadOnlyList<IconGroupInfo> IconGroups { get; }
        public ClrMetadataInfo ClrMetadata { get; }
        public StrongNameSignatureInfo StrongNameSignature { get; }
        public ReadyToRunInfo ReadyToRun { get; }
        public IReadOnlyList<string> Imports { get; }
        public IReadOnlyList<ImportEntry> ImportEntries { get; }
        public IReadOnlyList<ImportEntry> DelayImportEntries { get; }
        public IReadOnlyList<DelayImportDescriptorInfo> DelayImportDescriptors { get; }
        public IReadOnlyList<string> Exports { get; }
        public IReadOnlyList<ExportEntry> ExportEntries { get; }
        public IReadOnlyList<BoundImportEntry> BoundImports { get; }
        public IReadOnlyList<DebugDirectoryEntry> DebugDirectories { get; }
        public IReadOnlyList<BaseRelocationBlockInfo> BaseRelocations { get; }
        public IReadOnlyList<ExceptionFunctionInfo> ExceptionFunctions { get; }
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
            SectionEntropyInfo[] sectionEntropies,
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
            ResourceManifestInfo[] resourceManifests,
            IconGroupInfo[] iconGroups,
            ClrMetadataInfo clrMetadata,
            StrongNameSignatureInfo strongNameSignature,
            ReadyToRunInfo readyToRun,
            string[] imports,
            ImportEntry[] importEntries,
            ImportEntry[] delayImportEntries,
            DelayImportDescriptorInfo[] delayImportDescriptors,
            string[] exports,
            ExportEntry[] exportEntries,
            BoundImportEntry[] boundImports,
            DebugDirectoryEntry[] debugDirectories,
            BaseRelocationBlockInfo[] baseRelocations,
            ExceptionFunctionInfo[] exceptionFunctions,
            RichHeaderInfo richHeader,
            TlsInfo tlsInfo,
            LoadConfigInfo loadConfig,
            string[] assemblyReferences,
            AssemblyReferenceInfo[] assemblyReferenceInfos)
        {
            FilePath = filePath ?? string.Empty;
            ParseResult = parseResult ?? new ParseResultSnapshot(Array.Empty<string>(), Array.Empty<string>(), Array.Empty<ParseIssue>());
            Hash = hash ?? string.Empty;
            ImportHash = importHash ?? string.Empty;
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
            VersionInfoDetails = versionInfoDetails;
            FileAlignment = fileAlignment;
            SectionAlignment = sectionAlignment;
            SizeOfHeaders = sizeOfHeaders;
            OverlayInfo = overlayInfo ?? new OverlayInfo(0, 0);
            SectionEntropies = Array.AsReadOnly(sectionEntropies ?? Array.Empty<SectionEntropyInfo>());
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
            ResourceManifests = Array.AsReadOnly(resourceManifests ?? Array.Empty<ResourceManifestInfo>());
            IconGroups = Array.AsReadOnly(iconGroups ?? Array.Empty<IconGroupInfo>());
            ClrMetadata = clrMetadata;
            StrongNameSignature = strongNameSignature;
            ReadyToRun = readyToRun;
            Imports = Array.AsReadOnly(imports ?? Array.Empty<string>());
            ImportEntries = Array.AsReadOnly(importEntries ?? Array.Empty<ImportEntry>());
            DelayImportEntries = Array.AsReadOnly(delayImportEntries ?? Array.Empty<ImportEntry>());
            DelayImportDescriptors = Array.AsReadOnly(delayImportDescriptors ?? Array.Empty<DelayImportDescriptorInfo>());
            Exports = Array.AsReadOnly(exports ?? Array.Empty<string>());
            ExportEntries = Array.AsReadOnly(exportEntries ?? Array.Empty<ExportEntry>());
            BoundImports = Array.AsReadOnly(boundImports ?? Array.Empty<BoundImportEntry>());
            DebugDirectories = Array.AsReadOnly(debugDirectories ?? Array.Empty<DebugDirectoryEntry>());
            BaseRelocations = Array.AsReadOnly(baseRelocations ?? Array.Empty<BaseRelocationBlockInfo>());
            ExceptionFunctions = Array.AsReadOnly(exceptionFunctions ?? Array.Empty<ExceptionFunctionInfo>());
            RichHeader = richHeader;
            TlsInfo = tlsInfo;
            LoadConfig = loadConfig;
            AssemblyReferences = Array.AsReadOnly(assemblyReferences ?? Array.Empty<string>());
            AssemblyReferenceInfos = Array.AsReadOnly(assemblyReferenceInfos ?? Array.Empty<AssemblyReferenceInfo>());
        }
    }

    public sealed class ClrAssemblyReferenceInfo
    {
        public string Name { get; }
        public string Version { get; }
        public string Culture { get; }
        public string PublicKeyOrToken { get; }
        public int Token { get; }
        public int RowId { get; }
        public string FullName { get; }

        public ClrAssemblyReferenceInfo(
            string name,
            string version,
            string culture,
            string publicKeyOrToken,
            int token,
            int rowId,
            string fullName)
        {
            Name = name ?? string.Empty;
            Version = version ?? string.Empty;
            Culture = culture ?? string.Empty;
            PublicKeyOrToken = publicKeyOrToken ?? string.Empty;
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
}
