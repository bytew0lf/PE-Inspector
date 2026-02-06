using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.IO.MemoryMappedFiles;
using System.Xml.Linq;

using System.Security.Cryptography;

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

    public sealed class CertificateEntry
    {
        public CertificateTypeKind Type { get; }
        public byte[] Data { get; }
        public Pkcs7SignerInfo[] Pkcs7SignerInfos { get; }
        public string Pkcs7Error { get; }
        public AuthenticodeVerificationResult[] AuthenticodeResults { get; }

        public CertificateEntry(CertificateTypeKind type, byte[] data)
            : this(type, data, Array.Empty<Pkcs7SignerInfo>(), string.Empty, Array.Empty<AuthenticodeVerificationResult>())
        {
        }

        public CertificateEntry(
            CertificateTypeKind type,
            byte[] data,
            Pkcs7SignerInfo[] pkcs7SignerInfos,
            string pkcs7Error,
            AuthenticodeVerificationResult[] authenticodeResults)
        {
            Type = type;
            Data = data ?? Array.Empty<byte>();
            Pkcs7SignerInfos = pkcs7SignerInfos ?? Array.Empty<Pkcs7SignerInfo>();
            Pkcs7Error = pkcs7Error ?? string.Empty;
            AuthenticodeResults = authenticodeResults ?? Array.Empty<AuthenticodeVerificationResult>();
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

        public ExportEntry(string name, uint ordinal, uint addressRva, bool isForwarder, string forwarder)
        {
            Name = name ?? string.Empty;
            Ordinal = ordinal;
            AddressRva = addressRva;
            IsForwarder = isForwarder;
            Forwarder = forwarder ?? string.Empty;
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
            uint unloadInformationTableRva)
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
        public MetadataTableCountInfo[] MetadataTableCounts { get; }
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
            MetadataTableCountInfo[] metadataTableCounts,
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
            int eventDefinitionCount)
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
            MetadataTableCounts = metadataTableCounts ?? Array.Empty<MetadataTableCountInfo>();
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
        private readonly ParseResult _parseResult = new ParseResult();
        private readonly PECOFFOptions _options;
        private readonly string _filePath;

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

            if (!string.IsNullOrWhiteSpace(FileName) && File.Exists(FileName))
            {
                if (_options.UseMemoryMappedFile)
                {
                    _memoryMappedFile = MemoryMappedFile.CreateFromFile(FileName, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
                    _memoryMappedStream = _memoryMappedFile.CreateViewStream(0, 0, MemoryMappedFileAccess.Read);
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

            IMAGE_FILE_MACHINE_AM33 = 0x1d3,
            
            IMAGE_FILE_MACHINE_AMD64 = 0x8664, // x64

            IMAGE_FILE_MACHINE_ARM = 0x1c0,
            IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
            IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
            
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

            IMAGE_FILE_MACHINE_R3000 = 0x162,
            IMAGE_FILE_MACHINE_R4000 = 0x166,
            IMAGE_FILE_MACHINE_R10000 = 0x168,
            IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,
            
            IMAGE_FILE_MACHINE_SH3 = 0x1a2,
            IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
            IMAGE_FILE_MACHINE_SH4 = 0x1a6,
            IMAGE_FILE_MACHINE_SH5 = 0x1a8,
            IMAGE_FILE_MACHINE_THUMB = 0x1c2,
            

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
            IMAGE_SUBSYSTEM_XBOX = 14
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
            Version = 16,
            GroupIcon = 14,
            DlgInclude = 17,
            PlugAndPlay = 19,
            VXD = 20,
            AnimatedCursor = 21,
            AnimatedIcon = 22,
            HTML = 23,
            Manifest = 24
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
            public char[] Name;
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
                get { return Name == null ? string.Empty : new string(Name); }
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
                return _productversion;
            }
        }

        private string _fileversion;
        public string FileVersion
        {
            get
            {
                return _fileversion;
            }
        }

        private string _companyName;
        public string CompanyName
        {
            get { return _companyName; }
        }

        private string _fileDescription;
        public string FileDescription
        {
            get { return _fileDescription; }
        }

        private string _internalName;
        public string InternalName
        {
            get { return _internalName; }
        }

        private string _originalFilename;
        public string OriginalFilename
        {
            get { return _originalFilename; }
        }

        private string _productName;
        public string ProductName
        {
            get { return _productName; }
        }

        private string _comments;
        public string Comments
        {
            get { return _comments; }
        }

        private string _legalCopyright;
        public string LegalCopyright
        {
            get { return _legalCopyright; }
        }

        private string _legalTrademarks;
        public string LegalTrademarks
        {
            get { return _legalTrademarks; }
        }

        private string _privateBuild;
        public string PrivateBuild
        {
            get { return _privateBuild; }
        }

        private string _specialBuild;
        public string SpecialBuild
        {
            get { return _specialBuild; }
        }

        private string _language;
        public string Language
        {
            get { return _language; }
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

        private uint _sectionAlignment;
        public uint SectionAlignment
        {
            get { return _sectionAlignment; }
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

        private readonly List<SectionEntropyInfo> _sectionEntropies = new List<SectionEntropyInfo>();
        public SectionEntropyInfo[] SectionEntropies
        {
            get { return _sectionEntropies.ToArray(); }
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
            get { return _securityFeaturesInfo; }
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
            get { return _resources.ToArray(); }
        }

        private readonly List<ResourceStringTableInfo> _resourceStringTables = new List<ResourceStringTableInfo>();
        public ResourceStringTableInfo[] ResourceStringTables
        {
            get { return _resourceStringTables.ToArray(); }
        }

        private readonly List<ResourceManifestInfo> _resourceManifests = new List<ResourceManifestInfo>();
        public ResourceManifestInfo[] ResourceManifests
        {
            get { return _resourceManifests.ToArray(); }
        }

        private readonly List<ResourceMessageTableInfo> _resourceMessageTables = new List<ResourceMessageTableInfo>();
        public ResourceMessageTableInfo[] ResourceMessageTables
        {
            get { return _resourceMessageTables.ToArray(); }
        }

        private readonly List<ResourceDialogInfo> _resourceDialogs = new List<ResourceDialogInfo>();
        public ResourceDialogInfo[] ResourceDialogs
        {
            get { return _resourceDialogs.ToArray(); }
        }

        private readonly List<ResourceAcceleratorTableInfo> _resourceAccelerators = new List<ResourceAcceleratorTableInfo>();
        public ResourceAcceleratorTableInfo[] ResourceAccelerators
        {
            get { return _resourceAccelerators.ToArray(); }
        }

        private readonly List<IconGroupInfo> _iconGroups = new List<IconGroupInfo>();
        public IconGroupInfo[] IconGroups
        {
            get { return _iconGroups.ToArray(); }
        }

        private VersionInfoDetails _versionInfoDetails;
        public VersionInfoDetails VersionInfoDetails
        {
            get { return _versionInfoDetails; }
        }

        private ClrMetadataInfo _clrMetadata;
        public ClrMetadataInfo ClrMetadata
        {
            get { return _clrMetadata; }
        }

        private StrongNameSignatureInfo _strongNameSignature;
        public StrongNameSignatureInfo StrongNameSignature
        {
            get { return _strongNameSignature; }
        }

        private ReadyToRunInfo _readyToRun;
        public ReadyToRunInfo ReadyToRun
        {
            get { return _readyToRun; }
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

        private readonly List<ExportEntry> _exportEntries = new List<ExportEntry>();
        public ExportEntry[] ExportEntries
        {
            get { return _exportEntries.ToArray(); }
        }

        private readonly List<BoundImportEntry> _boundImports = new List<BoundImportEntry>();
        public BoundImportEntry[] BoundImports
        {
            get { return _boundImports.ToArray(); }
        }

        private readonly List<DebugDirectoryEntry> _debugDirectories = new List<DebugDirectoryEntry>();
        public DebugDirectoryEntry[] DebugDirectories
        {
            get { return _debugDirectories.ToArray(); }
        }

        private readonly List<BaseRelocationBlockInfo> _baseRelocations = new List<BaseRelocationBlockInfo>();
        public BaseRelocationBlockInfo[] BaseRelocations
        {
            get { return _baseRelocations.ToArray(); }
        }

        private readonly List<ExceptionFunctionInfo> _exceptionFunctions = new List<ExceptionFunctionInfo>();
        public ExceptionFunctionInfo[] ExceptionFunctions
        {
            get { return _exceptionFunctions.ToArray(); }
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
            get { return _loadConfig; }
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
                uint sectionSize = Math.Max(section.VirtualSize, section.SizeOfRawData);
                if (sectionSize == 0)
                {
                    continue;
                }

                ulong sectionStart = section.VirtualAddress;
                ulong sectionEnd = sectionStart + sectionSize;
                ulong rva = directoryVA;
                if (rva >= sectionStart && rva < sectionEnd)
                {
                    fileOffset = (directoryVA - section.VirtualAddress) + section.PointerToRawData;
                    return fileOffset <= PEFileStream.Length;
                }
            }

            return false;
        }

        private static bool TryGetSectionByRva(List<IMAGE_SECTION_HEADER> sections, uint rva, out IMAGE_SECTION_HEADER result)
        {
            foreach (IMAGE_SECTION_HEADER section in sections)
            {
                uint sectionSize = Math.Max(section.VirtualSize, section.SizeOfRawData);
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

        public PECOFFResult ToResult()
        {
            return new PECOFFResult(
                _filePath,
                _parseResult.Snapshot(),
                _hash ?? string.Empty,
                _importHash ?? string.Empty,
                _isDotNetFile,
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
                _overlayInfo,
                _sectionEntropies.ToArray(),
                _optionalHeaderChecksum,
                _computedChecksum,
                IsChecksumValid,
                _timeDateStamp,
                TimeDateStampUtc,
                _subsystemInfo,
                _dllCharacteristicsInfo,
                _securityFeaturesInfo,
                HasCertificate,
                _certificate ?? Array.Empty<byte>(),
                _certificates.ToArray(),
                _certificateEntries.ToArray(),
                _resources.ToArray(),
                _resourceStringTables.ToArray(),
                _resourceMessageTables.ToArray(),
                _resourceDialogs.ToArray(),
                _resourceAccelerators.ToArray(),
                _resourceManifests.ToArray(),
                _iconGroups.ToArray(),
                _clrMetadata,
                _strongNameSignature,
                _readyToRun,
                imports.ToArray(),
                _importEntries.ToArray(),
                _delayImportEntries.ToArray(),
                _delayImportDescriptors.ToArray(),
                exports.ToArray(),
                _exportEntries.ToArray(),
                _boundImports.ToArray(),
                _debugDirectories.ToArray(),
                _baseRelocations.ToArray(),
                _exceptionFunctions.ToArray(),
                _richHeader,
                _tlsInfo,
                _loadConfig,
                _assemblyReferenceInfos.Select(r => r.Name).ToArray(),
                _assemblyReferenceInfos.ToArray());
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
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
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

            if (level > 2)
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
                        Warn(ParseIssueCategory.Resources, "Resource language entry points to a subdirectory.");
                        continue;
                    }

                    if (!TryReadResourceDataEntry(buffer, dataOffset, out uint dataRva, out uint size, out uint codePage))
                    {
                        Warn(ParseIssueCategory.Resources, "Resource data entry outside section bounds.");
                        continue;
                    }

                    long fileOffset = -1;
                    if (TryGetFileOffset(sections, dataRva, out long dataFileOffset))
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

            if (TryGetFileOffset(sections, dataRva, out long fileOffset) &&
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

            if (TryGetFileOffset(sections, dataRva, out long fileOffset) &&
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

                if (!TryParseMessageTable(dataSpan, out MessageTableEntryInfo[] entries))
                {
                    continue;
                }

                _resourceMessageTables.Add(new ResourceMessageTableInfo(entry.NameId, entry.LanguageId, entries));
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
                if (TryParseGroupIcon(entry, data, iconEntries, resourceBuffer, resourceBaseRva, sections, out IconGroupInfo group))
                {
                    _iconGroups.Add(group);
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
            out IconGroupInfo group)
        {
            group = null;
            if (groupData == null || groupData.Length < 6)
            {
                return false;
            }

            ushort reserved = ReadUInt16(groupData, 0);
            ushort type = ReadUInt16(groupData, 2);
            ushort count = ReadUInt16(groupData, 4);
            if (reserved != 0 || type != 1 || count == 0)
            {
                return false;
            }

            List<IconEntryInfo> entries = new List<IconEntryInfo>();
            List<byte[]> iconImages = new List<byte[]>();
            for (int i = 0; i < count; i++)
            {
                int offset = 6 + (i * 14);
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

                entries.Add(new IconEntryInfo(width, height, colorCount, reservedEntry, planes, bitCount, bytesInRes, resourceId));

                ResourceEntry iconEntry = iconEntries.FirstOrDefault(r => r.NameId == resourceId);
                if (iconEntry != null &&
                    TryGetResourceDataSpan(resourceBuffer, resourceBaseRva, iconEntry.DataRva, iconEntry.Size, sections, out ReadOnlySpan<byte> iconSpan, out byte[] iconOwned))
                {
                    iconImages.Add(iconOwned.Length > 0 ? iconOwned : iconSpan.ToArray());
                }
                else
                {
                    iconImages.Add(Array.Empty<byte>());
                }
            }

            byte[] icoData = BuildIconFile(entries, iconImages);
            group = new IconGroupInfo(entry.NameId, entry.LanguageId, entries.ToArray(), icoData);
            return true;
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

        private static bool TryParseMessageTable(ReadOnlySpan<byte> data, out MessageTableEntryInfo[] entries)
        {
            entries = Array.Empty<MessageTableEntryInfo>();
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
                    results.Add(new MessageTableEntryInfo(id, text, isUnicode));

                    cursor += entryLength;
                    id++;
                }
            }

            if (results.Count == 0)
            {
                return false;
            }

            entries = results.ToArray();
            return true;
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

                XElement requestedExecutionLevel = FindFirstElement(root, "requestedExecutionLevel");
                string uiAccess = requestedExecutionLevel?.Attribute("uiAccess")?.Value ?? string.Empty;

                schema = new ManifestSchemaInfo(
                    rootElement,
                    ns,
                    manifestVersion,
                    identityName,
                    identityVersion,
                    identityArch,
                    identityType,
                    uiAccess);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
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
                entries.Add(new RichHeaderEntry(product, build, count, compid));
            }

            info = new RichHeaderInfo(key, entries.ToArray());
            return true;
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
                if (section.SizeOfRawData == 0)
                {
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

                uint virtualSize = Math.Max(section.VirtualSize, section.SizeOfRawData);
                uint virtualEnd = section.VirtualAddress + AlignUp(virtualSize, sectionAlignment == 0 ? 1u : sectionAlignment);
                if (virtualEnd > maxVirtualEnd)
                {
                    maxVirtualEnd = virtualEnd;
                }

                if ((section.Characteristics & SectionCharacteristics.IMAGE_SCN_CNT_CODE) != 0)
                {
                    sumCode += section.SizeOfRawData;
                }

                if ((section.Characteristics & SectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)
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
        }

        private bool TryReadImportByName(List<IMAGE_SECTION_HEADER> sections, uint nameRva, out ushort hint, out string name)
        {
            hint = 0;
            name = string.Empty;

            if (!TryGetFileOffset(sections, nameRva, out long fileOffset))
            {
                return false;
            }

            if (!TrySetPosition(fileOffset, 2))
            {
                return false;
            }

            hint = PEFile.ReadUInt16();
            if (!TryReadNullTerminatedString(fileOffset + 2, out string importName))
            {
                return false;
            }

            name = importName;
            return true;
        }

        private void ParseImportThunks(
            string dllName,
            uint thunkTableRva,
            ImportThunkSource source,
            List<IMAGE_SECTION_HEADER> sections,
            bool isPe32Plus,
            List<ImportEntry> targetList)
        {
            if (thunkTableRva == 0)
            {
                return;
            }

            if (!TryGetFileOffset(sections, thunkTableRva, out long thunkOffset))
            {
                Warn(ParseIssueCategory.Imports, "Import thunk RVA not mapped to a section.");
                return;
            }

            int thunkSize = isPe32Plus ? 8 : 4;
            int maxIterations = 65536;
            bool terminated = false;
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
                    terminated = true;
                    break;
                }

                ulong entryRva = (ulong)thunkTableRva + (ulong)(index * thunkSize);
                if (entryRva > uint.MaxValue)
                {
                    Warn(ParseIssueCategory.Imports, "Import thunk RVA exceeds supported limits.");
                    break;
                }

                bool isOrdinal = isPe32Plus
                    ? (value & 0x8000000000000000UL) != 0
                    : (value & 0x80000000UL) != 0;

                if (isOrdinal)
                {
                    ushort ordinal = (ushort)(value & 0xFFFF);
                    uint thunkEntryRva = (uint)entryRva;
                    targetList.Add(new ImportEntry(dllName, string.Empty, 0, ordinal, true, source, thunkEntryRva));
                    continue;
                }

                uint nameRva = (uint)value;
                if (TryReadImportByName(sections, nameRva, out ushort hint, out string importName))
                {
                    uint thunkEntryRva = (uint)entryRva;
                    targetList.Add(new ImportEntry(dllName, importName, hint, 0, false, source, thunkEntryRva));
                }
                else if (source == ImportThunkSource.ImportNameTable)
                {
                    Warn(ParseIssueCategory.Imports, "Import name entry could not be read.");
                }
            }

            if (!terminated)
            {
                Warn(ParseIssueCategory.Imports, $"Import thunk list for {dllName} did not terminate.");
            }
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
                    unloadInformationTableRva));

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
                    break;
                }

                long blockEnd = cursor + header.SizeOfBlock;
                if (blockEnd > end)
                {
                    Warn(ParseIssueCategory.Relocations, "Base relocation block exceeds table size.");
                    break;
                }

                int entryCount = (int)((header.SizeOfBlock - headerSize) / 2);
                int[] typeCounts = new int[16];
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
                }

                _baseRelocations.Add(new BaseRelocationBlockInfo(header.VirtualAddress, header.SizeOfBlock, entryCount, typeCounts));
                cursor = blockEnd;
            }
        }

        private void ParseExceptionDirectory(IMAGE_DATA_DIRECTORY directory, List<IMAGE_SECTION_HEADER> sections)
        {
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

            if (tableSize % 12 != 0)
            {
                Warn(ParseIssueCategory.Sections, "Exception directory size is not aligned to runtime function entries.");
            }

            int entryCount = tableSize / 12;
            for (int i = 0; i < entryCount; i++)
            {
                long entryOffset = tableOffset + (i * 12L);
                if (!TrySetPosition(entryOffset, 12))
                {
                    WarnAt(ParseIssueCategory.Sections, "Exception directory entry outside file bounds.", entryOffset);
                    break;
                }

                uint begin = PEFile.ReadUInt32();
                uint end = PEFile.ReadUInt32();
                uint unwind = PEFile.ReadUInt32();
                _exceptionFunctions.Add(new ExceptionFunctionInfo(begin, end, unwind));
            }
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
                        }
                    }
                }
                else if ((DebugDirectoryType)entry.Type == DebugDirectoryType.Coff)
                {
                    note = "COFF debug info (likely /Z7).";
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
                    note));
            }
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
                info = new DebugCodeViewInfo(signature, guid, age, path, 0, 0, false, false);
                return true;
            }

            if (string.Equals(signature, "NB10", StringComparison.Ordinal) && data.Length >= 16)
            {
                uint pdbSignature = ReadUInt32(span, 4);
                uint timeDateStamp = ReadUInt32(span, 8);
                uint age = ReadUInt32(span, 12);
                string path = ReadNullTerminatedAscii(span, 16, out int _);
                bool matches = timeDateStamp != 0 && timeDateStamp == debugTimeDateStamp;
                info = new DebugCodeViewInfo(signature, Guid.Empty, age, path, pdbSignature, timeDateStamp, true, matches);
                return true;
            }

            return false;
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

            ulong[] callbacks = Array.Empty<ulong>();
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

            _tlsInfo = new TlsInfo(
                startRaw,
                endRaw,
                indexAddr,
                callbacksAddr,
                zeroFill,
                characteristics,
                callbacks);
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

            _loadConfig = new LoadConfigInfo(
                size,
                timeDateStamp,
                major,
                minor,
                globalFlagsClear,
                globalFlagsSet,
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
                guardFlags);
        }

        private static ulong ReadPointer(ReadOnlySpan<byte> span, ref int offset, bool isPe32Plus)
        {
            ulong value = isPe32Plus ? ReadUInt64(span, offset) : ReadUInt32(span, offset);
            offset += isPe32Plus ? 8 : 4;
            return value;
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

            string assemblyName = string.Empty;
            string assemblyVersion = string.Empty;
            string mvid = string.Empty;
            string targetFramework = string.Empty;
            ClrAssemblyReferenceInfo[] assemblyReferences = Array.Empty<ClrAssemblyReferenceInfo>();
            MetadataTableCountInfo[] metadataTableCounts = Array.Empty<MetadataTableCountInfo>();
            int moduleCount = 0;
            int typeDefCount = 0;
            int typeRefCount = 0;
            int methodDefCount = 0;
            int fieldDefCount = 0;
            int propertyDefCount = 0;
            int eventDefCount = 0;
            TryParseMetadataDetails(
                buffer,
                length,
                out assemblyName,
                out assemblyVersion,
                out mvid,
                out targetFramework,
                out assemblyReferences,
                out metadataTableCounts,
                out moduleCount,
                out typeDefCount,
                out typeRefCount,
                out methodDefCount,
                out fieldDefCount,
                out propertyDefCount,
                out eventDefCount);

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
                metadataTableCounts,
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
                eventDefCount);

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
            _readyToRun = new ReadyToRunInfo(signature, signatureText, major, minor, flags, sectionsInfo.ToArray());
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

        private static bool TryParseMetadataDetails(
            byte[] metadata,
            int length,
            out string assemblyName,
            out string assemblyVersion,
            out string mvid,
            out string targetFramework,
            out ClrAssemblyReferenceInfo[] assemblyReferences,
            out MetadataTableCountInfo[] metadataTableCounts,
            out int moduleDefinitionCount,
            out int typeDefinitionCount,
            out int typeReferenceCount,
            out int methodDefinitionCount,
            out int fieldDefinitionCount,
            out int propertyDefinitionCount,
            out int eventDefinitionCount)
        {
            assemblyName = string.Empty;
            assemblyVersion = string.Empty;
            mvid = string.Empty;
            targetFramework = string.Empty;
            assemblyReferences = Array.Empty<ClrAssemblyReferenceInfo>();
            metadataTableCounts = Array.Empty<MetadataTableCountInfo>();
            moduleDefinitionCount = 0;
            typeDefinitionCount = 0;
            typeReferenceCount = 0;
            methodDefinitionCount = 0;
            fieldDefinitionCount = 0;
            propertyDefinitionCount = 0;
            eventDefinitionCount = 0;

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

                        foreach (AssemblyReferenceHandle handle in reader.AssemblyReferences)
                        {
                            AssemblyReference reference = reader.GetAssemblyReference(handle);
                            string name = reader.GetString(reference.Name);
                            string version = reference.Version.ToString();
                            string culture = reference.Culture.IsNil ? string.Empty : reader.GetString(reference.Culture);
                            string token = ToHex(reader.GetBlobBytes(reference.PublicKeyOrToken));
                            int rowId = MetadataTokens.GetRowNumber(handle);
                            int metadataToken = MetadataTokens.GetToken(handle);
                            string fullName = BuildAssemblyDisplayName(name, version, culture, token);

                            refs.Add(new ClrAssemblyReferenceInfo(name, version, culture, token, metadataToken, rowId, fullName));
                        }
                    }

                    assemblyReferences = refs.ToArray();
                    return true;
                }
            }
            catch (Exception)
            {
                return false;
            }
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

        private static MetadataTableCountInfo[] BuildMetadataTableCounts(MetadataReader reader)
        {
            List<MetadataTableCountInfo> counts = new List<MetadataTableCountInfo>();
            foreach (TableIndex table in Enum.GetValues(typeof(TableIndex)))
            {
                int count = reader.GetTableRowCount(table);
                if (count > 0)
                {
                    counts.Add(new MetadataTableCountInfo((int)table, table.ToString(), count));
                }
            }

            return counts.ToArray();
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
                }
            }
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

                if (_options.StrictMode && defaultSeverity == ParseIssueSeverity.Warning)
                {
                    return ParseIssueSeverity.Error;
                }
            }

            return defaultSeverity;
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
            if (severity == ParseIssueSeverity.Error && _options != null && _options.StrictMode)
            {
                throw new PECOFFParseException(message);
            }
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

        private void ReadPE()
        {
            try
            {
                _parseResult.Clear();
                _resources.Clear();
                _resourceStringTables.Clear();
                _resourceManifests.Clear();
                _resourceMessageTables.Clear();
                _resourceDialogs.Clear();
                _resourceAccelerators.Clear();
                _iconGroups.Clear();
                _versionInfoDetails = null;
                _sectionEntropies.Clear();
                _overlayInfo = new OverlayInfo(0, 0);
                _securityFeaturesInfo = null;
                imports.Clear();
                exports.Clear();
                _importEntries.Clear();
                _delayImportEntries.Clear();
                _delayImportDescriptors.Clear();
                _exportEntries.Clear();
                _boundImports.Clear();
                _debugDirectories.Clear();
                _baseRelocations.Clear();
                _exceptionFunctions.Clear();
                _richHeader = null;
                _tlsInfo = null;
                _loadConfig = null;
                _clrMetadata = null;
                _strongNameSignature = null;
                _fileAlignment = 0;
                _sectionAlignment = 0;
                _sizeOfImage = 0;
                _sizeOfCode = 0;
                _sizeOfInitializedData = 0;
                _numberOfRvaAndSizes = 0;
                _sizeOfHeaders = 0;
                _optionalHeaderChecksum = 0;
                _subsystemInfo = null;
                _dllCharacteristicsInfo = null;
                _importHash = string.Empty;
                _computedChecksum = 0;
                _checksumFieldOffset = 0;
                _certificateTableOffset = 0;
                _certificateTableSize = 0;
                _timeDateStamp = 0;
                _readyToRun = null;
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
                
                if (!TrySetPosition(0, Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))))
                {
                    Fail(ParseIssueCategory.File, "File too small for DOS header.");
                    return;
                }

                    IMAGE_DOS_HEADER header = new IMAGE_DOS_HEADER(PEFile);
                               
                    byte[] buffer = new byte[]{};
                
                    // Check the File header signature
                    if ((header.e_magic == MagicByteSignature.IMAGE_DOS_SIGNATURE) || (header.e_magic == MagicByteSignature.IMAGE_OS2_SIGNATURE) || (header.e_magic == MagicByteSignature.IMAGE_OS2_SIGNATURE_LE))
                    {
                        ParseRichHeader(header);
                        if (!TrySetPosition(header.e_lfanew, sizeof(uint) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))))
                        {
                            Fail(ParseIssueCategory.Header, "PE header offset is outside the file bounds.");
                            return;
                        }

                    // Set the position to the PE-Header
                    IMAGE_NT_HEADERS peHeader = new IMAGE_NT_HEADERS(PEFile);
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
                    _sizeOfImage = peHeader.SizeOfImage;
                    _sizeOfCode = peHeader.SizeOfCode;
                    _sizeOfInitializedData = peHeader.SizeOfInitializedData;
                    _numberOfRvaAndSizes = peHeader.NumberOfRvaAndSizes;
                    _sizeOfHeaders = peHeader.SizeOfHeaders;
                    _optionalHeaderChecksum = peHeader.CheckSum;
                    _subsystemInfo = BuildSubsystemInfo(peHeader.Subsystem);
                    _dllCharacteristicsInfo = BuildDllCharacteristicsInfo(peHeader.DllCharacteristics);

                    IMAGE_DATA_DIRECTORY[] dataDirectory = peHeader.DataDirectory ?? Array.Empty<IMAGE_DATA_DIRECTORY>();
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

                    bool hasClrDirectory = dataDirectory.Length > 14 && dataDirectory[14].Size > 0;
                    if (_options.EnableAssemblyAnalysis && hasClrDirectory && !string.IsNullOrWhiteSpace(_filePath))
                    {
                        try
                        {
                            AnalyzeAssembly analyzer = new AnalyzeAssembly(_filePath);
                            _obfuscationPercentage = analyzer.ObfuscationPercentage;
                            _isDotNetFile = analyzer.IsDotNetFile || hasClrDirectory;
                            _isObfuscated = analyzer.IsObfuscated;
                            _assemblyReferenceInfos = analyzer.AssemblyReferenceInfos.ToList();
                        }
                        catch (Exception ex)
                        {
                            Warn(ParseIssueCategory.AssemblyAnalysis, $"AnalyzeAssembly failed: {ex.Message}");
                            _obfuscationPercentage = 0.0;
                            _isDotNetFile = hasClrDirectory;
                            _isObfuscated = false;
                            _assemblyReferenceInfos.Clear();
                        }
                    }
                    else
                    {
                        _isDotNetFile = hasClrDirectory;
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

                    ValidateSections(header, peHeader, sections, dataDirectory);

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
                                                exportNamesByIndex[nameOrdinals[j]] = exportName;
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
                                        if (table.LookupTableVirtualAddress != 0)
                                        {
                                            ParseImportThunks(importName, table.LookupTableVirtualAddress, ImportThunkSource.ImportNameTable, sections, isPe32Plus, _importEntries);
                                        }

                                        if (table.ImportAddressTableRVA != 0 &&
                                            table.ImportAddressTableRVA != table.LookupTableVirtualAddress)
                                        {
                                            ParseImportThunks(importName, table.ImportAddressTableRVA, ImportThunkSource.ImportAddressTable, sections, isPe32Plus, _importEntries);
                                        }
                                    }
                                }
                                
                                break;
                            case 2:
                                // Resource Table                                
                                IMAGE_SECTION_HEADER resourceSection;
                                if (!TryGetSectionByRva(sections, dataDirectory[i].VirtualAddress, out resourceSection))
                                {
                                    resourceSection = sections.Find(
                                        p => p.Section.TrimEnd('\0').Equals(".rsrc", StringComparison.OrdinalIgnoreCase));
                                }

                                if (resourceSection.Name == null || !TryGetIntSize(resourceSection.SizeOfRawData, out int rsrcSize))
                                {
                                    Warn(ParseIssueCategory.Resources, "Resource section not found or invalid.");
                                    break;
                                }

                                if (!TrySetPosition(resourceSection.PointerToRawData, rsrcSize))
                                {
                                    Warn(ParseIssueCategory.Resources, "Resource section offset outside file bounds.");
                                    break;
                                }

                                byte[] resourceBuffer = ArrayPool<byte>.Shared.Rent(rsrcSize);
                                ReadOnlySpan<byte> resourceSpan;
                                try
                                {
                                    ReadExactly(PEFileStream, resourceBuffer, 0, rsrcSize);
                                    resourceSpan = new ReadOnlySpan<byte>(resourceBuffer, 0, rsrcSize);

                                    int rootOffset = 0;
                                    if (dataDirectory[i].VirtualAddress >= resourceSection.VirtualAddress)
                                    {
                                        uint delta = dataDirectory[i].VirtualAddress - resourceSection.VirtualAddress;
                                        if (delta <= int.MaxValue && delta < (uint)rsrcSize)
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

                                    ParseResourceDirectory(resourceSpan, rootOffset, 0, 0, string.Empty, 0, string.Empty, sections, new HashSet<int>());
                                    DecodeResourceStringTables(resourceSpan, resourceSection.VirtualAddress, sections);
                                    DecodeResourceMessageTables(resourceSpan, resourceSection.VirtualAddress, sections);
                                    DecodeResourceDialogs(resourceSpan, resourceSection.VirtualAddress, sections);
                                    DecodeResourceAccelerators(resourceSpan, resourceSection.VirtualAddress, sections);
                                    DecodeResourceManifests(resourceSpan, resourceSection.VirtualAddress, sections);
                                    DecodeResourceIconGroups(resourceSpan, resourceSection.VirtualAddress, sections);
                                    DecodeResourceVersionInfo(resourceSpan, resourceSection.VirtualAddress, sections);

                                    FileVersionInfo fvi;
                                    ResourceEntry versionEntry = _resources.FirstOrDefault(r => r.TypeId == (uint)ResourceType.Version);
                                    if (versionEntry != null &&
                                        TryGetResourceData(resourceSpan, resourceSection.VirtualAddress, versionEntry.DataRva, versionEntry.Size, sections, out byte[] versionData))
                                    {
                                        fvi = new FileVersionInfo(versionData);
                                        if (fvi.ProductVersion.Equals("0.0.0.0") && fvi.FileVersion.Equals("0.0.0.0"))
                                        {
                                            FileVersionInfo fallback = new FileVersionInfo(resourceBuffer, rsrcSize);
                                            if (!(fallback.ProductVersion.Equals("0.0.0.0") && fallback.FileVersion.Equals("0.0.0.0")))
                                            {
                                                fvi = fallback;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        fvi = new FileVersionInfo(resourceBuffer, rsrcSize);
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
                                }
                                finally
                                {
                                    ArrayPool<byte>.Shared.Return(resourceBuffer);
                                }

                                break;
                            case 3:
                                // Exception Table -> The .pdata Section
                                ParseExceptionDirectory(dataDirectory[i], sections);
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
                                    Pkcs7SignerInfo[] pkcs7Signers = Array.Empty<Pkcs7SignerInfo>();
                                    string pkcs7Error = string.Empty;
                                    AuthenticodeVerificationResult[] authenticodeResults = Array.Empty<AuthenticodeVerificationResult>();
                                    if (_options.ParseCertificateSigners &&
                                        (typeKind == CertificateTypeKind.PkcsSignedData || typeKind == CertificateTypeKind.TsStackSigned))
                                    {
                                        CertificateUtilities.TryGetPkcs7SignerInfos(certData, out pkcs7Signers, out pkcs7Error);
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

                                    _certificateEntries.Add(new CertificateEntry(typeKind, certData, pkcs7Signers, pkcs7Error, authenticodeResults));

                                    int aligned = Align8(entryLength);
                                    if (aligned <= 0)
                                    {
                                        break;
                                    }

                                    offset += aligned;
                                }

                                if (_certificates.Count > 0)
                                {
                                    _certificate = _certificates[0];
                                }

                                break;
                            case 5:
                                // Base Relocation Table -> The .reloc Section
                                ParseBaseRelocationTable(dataDirectory[i], sections);
                                break;
                            case 6:
                                // Debug The .debug Section
                                ParseDebugDirectory(dataDirectory[i], sections);
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
                                ParseLoadConfigDirectory(dataDirectory[i], sections, isPe32Plus);
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
                                _clrMetadata = null;
                                if (!TryGetFileOffset(sections, dataDirectory[i].VirtualAddress, out long clrOffset))
                                {
                                    Warn(ParseIssueCategory.CLR, "CLR header RVA not mapped to a section.");
                                    break;
                                }

                                buffer = new byte[Marshal.SizeOf(typeof(IMAGE_COR20_HEADER))];
                                if (!TrySetPosition(clrOffset, buffer.Length))
                                {
                                    Warn(ParseIssueCategory.CLR, "CLR header offset outside file bounds.");
                                    break;
                                }

                                ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                                IMAGE_COR20_HEADER clrHeader = ByteArrayToStructure<IMAGE_COR20_HEADER>(buffer);
                                if (clrHeader.MetaData.Size == 0)
                                {
                                    Warn(ParseIssueCategory.CLR, "CLR header does not reference metadata.");
                                    break;
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
                                    break;
                                }

                                if (!TryGetFileOffset(sections, clrHeader.MetaData.VirtualAddress, out long metadataOffset))
                                {
                                    Warn(ParseIssueCategory.Metadata, "Metadata RVA not mapped to a section.");
                                    break;
                                }

                                if (!TrySetPosition(metadataOffset, metadataSize))
                                {
                                    Warn(ParseIssueCategory.Metadata, "Metadata offset outside file bounds.");
                                    break;
                                }

                                byte[] metadataBuffer = ArrayPool<byte>.Shared.Rent(metadataSize);
                                try
                                {
                                    ReadExactly(PEFileStream, metadataBuffer, 0, metadataSize);
                                    if (!TryParseClrMetadata(metadataBuffer, metadataSize, clrHeader, out ClrMetadataInfo metadataInfo))
                                    {
                                        Warn(ParseIssueCategory.Metadata, "Failed to parse CLR metadata.");
                                        break;
                                    }

                                    _clrMetadata = metadataInfo;
                                }
                                finally
                                {
                                    ArrayPool<byte>.Shared.Return(metadataBuffer);
                                }
                                break;
                            case 15:
                                // Unknown
                                break;
                            default:
                                // Not supported or Implemented
                                break;
                        }
                    }

                    ValidateImportExportConsistency();
                    ComputeImportHash();
                    ComputeOverlayInfo(sections);
                    ComputeSectionEntropies(sections);
                    ComputeSecurityFeatures(isPe32Plus);
                    
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
