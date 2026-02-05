using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

using System.Security.Cryptography;

namespace PECoff
{
    public sealed class ParseResult
    {
        private readonly List<string> _errors = new List<string>();
        private readonly List<string> _warnings = new List<string>();

        public IReadOnlyList<string> Errors => _errors;
        public IReadOnlyList<string> Warnings => _warnings;
        public bool IsSuccess => _errors.Count == 0;

        internal void Clear()
        {
            _errors.Clear();
            _warnings.Clear();
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

    // Based on https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
    // https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Section_Table
    // https://tech-zealots.com/malware-analysis/understanding-concepts-of-va-rva-and-offset/
    // http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm
    // https://stackoverflow.com/questions/9955744/getting-offset-in-file-from-rva
    public class PECOFF
    {
        private BinaryReader PEFile;
        private FileStream PEFileStream;
        private readonly ParseResult _parseResult = new ParseResult();

        #region Constructor / Destructor
        public PECOFF(string FileName)
        {
            // For Debug
            //();

            // Constructor
            if (File.Exists(FileName))
            {
                PEFileStream = new FileStream(FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                PEFile = new BinaryReader(PEFileStream, Encoding.UTF8, leaveOpen: true);

                ReadPE();
            }
            else
            {
                PEFile = null;
                PEFileStream = null;
                _parseResult.AddError("File does not exist.");
            }
        }
        
        ~PECOFF()
        { 
            // Destructor
            if (PEFile != null)
            {
                PEFile.Dispose();
            }

            if (PEFileStream != null)
            {
                PEFileStream.Dispose();
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
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            IMAGE_DLL_CHARACTERISTICS_RESERVED_04 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
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

            public IMAGE_NT_HEADERS(BinaryReader reader)
            {
                IMAGE_NT_HEADERS hdr = new IMAGE_NT_HEADERS
                {
                    DataDirectory = Array.Empty<IMAGE_DATA_DIRECTORY>()
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
                }
                else if (hdr.Magic == PEFormat.PE32plus &&
                         optionalHeaderBuffer.Length >= Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64)))
                {
                    IMAGE_OPTIONAL_HEADER64 opt64 = optionalHeaderBuffer.ToStructure<IMAGE_OPTIONAL_HEADER64>();
                    hdr.DataDirectory = opt64.DataDirectory ?? Array.Empty<IMAGE_DATA_DIRECTORY>();
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
        private struct IMPORT_DIRECTORY_TABLE
        {
            public UInt32 LookupTableVirtualAddress;
            public UInt32 TimeDateStamp; // Set to Zero until Bound
            public UInt32 FowarderChain;
            public UInt32 NameRVA;
            public UInt32 ImportAddressTableRVA;
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

        private List<string> imports = new List<string>();
        public string[] Imports
        {
            get { return imports.ToArray(); }
        }

        private List<string> exports = new List<string>();
        public string[] Exports
        {
            get { return exports.ToArray(); }
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

        private static int Align8(int value)
        {
            return (value + 7) & ~7;
        }

        private void Fail(string message)
        {
            _parseResult.AddError(message);
        }

        private void Warn(string message)
        {
            _parseResult.AddWarning(message);
        }

        private void ReadPE()
        {
            try
            {
                _parseResult.Clear();
                if (PEFile == null || PEFileStream == null)
                {
                    Fail("No PE file stream available.");
                    return;
                }

                Stream fs = PEFileStream;
                {
                    byte[] rawData = new byte[fs.Length];
                    ReadExactly(fs, rawData, 0, rawData.Length);
                    fs.Position = 0;

                    // Compute a Hashvalue for the file
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        StringBuilder sbHash = new StringBuilder();
                        foreach (byte b in sha256.ComputeHash(rawData))
                        {
                            sbHash.Append(string.Format("{0:X2}", b));
                        }
                        _hash = sbHash.ToString();
                    }

                    try
                    {
                        if (rawData.Length > 0)
                        {
                            // analyze Assembly
                            AnalyzeAssembly a = new AnalyzeAssembly(rawData);
                            
                            Array.Clear(rawData, 0, rawData.Length);
                            rawData = null;

                            _obfuscationPercentage = a.ObfuscationPercentage;
                            _isDotNetFile = a.IsDotNetFile;
                            _isObfuscated = a.IsObfuscated;
                            _assemblyReferenceInfos = a.AssemblyReferenceInfos.ToList();
                        }
                    }
                    catch (Exception ex)
                    {
                        // Something is wrong
                        Warn($"AnalyzeAssembly failed: {ex.Message}");
                        _obfuscationPercentage = 0.0;
                        _isDotNetFile = false;
                        _isObfuscated = false;
                        _assemblyReferenceInfos.Clear();
                    }
                }
                
                if (!TrySetPosition(0, Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))))
                {
                    Fail("File too small for DOS header.");
                    return;
                }

                IMAGE_DOS_HEADER header = new IMAGE_DOS_HEADER(PEFile);
                               
                byte[] buffer = new byte[]{};
                
                // Check the File header signature
                if ((header.e_magic == MagicByteSignature.IMAGE_DOS_SIGNATURE) || (header.e_magic == MagicByteSignature.IMAGE_OS2_SIGNATURE) || (header.e_magic == MagicByteSignature.IMAGE_OS2_SIGNATURE_LE))
                {
                    if (!TrySetPosition(header.e_lfanew, sizeof(uint) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))))
                    {
                        Fail("PE header offset is outside the file bounds.");
                        return;
                    }

                    // Set the position to the PE-Header
                    IMAGE_NT_HEADERS peHeader = new IMAGE_NT_HEADERS(PEFile);
                    if (peHeader.Signature != IMAGE_NT_SIGNATURE )
                    {
                        Fail("Invalid PE signature.");
                        return;
                    }

                    if (peHeader.Magic != PEFormat.PE32 && peHeader.Magic != PEFormat.PE32plus)
                    {
                        Fail("Unknown PE optional header format.");
                        return;
                    }
                    
                    IMAGE_DATA_DIRECTORY[] dataDirectory = peHeader.DataDirectory ?? Array.Empty<IMAGE_DATA_DIRECTORY>();
                    
                    List<IMAGE_SECTION_HEADER> sections = new List<IMAGE_SECTION_HEADER>();
                    int sectionTableSize = peHeader.FileHeader.NumberOfSections * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
                    if (!TrySetPosition(PEFileStream.Position, sectionTableSize))
                    {
                        Fail("Section table exceeds file bounds.");
                        return;
                    }

                    for (int i = 0; i < peHeader.FileHeader.NumberOfSections; i++)
                    {                       
                        sections.Add(new IMAGE_SECTION_HEADER(PEFile));
                    }

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
                                    Warn("Export table RVA not mapped to a section.");
                                    break;
                                }

                                if (!TrySetPosition(exportTableOffset, buffer.Length))
                                {
                                    Warn("Export table offset outside file bounds.");
                                    break;
                                }

                                ReadExactly(PEFileStream, buffer, 0, buffer.Length);
                                edt = (ByteArrayToStructure<EXPORT_DIRECTORY_TABLE>(buffer));

                                if (!TryGetFileOffset(sections, edt.NamePointerRVA, out long namePtrOffset))
                                {
                                    Warn("Export name pointer RVA not mapped to a section.");
                                    break;
                                }

                                long pointerBytes = edt.NumberOfNamePointers * sizeof(UInt32);
                                if (pointerBytes > int.MaxValue || !TrySetPosition(namePtrOffset, (int)pointerBytes))
                                {
                                    Warn("Export name pointer table outside file bounds.");
                                    break;
                                }

                                List<UInt32> NamePointers = new List<uint>();
                                for (int j = 0; j < edt.NumberOfNamePointers; j++)
                                {
                                    NamePointers.Add(PEFile.ReadUInt32());
                                }

                                // Read all exports
                                bool exportNameFailure = false;
                                foreach (UInt32 ptr in NamePointers)
                                {
                                    if (!TryGetFileOffset(sections, ptr, out long exportNameOffset))
                                    {
                                        exportNameFailure = true;
                                        continue;
                                    }

                                    if (TryReadNullTerminatedString(exportNameOffset, out string exportName) &&
                                        !string.IsNullOrWhiteSpace(exportName))
                                    {
                                        exports.Add(exportName);
                                    }
                                    else
                                    {
                                        exportNameFailure = true;
                                    }
                                }

                                if (exportNameFailure)
                                {
                                    Warn("One or more export names could not be read.");
                                }

                                break;
                            case 1:
                                // Import Table
                                buffer = new byte[Marshal.SizeOf(new IMPORT_DIRECTORY_TABLE())];
                                List<IMPORT_DIRECTORY_TABLE> idt = new List<IMPORT_DIRECTORY_TABLE>();
                                if (!TryGetFileOffset(sections, dataDirectory[i].VirtualAddress, out long importTableOffset))
                                {
                                    Warn("Import table RVA not mapped to a section.");
                                    break;
                                }

                                if (!TryGetIntSize(dataDirectory[i].Size, out int importTableSize))
                                {
                                    Warn("Import table size exceeds supported limits.");
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
                                        Warn("Import table entry outside file bounds.");
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
                                        Warn("Import name RVA not mapped to a section.");
                                        continue;
                                    }

                                    if (TryReadNullTerminatedString(importNameOffset, out string importName) &&
                                        !string.IsNullOrWhiteSpace(importName))
                                    {
                                        imports.Add(importName);
                                    }
                                }
                                
                                break;
                            case 2:
                                // Resource Table                                

                                // Read the Version info for the file
                                IMAGE_SECTION_HEADER sect = sections.Find(
                                    p => p.Section.TrimEnd('\0').Equals(".rsrc", StringComparison.OrdinalIgnoreCase));

                                if (sect.Name == null || !TryGetIntSize(sect.SizeOfRawData, out int rsrcSize))
                                {
                                    Warn("Resource section not found or invalid.");
                                    break;
                                }

                                if (!TrySetPosition(sect.PointerToRawData, rsrcSize))
                                {
                                    Warn("Resource section offset outside file bounds.");
                                    break;
                                }

                                buffer = new byte[rsrcSize];
                                ReadExactly(PEFileStream, buffer, 0, buffer.Length);                           

                                FileVersionInfo fvi = new FileVersionInfo(buffer);                                
                                _fileversion = fvi.FileVersion;
                                _productversion = fvi.ProductVersion;

                                if (fvi.ProductVersion.Equals("0.0.0.0") && fvi.FileVersion.Equals("0.0.0.0"))
                                {
                                    System.Diagnostics.FileVersionInfo versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(PEFileStream.Name);
                                    _fileversion = versionInfo.FileVersion;
                                    _productversion = versionInfo.ProductVersion;
                                }

                                // This will read the Directory table --> further implementation needed
                                //buffer = new byte[Marshal.SizeOf(new RESOURCE_DIRECTORY_TABLE())];
                                //RESOURCE_DIRECTORY_TABLE rdt = new RESOURCE_DIRECTORY_TABLE();
                                //PEFileStream.Position = GetFileOffset(sections, DataDirectory[i].VirtualAddress);
                                //PEFile.Read(buffer, 0, buffer.Length);
                                //rdt = (ByteArrayToStructure<RESOURCE_DIRECTORY_TABLE>(buffer));
                                
                                break;
                            case 3:
                                // Exception Table -> The .pdata Section
                                break;
                            case 4:
                                // Certificate Table -> The attribute certificate table
                                _certificates.Clear();
                                _certificate = null;
                                if (!TryGetIntSize(dataDirectory[i].Size, out int certSize) ||
                                    certSize < (sizeof(UInt32) + sizeof(CertificateRevision) + sizeof(CertificateType)))
                                {
                                    Warn("Certificate table size is invalid.");
                                    break;
                                }

                                if (!TrySetPosition(dataDirectory[i].VirtualAddress, certSize))
                                {
                                    Warn("Certificate table offset outside file bounds.");
                                    break;
                                }

                                buffer = new byte[certSize];
                                ReadExactly(PEFileStream, buffer, 0, buffer.Length);

                                int headerSize = Marshal.SizeOf(typeof(CertificateTableHeader));
                                int offset = 0;
                                while (offset + headerSize <= buffer.Length)
                                {
                                    byte[] tmp = new byte[headerSize];
                                    Array.Copy(buffer, offset, tmp, 0, headerSize);
                                    CertificateTableHeader certHeader = ByteArrayToStructure<CertificateTableHeader>(tmp);

                                    if (certHeader.dwLength < headerSize)
                                    {
                                        Warn("Certificate entry length is invalid.");
                                        break;
                                    }

                                    if (certHeader.dwLength > int.MaxValue)
                                    {
                                        Warn("Certificate entry length exceeds supported limits.");
                                        break;
                                    }

                                    int entryLength = (int)certHeader.dwLength;
                                    if (offset + entryLength > buffer.Length)
                                    {
                                        Warn("Certificate entry exceeds certificate table size.");
                                        break;
                                    }

                                    int certDataLength = entryLength - headerSize;
                                    if (certDataLength <= 0)
                                    {
                                        Warn("Certificate entry does not contain certificate data.");
                                        break;
                                    }

                                    byte[] certData = new byte[certDataLength];
                                    Array.Copy(buffer, offset + headerSize, certData, 0, certDataLength);
                                    _certificates.Add(certData);

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
                                break;
                            case 6:
                                // Debug The .debug Section
                                break;
                            case 7:
                                // Archive -> Reserved, must be 0
                                break;
                            case 8:
                                // Global Ptr -> The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero.
                                break;
                            case 9:
                                // TLS Table -> Thread Local Storage section
                                break;
                            case 10:
                                // Load Config Table -> The load configuration table address and size 
                                break;
                            case 11:
                                // Bound Import -> The bound import table address and size
                                break;
                            case 12:
                                // IAT -> Import Address Table
                                break;
                            case 13:
                                // Delay Import Descriptor -> Delay-Load Import Tables 
                                break;
                            case 14:
                                // CLR Runtime Header -> The .cormeta Section (Object Only)
                                break;
                            case 15:
                                // Unknown
                                break;
                            default:
                                // Not supported or Implemented
                                break;
                        }
                    }
                    

                }
                else
                {
                    // not a DOS-File
                    Fail("Invalid DOS signature.");
                }
            }
            catch (Exception ex)
            {
               Fail($"Unexpected error while parsing PE: {ex.Message}");
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
