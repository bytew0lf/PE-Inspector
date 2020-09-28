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
    // Based on https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
    // https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Section_Table
    // https://tech-zealots.com/malware-analysis/understanding-concepts-of-va-rva-and-offset/
    // http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm
    // https://stackoverflow.com/questions/9955744/getting-offset-in-file-from-rva
    public class PECOFF
    {
        private BinaryReader PEFile;
        private StreamReader PEFileStreamReader;
        private Stream PEFileStream;

        #region Constructor / Destructor
        public PECOFF(string FileName)
        {
            // For Debug
            //();

            // Constructor
            if (File.Exists(FileName))
            {
                PEFileStreamReader = new StreamReader(FileName);
                PEFileStream = PEFileStreamReader.BaseStream;
                PEFile = new BinaryReader(PEFileStream);

                ReadPE();
            }
            else
            {
                PEFile = null;
            }
        }
        
        ~PECOFF()
        { 
            // Destructor
            if (PEFile != null)
            {
                PEFile.Close();
                PEFile.Dispose();
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

                byte[] buffer = new byte[Marshal.SizeOf(this)];
                reader.Read(buffer, 0, buffer.Length);
                hdr = buffer.ToStructure<IMAGE_DOS_HEADER>();
                
                this = hdr;
            } 
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IMAGE_NT_HEADERS
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IntPtr OptionalHeader;
            public PEFormat Magic;

            public IMAGE_NT_HEADERS(BinaryReader reader)
            {
                IMAGE_NT_HEADERS hdr = new IMAGE_NT_HEADERS();
                this = hdr;

                byte[] buffer = new byte[Marshal.SizeOf(this)];
                reader.Read(buffer, 0, buffer.Length);
                hdr = buffer.ToStructure<IMAGE_NT_HEADERS>();

                Extensions.Int64Words w = hdr.OptionalHeader.ToInt64().GetWords();
                PEFormat _magic = (PEFormat)w.Word0;

                reader.BaseStream.Position -= (Marshal.SizeOf(new IntPtr()) + sizeof(PEFormat)); // Correct the position of the Stream for continued reading
                switch (_magic)
                {
                    case PEFormat.PE32:
                        buffer = new byte[Marshal.SizeOf(new IMAGE_OPTIONAL_HEADER32())];                        
                        GCHandle handle32 = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                        reader.Read(buffer, 0, buffer.Length);
                        hdr.OptionalHeader = handle32.AddrOfPinnedObject();
                        handle32.Free(); // hopefully this is right
                        hdr.Magic = PEFormat.PE32;
                        break;

                    case PEFormat.PE32plus:
                        buffer = new byte[Marshal.SizeOf(new IMAGE_OPTIONAL_HEADER64())];
                        GCHandle handle64 = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                        reader.Read(buffer, 0, buffer.Length);
                        hdr.OptionalHeader = handle64.AddrOfPinnedObject();
                        handle64.Free(); // hopefully this is right
                        hdr.Magic = PEFormat.PE32plus;
                        break;
                    default:
                        break;
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

                byte[] buffer = new byte[Marshal.SizeOf(this)];
                reader.Read(buffer, 0, buffer.Length);
                section = buffer.ToStructure<IMAGE_SECTION_HEADER>();

                this = section;
            }

            public string Section
            {
                get { return new string(Name); }
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

        private bool _hasCertificate = false;
        public bool HasCertificate
        {
            get => _hasCertificate;
        }

        private byte[] _certificate;
        public byte[] Certificate
        {
            get => _certificate;
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
        #endregion

        #region Functions

        private long GetFileOffset(List<IMAGE_SECTION_HEADER> sections, UInt32 DirectoryVA)
        {
            long fileoffset = 0;
            foreach (IMAGE_SECTION_HEADER section in sections)
            {
                if (DirectoryVA >= section.VirtualAddress && DirectoryVA <= (section.VirtualAddress + section.VirtualSize))
                {
                    fileoffset = (DirectoryVA - section.VirtualAddress) + section.PointerToRawData;
                    break;
                }
            }
            return fileoffset;
        }

        private void ReadPE()
        {
            try
            {

                Stream fs = PEFileStream;
                {
                    byte[] rawData = new byte[fs.Length];
                    fs.Read(rawData, 0, rawData.Length);
                    fs.Position = 0;

                    // Compute a Hashvalue for the file
                    StringBuilder sbHash = new StringBuilder();
                    foreach (byte b in SHA256.Create().ComputeHash(rawData))
                    {
                        sbHash.Append(string.Format("{0:X2}", b));
                    }
                    _hash = sbHash.ToString();

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
                        }
                    }
                    catch (Exception)
                    {
                        // Something is wrong
                        _obfuscationPercentage = 0.0;
                        _isDotNetFile = false;
                        _isObfuscated = false;
                    }
                }
                

               IMAGE_DOS_HEADER header = new IMAGE_DOS_HEADER(PEFile);
                               
                byte[] buffer = new byte[]{};
                
                // Check the File header signature
                if ((header.e_magic == MagicByteSignature.IMAGE_DOS_SIGNATURE) || (header.e_magic == MagicByteSignature.IMAGE_OS2_SIGNATURE) || (header.e_magic == MagicByteSignature.IMAGE_OS2_SIGNATURE_LE))
                {
                    // Set the position to the PE-Header
                    PEFileStream.Position = header.e_lfanew;

                    // Read the PE Header
                    IMAGE_NT_HEADERS peHeader = new IMAGE_NT_HEADERS(PEFile);
                    
                    IMAGE_DATA_DIRECTORY[] DataDirectory = new IMAGE_DATA_DIRECTORY[] { };
                    var OptionalHeader = new object();
                    switch (peHeader.Magic)
                    {
                        case PEFormat.PE32:
                            OptionalHeader = peHeader.OptionalHeader.ToStructure<IMAGE_OPTIONAL_HEADER32>();
                            DataDirectory = ((IMAGE_OPTIONAL_HEADER32)OptionalHeader).DataDirectory;
                            break;
                        case PEFormat.PE32plus:
                            OptionalHeader = peHeader.OptionalHeader.ToStructure<IMAGE_OPTIONAL_HEADER64>();
                            DataDirectory = ((IMAGE_OPTIONAL_HEADER64)OptionalHeader).DataDirectory;
                            break;
                        default:
                            break;
                    }                   
                    
                    List<IMAGE_SECTION_HEADER> sections = new List<IMAGE_SECTION_HEADER>();
                    for (int i = 0; i < peHeader.FileHeader.NumberOfSections; i++)
                    {                       
                        sections.Add(new IMAGE_SECTION_HEADER(PEFile));
                    }

                    DateTime dt;
                    for (int i = 0; i < DataDirectory.Length; i++)
                    {
                        // skip empty directories
                        if (DataDirectory[i].Size == 0) { continue; }

                        switch (i)
                        {
                            case 0:
                                // Export Table                               

                                // Read the export directory table
                                buffer = new byte[Marshal.SizeOf(new EXPORT_DIRECTORY_TABLE())];
                                EXPORT_DIRECTORY_TABLE edt = new EXPORT_DIRECTORY_TABLE();
                                PEFileStream.Position = GetFileOffset(sections, DataDirectory[i].VirtualAddress);
                                PEFile.Read(buffer, 0, buffer.Length);
                                edt = (ByteArrayToStructure<EXPORT_DIRECTORY_TABLE>(buffer));

                                PEFileStream.Position = GetFileOffset(sections, edt.NamePointerRVA);
                                List<UInt32> NamePointers = new List<uint>();
                                for (int j = 0; j < edt.NumberOfNamePointers; j++)
                                {
                                    NamePointers.Add(PEFile.ReadUInt32());
                                }

                                // Read all exports
                                
                                List<byte> exportname = new List<byte>();
                                foreach (UInt32 ptr in NamePointers)
                                {
                                    PEFileStream.Position = GetFileOffset(sections, ptr);
                                    while (PEFile.PeekChar() != '\0')
                                    {
                                        exportname.Add(PEFile.ReadByte());
                                    }
                                    exports.Add(Encoding.UTF8.GetString(exportname.ToArray()));
                                    exportname.Clear();
                                }

                                break;
                            case 1:
                                // Import Table
                                buffer = new byte[Marshal.SizeOf(new IMPORT_DIRECTORY_TABLE())];
                                List<IMPORT_DIRECTORY_TABLE> idt = new List<IMPORT_DIRECTORY_TABLE>();
                                PEFileStream.Position = GetFileOffset(sections, DataDirectory[i].VirtualAddress);

                                // Read the Import directory table
                                for (int j = 0; j < (DataDirectory[i].Size / Marshal.SizeOf(new IMPORT_DIRECTORY_TABLE())) -1; j++)
                                {
                                    PEFile.Read(buffer, 0, buffer.Length);
                                    idt.Add(ByteArrayToStructure<IMPORT_DIRECTORY_TABLE>(buffer));
                                }
                                
                                // Read the import names
                                
                                List<byte> name = new List<byte>();
                                foreach (IMPORT_DIRECTORY_TABLE table in idt)
                                {
                                    PEFileStream.Position = GetFileOffset(sections, table.NameRVA);                                    
                                    while (PEFile.PeekChar() != '\0')
                                    {
                                        name.Add(PEFile.ReadByte());
                                    }
                                    imports.Add(Encoding.UTF8.GetString(name.ToArray()));
                                    name.Clear();
                                }
                                
                                break;
                            case 2:
                                // Resource Table                                

                                // Read the Version info for the file
                                IMAGE_SECTION_HEADER sect = sections.Find(p => p.Section == ".rsrc\0\0\0");
                                PEFileStream.Position = sect.PointerToRawData;
                                buffer = new byte[sect.SizeOfRawData];
                                PEFile.Read(buffer, 0, buffer.Length);                           

                                FileVersionInfo fvi = new FileVersionInfo(buffer);                                
                                _fileversion = fvi.FileVersion;
                                _productversion = fvi.ProductVersion;

                                if (fvi.ProductVersion.Equals("0.0.0.0") && fvi.FileVersion.Equals("0.0.0.0"))
                                {
                                    System.Diagnostics.FileVersionInfo versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(((FileStream)PEFileStream).Name);
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
                                CertificateTable cert = new CertificateTable();                                

                                buffer = new byte[DataDirectory[i].Size];
                                PEFileStream.Position = DataDirectory[i].VirtualAddress;

                                PEFile.Read(buffer, 0, buffer.Length);

                                byte[] tmp = new byte[sizeof(UInt32) + sizeof(CertificateRevision) + sizeof(CertificateType)];
                                Array.Copy(buffer, tmp, tmp.Length);

                                cert = ByteArrayToStructure<CertificateTable>(tmp);
                                int size_tmp = tmp.Length;
                                tmp = new byte[buffer.Length - size_tmp];
                                Array.Copy(buffer, size_tmp, tmp, 0, tmp.Length);
                                cert.bCertificate = tmp;

                                _hasCertificate = true;
                                _certificate = tmp;

                                //// Debug output
                                //dt = DateTime.Now;
                                //string fn_cert = string.Format("{0}_Cert_.p7b", Path.GetFileName(((FileStream)PEFileStream).Name));
                                //BinaryWriter bw = new BinaryWriter(new StreamWriter(Path.Combine(Directory.GetCurrentDirectory(), fn_cert)).BaseStream);
                                //bw.Write(tmp);
                                //bw.Close();
                                //bw.Dispose();

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
                }
            }
            catch (Exception)
            {
               // we need to handle this exception
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
