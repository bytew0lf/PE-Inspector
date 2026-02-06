using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text;

using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace PECoff
{
    public static class Extensions
    {
        public struct Int64Words
        {
            public ushort Word0;
            public ushort Word1;
            public ushort Word2;
            public ushort Word3;
        }

        public struct UInt32Words
        {
            public ushort LOW;
            public ushort HI;
        }

        public static int WordCount(this String str)
        {
            return str.Split(new char[] { ' ', '.', '?' }, StringSplitOptions.RemoveEmptyEntries).Length;
        }

        public static UInt16 ReverseBytes(this UInt16 value)
        {
            return (UInt16)((value & 0xFFU) << 8 | (value & 0xFF00U) >> 8);
        }

        public static UInt32 ReverseBytes(this UInt32 value)
        {
            return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 | 
                   (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
        }

        public static Int32 ReverseBytes(this Int32 value)
        {
            UInt32 x = Convert.ToUInt32(value);

            return Convert.ToInt32((x & 0x000000FF) << 24 | (x & 0x0000FF00) << 8 | (x & 0x00FF0000) >> 8 | (x & 0xFF000000) >> 24);
        }

        public static UInt64 ReverseBytes(this UInt64 value)
        {
            return (value & 0x00000000000000FFUL) << 56 | (value & 0x000000000000FF00UL) << 40 |
                   (value & 0x0000000000FF0000UL) << 24 | (value & 0x00000000FF000000UL) << 8 |
                   (value & 0x000000FF00000000UL) >> 8 | (value & 0x0000FF0000000000UL) >> 24 |
                   (value & 0x00FF000000000000UL) >> 40 | (value & 0xFF00000000000000UL) >> 56;
        }

        public static T ToStructure<T>(this byte[] bytes) where T : struct
        {
            // Thanks to coincoin @ http://stackoverflow.com/questions/2871/reading-a-c-c-data-structure-in-c-sharp-from-a-byte-array
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T retVal = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return retVal;
        }

        public static T ToStructure<T>(this IntPtr value) where T : struct
        {
            T retVal = (T)Marshal.PtrToStructure(value, typeof(T));
            return retVal;
        }

        public static Int64Words GetWords(this Int64 value)
        {
            byte[] b = BitConverter.GetBytes(value);
            return b.ToStructure<Int64Words>();
        }

        public static UInt32Words GetWords(this UInt32 value)
        {
            byte[] b = BitConverter.GetBytes(value);
            return b.ToStructure<UInt32Words>();
        }
    }


    public class Search
    {
        /**
       * Returns the index within this string of the first occurrence of the
       * specified substring. If it is not a substring, return -1.
       * 
       * @param haystack The string to be scanned
       * @param needle The target string to search
       * @return The start index of the substring
       */
        public static long IndexOf(byte[] haystack, byte[] needle)
        {
            return IndexOf(haystack, haystack != null ? haystack.Length : 0, needle);
        }

        public static long IndexOf(byte[] haystack, int length, byte[] needle)
        {
            if (needle.Length == 0)
            {
                return 0;
            }

            if (haystack == null || length <= 0)
            {
                return -1;
            }

            if (length > haystack.Length)
            {
                length = haystack.Length;
            }

            long[] charTable = MakeCharTable(needle);
            long[] offsetTable = MakeOffsetTable(needle);
            for (long i = needle.Length - 1, j; i < length; )
            {
                for (j = needle.Length - 1; needle[j] == haystack[i]; --i, --j)
                {
                    if (j == 0)
                    {
                        return i;
                    }
                }
                // i += needle.length - j; // For naive method
                i += Math.Max(offsetTable[needle.Length - 1 - j], charTable[haystack[i]]);
            }
            return -1;
        }

        /**
         * Makes the jump table based on the mismatched character information.
         */
        private static long[] MakeCharTable(byte[] needle)
        {
            int ALPHABET_SIZE = 256;
            long[] table = new long[ALPHABET_SIZE];
            for (long i = 0; i < table.Length; ++i)
            {
                table[i] = needle.Length;
            }
            for (long i = 0; i < needle.Length - 1; ++i)
            {
                table[needle[i]] = needle.Length - 1 - i;
            }
            return table;
        }

        /**
         * Makes the jump table based on the scan offset which mismatch occurs.
         */
        private static long[] MakeOffsetTable(byte[] needle)
        {
            long[] table = new long[needle.Length];
            long lastPrefixPosition = needle.Length;
            for (long i = needle.Length - 1; i >= 0; --i)
            {
                if (IsPrefix(needle, i + 1))
                {
                    lastPrefixPosition = i + 1;
                }
                table[needle.Length - 1 - i] = lastPrefixPosition - i + needle.Length - 1;
            }
            for (long i = 0; i < needle.Length - 1; ++i)
            {
                long slen = SuffixLength(needle, i);
                table[slen] = needle.Length - 1 - i + slen;
            }
            return table;
        }

        /**
         * Is needle[p:end] a prefix of needle?
         */
        private static bool IsPrefix(byte[] needle, long p)
        {
            for (long i = p, j = 0; i < needle.Length; ++i, ++j)
            {
                if (needle[i] != needle[j])
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * Returns the maximum length of the substring ends at p and is a suffix.
         */
        private static long SuffixLength(byte[] needle, long p)
        {
            long len = 0;
            for (long i = p, j = needle.Length - 1;
                 i >= 0 && needle[i] == needle[j]; --i, --j)
            {
                len += 1;
            }
            return len;
        }
    
    
    }

    public class FileVersionInfo
    {
        private MemoryStream _ms;
        private VS_VERSIONINFO vi;
        private readonly Dictionary<string, string> _stringValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Dictionary<string, string>> _stringTables = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        private readonly List<uint> _translations = new List<uint>();
        private uint? _translation;

        #region enums
        [Flags]
        private enum FileFlags : uint
        {
            VS_FF_DEBUG = 0x00000001,
            VS_FF_INFOINFERRED = 0x00000010,
            VS_FF_PATCHED = 0x00000004,
            VS_FF_PRERELEASE = 0x00000002,
            VS_FF_PRIVATEBUILD = 0x00000008,
            VS_FF_SPECIALBUILD = 0x00000020
        }

        private enum FileOS : uint
        {
            VOS_DOS = 0x00010000, // The file was designed for MS-DOS.
            VOS_NT = 0x00040000, // The file was designed for Windows NT.
            VOS__WINDOWS16 = 0x00000001, // The file was designed for 16-bit Windows.
            VOS__WINDOWS32 = 0x00000004, // The file was designed for 32-bit Windows.
            VOS_OS216 = 0x00020000, // The file was designed for 16-bit OS/2.
            VOS_OS232 = 0x00030000, // The file was designed for 32-bit OS/2.
            VOS__PM16 = 0x00000002, // The file was designed for 16-bit Presentation Manager.
            VOS__PM32 = 0x00000003, // The file was designed for 32-bit Presentation Manager.
            VOS_UNKNOWN = 0x00000000, // The operating system for which the file was designed is unknown to the system.

            VOS_DOS_WINDOWS16 = 0x00010001, // The file was designed for 16-bit Windows running on MS-DOS.
            VOS_DOS_WINDOWS32 = 0x00010004, // The file was designed for 32-bit Windows running on MS-DOS.
            VOS_NT_WINDOWS32 = 0x00040004, // The file was designed for Windows NT.
            VOS_OS216_PM16 = 0x00020002, // The file was designed for 16-bit Presentation Manager running on 16-bit OS/2.
            VOS_OS232_PM32 = 0x00030003 // The file was designed for 32-bit Presentation Manager running on 32-bit OS/2.
        }

        private enum FileType : uint
        {
            VFT_APP = 0x00000001, // The file contains an application.
            VFT_DLL = 0x00000002, // The file contains a DLL.
            VFT_DRV = 0x00000003, // The file contains a device driver. If dwFileType is VFT_DRV, dwFileSubtype contains a more specific description of the driver.
            VFT_FONT = 0x00000004, // The file contains a font. If dwFileType is VFT_FONT, dwFileSubtype contains a more specific description of the font file.
            VFT_STATIC_LIB = 0x00000007, // The file contains a static-link library.
            VFT_UNKNOWN = 0x00000000, // The file type is unknown to the system.
            VFT_VXD = 0x00000005 // The file contains a virtual device.
        }

        private enum FileDRVSubtype : uint
        {

            VFT2_DRV_COMM = 0x0000000A, // The file contains a communications driver.
            VFT2_DRV_DISPLAY = 0x00000004, // The file contains a display driver.
            VFT2_DRV_INSTALLABLE = 0x00000008, // The file contains an installable driver.
            VFT2_DRV_KEYBOARD = 0x00000002, // The file contains a keyboard driver.
            VFT2_DRV_LANGUAGE = 0x00000003, // The file contains a language driver.
            VFT2_DRV_MOUSE = 0x00000005, // The file contains a mouse driver.
            VFT2_DRV_NETWORK = 0x00000006, // The file contains a network driver.
            VFT2_DRV_PRINTER = 0x00000001, // The file contains a printer driver.
            VFT2_DRV_SOUND = 0x00000009, // The file contains a sound driver.
            VFT2_DRV_SYSTEM = 0x00000007, // The file contains a system driver.
            VFT2_DRV_VERSIONED_PRINTER = 0x0000000C, // The file contains a versioned printer driver.
            VFT2_UNKNOWN = 0x00000000 // The driver type is unknown by the system.
        }
        private enum FileFNTSubtype : uint
        {
            VFT2_FONT_RASTER = 0x00000001, // The file contains a raster font.
            VFT2_FONT_TRUETYPE = 0x00000003, // The file contains a TrueType font.
            VFT2_FONT_VECTOR = 0x00000002, // The file contains a vector font.
            VFT2_UNKNOWN = 0x00000000 // The font type is unknown by the system.
        }

        #endregion


        #region Structures
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        private struct VS_VERSIONINFO
        {
            public ushort wLength;
            public ushort wValueLength;
            public ushort wType;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
            public string szKey; // The Unicode string L"VS_VERSION_INFO". 
            
            public ushort Padding1;
            public VS_FIXEDFILEINFO Value;
            public ushort Padding2;
            public ushort Children;

            public VS_VERSIONINFO(BinaryReader reader)
            {
                VS_VERSIONINFO hdr = new VS_VERSIONINFO();
                this = hdr;

                byte[] buffer = new byte[Marshal.SizeOf(this)];
                reader.Read(buffer, 0, buffer.Length);
                hdr = buffer.ToStructure<VS_VERSIONINFO>();

                //hdr.Value.FileVersion = hdr.Value.FileVersion.ReverseBytes();
                //hdr.Value.ProductVersion = hdr.Value.ProductVersion.ReverseBytes();
                //hdr.Value.TimeStamp =hdr.Value.TimeStamp.ReverseBytes();

                this = hdr;                
            }            
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct VS_FIXEDFILEINFO
        {

            [FieldOffset(0)]
            public UInt32 dwSignature; // Contains the value 0xFEEF04BD. 
            [FieldOffset(4)]
            public UInt32 dwStrucVersion;

            [FieldOffset(8)]
            public UInt32 dwFileVersionMS;
            [FieldOffset(12)]
            public UInt32 dwFileVersionLS;
            [FieldOffset(8)]
            public UInt64 FileVersion;

            [FieldOffset(16)]
            public UInt32 dwProductVersionMS;
            [FieldOffset(20)]
            public UInt32 dwProductVersionLS;
            [FieldOffset(16)]
            public UInt64 ProductVersion;

            [FieldOffset(24)]
            public UInt32 dwFileFlagsMask;

            [FieldOffset(28)]
            public FileFlags dwFileFlags;
            [FieldOffset(32)]
            public FileOS dwFileOS;
            [FieldOffset(36)]
            public FileType dwFileType;

            [FieldOffset(40)]
            public FileDRVSubtype DriverFileSubtype;
            [FieldOffset(40)]
            public FileFNTSubtype FontFileSubtype;
            [FieldOffset(40)]
            public UInt32 VXDFileSubtype;

            [FieldOffset(44)]
            public UInt32 dwFileDateMS;
            [FieldOffset(48)]
            public UInt32 dwFileDateLS;
            [FieldOffset(44)]
            public UInt64 TimeStamp;
        }


        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        private struct VarFileInfo
        {
            public ushort wLength;
            public ushort wValueLength;
            public ushort wType;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 11)]
            public string szKey; // The Unicode string L"VarFileInfo".
            public ushort Padding;
            Var Children;


            public VarFileInfo(BinaryReader reader)
            {
                VarFileInfo hdr = new VarFileInfo();
                this = hdr;

                byte[] buffer = new byte[Marshal.SizeOf(this)];
                reader.Read(buffer, 0, buffer.Length);
                hdr = buffer.ToStructure<VarFileInfo>();

                this = hdr;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        private struct Var 
        {
            public ushort wLength;
            public ushort wValueLength;
            public ushort wType;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 11)]
            public string szKey; // The Unicode string L"Translation". 
            public ushort Padding;
            public UInt32 Value;            
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        private struct StringTable
        {
            public ushort wLength;
            public ushort wValueLength;
            public ushort wType;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string szKey; // An 8-digit hexadecimal number stored as a Unicode string.
            public ushort Padding;
            VI_String Children;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        private struct StringFileInfo
        {
            public ushort wLength;
            public ushort wValueLength;
            public ushort wType;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string szKey; // L"StringFileInfo". 
            public ushort Padding;
            public StringTable Children;


            public StringFileInfo(BinaryReader reader)
            {
                StringFileInfo hdr = new StringFileInfo();
                this = hdr;

                byte[] buffer = new byte[Marshal.SizeOf(this)];
                reader.Read(buffer, 0, buffer.Length);
                hdr = buffer.ToStructure<StringFileInfo>();                              

                this = hdr;                
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        private struct VI_String
        {
            public ushort wLength;
            public ushort wValueLength;
            public ushort wType;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)] // Unknown size
            public char[] szKey; //
            public ushort Padding;
            public ushort Value;
        }
        #endregion


        #region Constructors / Destructors
        public FileVersionInfo(byte[] buffer)
            : this(buffer, buffer != null ? buffer.Length : 0)
        {
        }

        public FileVersionInfo(byte[] buffer, int length)
        {
            if (buffer == null || length <= 0)
            {
                _ms = new MemoryStream(Array.Empty<byte>());
                return;
            }

            if (length > buffer.Length)
            {
                length = buffer.Length;
            }

            // Constructor
            _ms = new MemoryStream(buffer, 0, length, false, true);

            // VS_VERSION_INFO
            byte[] pattern = Encoding.Unicode.GetBytes("VS_VERSION_INFO");
            long pos = Search.IndexOf(buffer, length, pattern);
            if (pos == -1)
            {
                return; // No VersionInfo found
            }

            _ms.Position = pos - 6; // setup the correct offset
            vi = new VS_VERSIONINFO(new BinaryReader(_ms));
            ParseVersionResource(buffer, (int)(pos - 6));
        }

        ~FileVersionInfo()
        { 
            // Destructor
            if (_ms != null)
            {
                _ms.Close();
                _ms.Dispose();
            }
        }
        #endregion

        #region Properties
        public string FileVersion
        {
            get 
            {
                ushort major  = 0;
                ushort minor  = 0;                
                ushort release = 0;
                ushort build = 0;

                if (vi.Value.dwSignature == 0xFEEF04BD)
                {
                    major = vi.Value.dwFileVersionMS.GetWords().HI;
                    minor = vi.Value.dwFileVersionMS.GetWords().LOW;

                    release = vi.Value.dwFileVersionLS.GetWords().HI;
                    build = vi.Value.dwFileVersionLS.GetWords().LOW;
                }
                
                return String.Format("{0}.{1}.{2}.{3}", major, minor, release, build);            
            }
        }

        public string ProductVersion
        {
            get
            {
                ushort major = 0;
                ushort minor = 0;
                ushort release = 0;
                ushort build = 0;

                if (vi.Value.dwSignature == 0xFEEF04BD)
                {
                    major = vi.Value.dwProductVersionMS.GetWords().HI;
                    minor = vi.Value.dwProductVersionMS.GetWords().LOW;

                    release = vi.Value.dwProductVersionLS.GetWords().HI;
                    build = vi.Value.dwProductVersionLS.GetWords().LOW;
                }

                return String.Format("{0}.{1}.{2}.{3}", major, minor, release, build);
            }
        }

        public string CompanyName => GetStringValue("CompanyName");
        public string FileDescription => GetStringValue("FileDescription");
        public string InternalName => GetStringValue("InternalName");
        public string OriginalFilename => GetStringValue("OriginalFilename");
        public string ProductName => GetStringValue("ProductName");
        public string Comments => GetStringValue("Comments");
        public string LegalCopyright => GetStringValue("LegalCopyright");
        public string LegalTrademarks => GetStringValue("LegalTrademarks");
        public string PrivateBuild => GetStringValue("PrivateBuild");
        public string SpecialBuild => GetStringValue("SpecialBuild");
        public string Language => GetLanguage();
        public uint? Translation => _translation;
        public IReadOnlyDictionary<string, string> StringValues => new ReadOnlyDictionary<string, string>(_stringValues);

        public VersionFixedFileInfo FixedFileInfo
        {
            get
            {
                if (vi.Value.dwSignature != 0xFEEF04BD)
                {
                    return null;
                }

                return new VersionFixedFileInfo(
                    FileVersion,
                    ProductVersion,
                    vi.Value.dwFileFlagsMask,
                    (uint)vi.Value.dwFileFlags,
                    DecodeFileFlags((uint)vi.Value.dwFileFlags, vi.Value.dwFileFlagsMask),
                    (uint)vi.Value.dwFileOS,
                    DecodeFileOs((uint)vi.Value.dwFileOS),
                    (uint)vi.Value.dwFileType,
                    DecodeFileType((uint)vi.Value.dwFileType),
                    (uint)vi.Value.VXDFileSubtype,
                    DecodeFileSubtype((uint)vi.Value.dwFileType, (uint)vi.Value.VXDFileSubtype),
                    vi.Value.dwFileDateMS,
                    vi.Value.dwFileDateLS);
            }
        }

        public VersionInfoDetails ToVersionInfoDetails()
        {
            VersionFixedFileInfo fixedInfo = FixedFileInfo;
            VersionStringTableInfo[] stringTables = _stringTables
                .Select(kvp =>
                {
                    Dictionary<string, string> normalized = NormalizeVersionStrings(kvp.Value);
                    ParseStringTableKey(kvp.Key, out ushort languageId, out ushort codePage);
                    return new VersionStringTableInfo(kvp.Key, languageId, codePage, new ReadOnlyDictionary<string, string>(normalized));
                })
                .ToArray();
            VersionTranslationInfo[] translations = _translations
                .Distinct()
                .Select(BuildTranslationInfo)
                .ToArray();
            return new VersionInfoDetails(
                fixedInfo,
                new ReadOnlyDictionary<string, string>(_stringValues),
                stringTables,
                _translation,
                translations,
                GetLanguage());
        }
        #endregion

        private string GetStringValue(string key)
        {
            return _stringValues.TryGetValue(key, out string value) ? value : string.Empty;
        }

        private string GetLanguage()
        {
            string language = GetStringValue("Language");
            if (!string.IsNullOrWhiteSpace(language))
            {
                language = language.Trim();
                if (TryParseLanguageCode(language, out ushort langId, out ushort codePage))
                {
                    string cultureName = ResolveCultureName(langId);

                    if (!string.IsNullOrWhiteSpace(cultureName))
                    {
                        return string.Format("{0} ({1:X4}-{2:X4})", cultureName, langId, codePage);
                    }
                }

                return language;
            }

            if (_translation.HasValue)
            {
                ushort langId = (ushort)(_translation.Value & 0xFFFF);
                ushort codePage = (ushort)((_translation.Value >> 16) & 0xFFFF);
                if (langId == 0)
                {
                    return string.Empty;
                }
                string cultureName = ResolveCultureName(langId);

                if (!string.IsNullOrWhiteSpace(cultureName))
                {
                    return string.Format("{0} ({1:X4}-{2:X4})", cultureName, langId, codePage);
                }

                return string.Format("{0:X4}-{1:X4}", langId, codePage);
            }

            return string.Empty;
        }

        private VersionTranslationInfo BuildTranslationInfo(uint translationValue)
        {
            ushort langId = (ushort)(translationValue & 0xFFFF);
            ushort codePage = (ushort)((translationValue >> 16) & 0xFFFF);
            string cultureName = ResolveCultureName(langId);
            string displayName;
            if (!string.IsNullOrWhiteSpace(cultureName))
            {
                displayName = string.Format("{0} ({1:X4}-{2:X4})", cultureName, langId, codePage);
            }
            else
            {
                displayName = string.Format("{0:X4}-{1:X4}", langId, codePage);
            }

            return new VersionTranslationInfo(langId, codePage, translationValue, cultureName, displayName);
        }

        private static string ResolveCultureName(ushort langId)
        {
            if (langId == 0)
            {
                return string.Empty;
            }

            try
            {
                return CultureInfo.GetCultureInfo(langId).EnglishName;
            }
            catch (CultureNotFoundException)
            {
            }

            try
            {
                foreach (CultureInfo culture in CultureInfo.GetCultures(CultureTypes.AllCultures))
                {
                    if (culture.LCID == langId)
                    {
                        return culture.EnglishName;
                    }
                }
            }
            catch (Exception)
            {
            }

            return ResolveCultureNameFromLangId(langId);
        }

        private static Dictionary<string, string> NormalizeVersionStrings(Dictionary<string, string> values)
        {
            Dictionary<string, string> normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, string> entry in values)
            {
                string key = entry.Key?.Trim() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(key))
                {
                    continue;
                }

                string value = entry.Value?.Trim() ?? string.Empty;
                if (normalized.ContainsKey(key))
                {
                    continue;
                }

                normalized[key] = value;
            }

            return normalized;
        }

        private static void ParseStringTableKey(string key, out ushort languageId, out ushort codePage)
        {
            languageId = 0;
            codePage = 0;
            if (string.IsNullOrWhiteSpace(key) || key.Length != 8)
            {
                return;
            }

            if (ushort.TryParse(key.Substring(0, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ushort lang) &&
                ushort.TryParse(key.Substring(4, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ushort cp))
            {
                languageId = lang;
                codePage = cp;
            }
        }

        private static string[] DecodeFileFlags(uint flags, uint mask)
        {
            uint effective = mask != 0 ? (flags & mask) : flags;
            if (effective == 0)
            {
                return Array.Empty<string>();
            }

            List<string> names = new List<string>();
            foreach (FileFlags flag in Enum.GetValues(typeof(FileFlags)))
            {
                if (((uint)flag & effective) != 0)
                {
                    string name = flag.ToString();
                    if (name.StartsWith("VS_FF_", StringComparison.Ordinal))
                    {
                        name = name.Substring(6);
                    }
                    names.Add(name);
                }
            }

            return names.Count == 0 ? Array.Empty<string>() : names.ToArray();
        }

        private static string DecodeFileOs(uint value)
        {
            if (Enum.IsDefined(typeof(FileOS), value))
            {
                return ((FileOS)value).ToString();
            }

            return string.Format("0x{0:X8}", value);
        }

        private static string DecodeFileType(uint value)
        {
            if (Enum.IsDefined(typeof(FileType), value))
            {
                return ((FileType)value).ToString();
            }

            return string.Format("0x{0:X8}", value);
        }

        private static string DecodeFileSubtype(uint fileType, uint subtype)
        {
            if (subtype == 0)
            {
                return string.Empty;
            }

            if (fileType == (uint)FileType.VFT_DRV && Enum.IsDefined(typeof(FileDRVSubtype), subtype))
            {
                return ((FileDRVSubtype)subtype).ToString();
            }

            if (fileType == (uint)FileType.VFT_FONT && Enum.IsDefined(typeof(FileFNTSubtype), subtype))
            {
                return ((FileFNTSubtype)subtype).ToString();
            }

            return string.Format("0x{0:X8}", subtype);
        }

        private static string ResolveCultureNameFromLangId(ushort langId)
        {
            int primary = langId & 0x03FF;
            int sub = (langId >> 10) & 0x003F;

            string primaryName = GetPrimaryLanguageName(primary);
            if (string.IsNullOrWhiteSpace(primaryName))
            {
                return string.Empty;
            }

            string subName = GetSublanguageName(primary, sub);
            if (string.IsNullOrWhiteSpace(subName))
            {
                return primaryName;
            }

            return string.Format("{0} ({1})", primaryName, subName);
        }

        private static string GetPrimaryLanguageName(int primary)
        {
            switch (primary)
            {
                case 0x01: return "Arabic";
                case 0x04: return "Chinese";
                case 0x05: return "Czech";
                case 0x06: return "Danish";
                case 0x07: return "German";
                case 0x08: return "Greek";
                case 0x09: return "English";
                case 0x0A: return "Spanish";
                case 0x0B: return "Finnish";
                case 0x0C: return "French";
                case 0x0D: return "Hebrew";
                case 0x0E: return "Hungarian";
                case 0x0F: return "Icelandic";
                case 0x10: return "Italian";
                case 0x11: return "Japanese";
                case 0x12: return "Korean";
                case 0x13: return "Dutch";
                case 0x14: return "Norwegian";
                case 0x15: return "Polish";
                case 0x16: return "Portuguese";
                case 0x19: return "Russian";
                case 0x1D: return "Swedish";
                default: return string.Empty;
            }
        }

        private static string GetSublanguageName(int primary, int sub)
        {
            switch (primary)
            {
                case 0x09: // English
                    switch (sub)
                    {
                        case 0x01: return "United States";
                        case 0x02: return "United Kingdom";
                        case 0x03: return "Australia";
                        case 0x04: return "Canada";
                        case 0x05: return "New Zealand";
                        case 0x06: return "Ireland";
                        case 0x07: return "South Africa";
                        case 0x08: return "Jamaica";
                        case 0x09: return "Caribbean";
                        case 0x0A: return "Belize";
                        case 0x0B: return "Trinidad";
                        case 0x0C: return "Zimbabwe";
                        case 0x0D: return "Philippines";
                        default: return string.Empty;
                    }
                case 0x07: // German
                    switch (sub)
                    {
                        case 0x01: return "Germany";
                        case 0x02: return "Switzerland";
                        case 0x03: return "Austria";
                        case 0x04: return "Luxembourg";
                        case 0x05: return "Liechtenstein";
                        default: return string.Empty;
                    }
                case 0x0C: // French
                    switch (sub)
                    {
                        case 0x01: return "France";
                        case 0x02: return "Belgium";
                        case 0x03: return "Canada";
                        case 0x04: return "Switzerland";
                        case 0x05: return "Luxembourg";
                        case 0x06: return "Monaco";
                        default: return string.Empty;
                    }
                case 0x16: // Portuguese
                    switch (sub)
                    {
                        case 0x01: return "Brazil";
                        case 0x02: return "Portugal";
                        default: return string.Empty;
                    }
                default:
                    return string.Empty;
            }
        }

        private static bool TryParseLanguageCode(string value, out ushort langId, out ushort codePage)
        {
            langId = 0;
            codePage = 0;
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            int dashIndex = value.IndexOf('-');
            if (dashIndex != 4)
            {
                return false;
            }

            if (value.Length < 9)
            {
                return false;
            }

            string langPart = value.Substring(0, 4);
            string codePart = value.Substring(5, 4);

            if (!ushort.TryParse(langPart, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out langId))
            {
                return false;
            }

            if (!ushort.TryParse(codePart, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out codePage))
            {
                return false;
            }

            if (langId == 0)
            {
                return false;
            }

            return true;
        }

        private void ParseVersionResource(byte[] buffer, int offset)
        {
            if (buffer == null || buffer.Length == 0 || offset < 0 || offset >= buffer.Length)
            {
                return;
            }

            ParseBlock(buffer, offset, buffer.Length, string.Empty, string.Empty);
        }

        private int ParseBlock(byte[] buffer, int offset, int maxOffset, string parentKey, string stringTableKey)
        {
            if (offset + 6 > buffer.Length || offset >= maxOffset)
            {
                return maxOffset;
            }

            ushort wLength = ReadUInt16(buffer, offset);
            ushort wValueLength = ReadUInt16(buffer, offset + 2);
            ushort wType = ReadUInt16(buffer, offset + 4);

            if (wLength < 6)
            {
                return maxOffset;
            }

            int blockEnd = offset + wLength;
            if (blockEnd > maxOffset)
            {
                blockEnd = maxOffset;
            }

            if (blockEnd > buffer.Length)
            {
                blockEnd = buffer.Length;
            }

            int keyOffset = offset + 6;
            string key = ReadUnicodeString(buffer, keyOffset, out int keyBytes);
            int cursor = keyOffset + keyBytes;
            cursor = Align4(cursor);

            string currentTableKey = stringTableKey;
            if (string.Equals(parentKey, "StringFileInfo", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(key))
            {
                currentTableKey = key.Trim();
                if (!_stringTables.ContainsKey(currentTableKey))
                {
                    _stringTables[currentTableKey] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                }
            }

            int valueByteLength = 0;
            if (wValueLength > 0)
            {
                valueByteLength = wType == 1 ? wValueLength * 2 : wValueLength;
            }

            if (valueByteLength > 0 && cursor + valueByteLength <= buffer.Length && cursor + valueByteLength <= blockEnd)
            {
                if (wType == 1)
                {
                    string value = Encoding.Unicode.GetString(buffer, cursor, valueByteLength).TrimEnd('\0');
                    if (!string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(value))
                    {
                        _stringValues[key] = value;
                    }

                    if (!string.IsNullOrWhiteSpace(currentTableKey) &&
                        !string.Equals(parentKey, "StringFileInfo", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(key, "StringFileInfo", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!_stringTables.TryGetValue(currentTableKey, out Dictionary<string, string> table))
                        {
                            table = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                            _stringTables[currentTableKey] = table;
                        }

                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            table[key] = value;
                        }
                    }
                }
                else if (string.Equals(key, "Translation", StringComparison.OrdinalIgnoreCase) && valueByteLength >= 4)
                {
                    int count = valueByteLength / 4;
                    for (int i = 0; i < count; i++)
                    {
                        int entryOffset = cursor + (i * 4);
                        if (entryOffset + 4 > buffer.Length)
                        {
                            break;
                        }

                        uint translation = BitConverter.ToUInt32(buffer, entryOffset);
                        if (translation == 0)
                        {
                            continue;
                        }

                        _translations.Add(translation);
                        if (!_translation.HasValue)
                        {
                            _translation = translation;
                        }
                    }
                }
            }

            cursor += valueByteLength;
            cursor = Align4(cursor);

            while (cursor < blockEnd)
            {
                int next = ParseBlock(buffer, cursor, blockEnd, key, currentTableKey);
                if (next <= cursor)
                {
                    break;
                }

                cursor = next;
            }

            return blockEnd;
        }

        private static ushort ReadUInt16(byte[] buffer, int offset)
        {
            if (offset + 1 >= buffer.Length)
            {
                return 0;
            }

            return (ushort)(buffer[offset] | (buffer[offset + 1] << 8));
        }

        private static string ReadUnicodeString(byte[] buffer, int offset, out int bytesRead)
        {
            StringBuilder sb = new StringBuilder();
            int i = offset;
            while (i + 1 < buffer.Length)
            {
                ushort ch = (ushort)(buffer[i] | (buffer[i + 1] << 8));
                i += 2;
                if (ch == 0)
                {
                    bytesRead = i - offset;
                    return sb.ToString();
                }
                sb.Append((char)ch);
            }

            bytesRead = i - offset;
            return sb.ToString();
        }

        private static int Align4(int value)
        {
            return (value + 3) & ~3;
        }
    }

    public class AnalyzeAssembly
    {
        #region Constructors / Destructors
        public AnalyzeAssembly(byte[] RawData)
        {
            TempAssemblyLoadContext loadContext = new TempAssemblyLoadContext();
            // Constructor          
            try
            {
                AssemblyLoader value = new AssemblyLoader();
                using (MemoryStream ms = new MemoryStream(RawData ?? Array.Empty<byte>(), false))
                {
                    Assembly asm = loadContext.LoadFromStream(ms);
                    value.Load(asm);
                }

                _isDotNetFile = value.IsDotNetFile;
                _isObfuscated = value.IsObfuscated;
                _obfuscationPercentage = value.ObfuscationPercentage;
                _assemblyReferences = new List<string>(value.AssemblyReferences);
                _assemblyReferenceInfos = new List<AssemblyReferenceInfo>(value.AssemblyReferenceInfos);
            }
            catch (Exception)
            {
                //Console.WriteLine("General Exception");
                _obfuscationPercentage = 0.0;
                _isDotNetFile = false;
                _isObfuscated = false;
                _assemblyReferences = new List<string>();
                _assemblyReferenceInfos = new List<AssemblyReferenceInfo>();
            }
            finally
            {
                loadContext.Unload();
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
        }

        public AnalyzeAssembly(Stream stream)
        {
            TempAssemblyLoadContext loadContext = new TempAssemblyLoadContext();
            try
            {
                AssemblyLoader value = new AssemblyLoader();
                Assembly asm = loadContext.LoadFromStream(stream);
                value.Load(asm);

                _isDotNetFile = value.IsDotNetFile;
                _isObfuscated = value.IsObfuscated;
                _obfuscationPercentage = value.ObfuscationPercentage;
                _assemblyReferences = new List<string>(value.AssemblyReferences);
                _assemblyReferenceInfos = new List<AssemblyReferenceInfo>(value.AssemblyReferenceInfos);
            }
            catch (Exception)
            {
                _obfuscationPercentage = 0.0;
                _isDotNetFile = false;
                _isObfuscated = false;
                _assemblyReferences = new List<string>();
                _assemblyReferenceInfos = new List<AssemblyReferenceInfo>();
            }
            finally
            {
                loadContext.Unload();
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
        }

        public AnalyzeAssembly(string filePath)
        {
            TempAssemblyLoadContext loadContext = new TempAssemblyLoadContext();
            try
            {
                AssemblyLoader value = new AssemblyLoader();
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    Assembly asm = loadContext.LoadFromStream(fs);
                    value.Load(asm);
                }

                _isDotNetFile = value.IsDotNetFile;
                _isObfuscated = value.IsObfuscated;
                _obfuscationPercentage = value.ObfuscationPercentage;
                _assemblyReferences = new List<string>(value.AssemblyReferences);
                _assemblyReferenceInfos = new List<AssemblyReferenceInfo>(value.AssemblyReferenceInfos);
            }
            catch (Exception)
            {
                _obfuscationPercentage = 0.0;
                _isDotNetFile = false;
                _isObfuscated = false;
                _assemblyReferences = new List<string>();
                _assemblyReferenceInfos = new List<AssemblyReferenceInfo>();
            }
            finally
            {
                loadContext.Unload();
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
        }

        ~AnalyzeAssembly()
        {
            
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

        private List<string> _assemblyReferences = new List<string>();
        public string[] AssemblyReferences
        {
            get { return _assemblyReferences.ToArray(); }
        }

        private List<AssemblyReferenceInfo> _assemblyReferenceInfos = new List<AssemblyReferenceInfo>();
        public AssemblyReferenceInfo[] AssemblyReferenceInfos
        {
            get { return _assemblyReferenceInfos.ToArray(); }
        }
        #endregion
    }

    [Serializable]
    public class AssemblyLoader
    {
        // This Class runs in its own AppDomain, loads an assembly and analyzes it
        // Afterwards the AppDomain is unloaded.
        // The Class must be marked as [Serializable]!

        private bool _isObfuscated = false;
        public bool IsObfuscated => _isObfuscated;

        private double _obfuscationPercentage;
        public double ObfuscationPercentage => _obfuscationPercentage;

        private bool _isDotNetFile;
        public bool IsDotNetFile => _isDotNetFile;

        private List<AssemblyReferenceInfo> _assemblyReferenceInfos = new List<AssemblyReferenceInfo>();
        public string[] AssemblyReferences => _assemblyReferenceInfos.Select(r => r.Name).ToArray();
        public AssemblyReferenceInfo[] AssemblyReferenceInfos => _assemblyReferenceInfos.ToArray();

        public void Load(Assembly asm)
        {
            try
            {
                _isDotNetFile = true;
                try
                {
                    AssemblyName[] refs = asm.GetReferencedAssemblies();
                    if (refs != null && refs.Length > 0)
                    {
                        foreach (AssemblyName reference in refs)
                        {
                            if (!string.IsNullOrWhiteSpace(reference.Name))
                            {
                                string version = reference.Version != null ? reference.Version.ToString() : string.Empty;
                                _assemblyReferenceInfos.Add(new AssemblyReferenceInfo(reference.Name, version));
                            }
                        }
                    }
                }
                catch (Exception)
                {
                }

                Type[] types = new Type[] { };
                try
                {
                    types = asm.GetTypes();
                }
                catch (ReflectionTypeLoadException ex)
                {
                    // Get the loaded types and ignore the rest
                    types = ex.Types;
                }
                catch (Exception)
                { }

                uint cnt = 0;
                long len = types.LongLength;

                #region Analysis
                foreach (Type t in types)
                {
                    try
                    {

                        if (t != null)
                        {
                            if (t.Name.Length < 2 || t.Name == "DotfuscatorAttribute")
                            {
                                // Type seems to be obfuscated
                                cnt++;
                            }

                            MethodInfo[] methods = t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                            len += methods.LongLength;
                            foreach (MethodInfo m in methods)
                            {
                                try
                                {
                                    if ((m.Name == "$") || (m.Name.Length < 2) || m.Name.Contains("="))
                                    {
                                        //Method seems to be obfuscated
                                        cnt++;
                                    }
                                }
                                catch (Exception)
                                {
                                }
                            }

                            PropertyInfo[] pis = t.GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                            len += pis.LongLength;
                            foreach (PropertyInfo pi in pis)
                            {
                                try
                                {
                                    if ((pi.Name.Length < 2) || pi.Name.Contains("="))
                                    {
                                        // Property seems to be obfuscated
                                        cnt++;
                                    }
                                }
                                catch (Exception)
                                {
                                }
                            }

                            FieldInfo[] fis = t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                            len += fis.LongLength;
                            foreach (FieldInfo fi in fis)
                            {
                                try
                                {
                                    if ((fi.Name.Length < 2) || fi.Name.Contains("="))
                                    {
                                        // Field seems to be obfuscated
                                        cnt++;
                                    }
                                }
                                catch (Exception)
                                {
                                }
                            }
                        }
                    }
                    catch (Exception)
                    {
                    }

                }
                #endregion

                double x = ((double)cnt * 100) / len;


                if (x > 0.0)
                {
                    _isObfuscated = true;
                    _obfuscationPercentage = x;
                }
                else if (Double.IsNaN(x))
                {
                    _obfuscationPercentage = 0.0;
                    _isObfuscated = false;
                }
                else
                {
                    _obfuscationPercentage = x;
                    _isObfuscated = false;
                }
            }
            catch (ReflectionTypeLoadException)
            {
                //Console.WriteLine("ReflectionTypeLoadException");
                _obfuscationPercentage = 0.0;
                _isDotNetFile = false;
                _isObfuscated = false;
                _assemblyReferenceInfos.Clear();
            }
            catch (Exception)
            {
                //Console.WriteLine("General Exception");
                _obfuscationPercentage = 0.0;
                _isDotNetFile = false;
                _isObfuscated = false;
                _assemblyReferenceInfos.Clear();
            }
        }   
    }

    internal sealed class TempAssemblyLoadContext : AssemblyLoadContext
    {
        public TempAssemblyLoadContext() : base(isCollectible: true)
        {
        }
    }
}
