using System;
using System.Runtime.InteropServices;

namespace CS_Unhook
{
    internal class Imports
    {
        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo,
            uint cb);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileA(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpFileMappingAttributes,
            PageProtection flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, FileMapAccessType dwDesiredAccess,
            UInt32 dwFileOffsetHigh, UInt32 dwFileOffsetLow, IntPtr dwNumberOfBytesToMap);

        [DllImport("kernel32.dll")]
        public static extern int VirtualProtect(IntPtr lpAddress, UInt32 dwSize, uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("msvcrt.dll",
            SetLastError = false)]
        public static extern IntPtr memcpy(IntPtr dest, IntPtr src, UInt32 count);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);

        public const uint GENERIC_READ = 0x80000000;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_SHARE_READ = 0x00000001;

        public enum FileMapAccessType : uint
        {
            Read = 0x04
        }

        [Flags]
        public enum PageProtection : uint
        {
            Readonly = 0x02,
            SectionImage = 0x1000000,
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)] public UInt32 VirtualSize;
            [FieldOffset(12)] public UInt32 VirtualAddress;
            [FieldOffset(16)] public UInt32 SizeOfRawData;
            [FieldOffset(20)] public UInt32 PointerToRawData;
            [FieldOffset(24)] public UInt32 PointerToRelocations;
            [FieldOffset(28)] public UInt32 PointerToLinenumbers;
            [FieldOffset(32)] public UInt16 NumberOfRelocations;
            [FieldOffset(34)] public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)] public UInt32 Characteristics;

            public string Section
            {

                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic; // Magic number

            public UInt16 e_cblp; // Bytes on last page of file
            public UInt16 e_cp; // Pages in file
            public UInt16 e_crlc; // Relocations
            public UInt16 e_cparhdr; // Size of header in paragraphs
            public UInt16 e_minalloc; // Minimum extra paragraphs needed
            public UInt16 e_maxalloc; // Maximum extra paragraphs needed
            public UInt16 e_ss; // Initial (relative) SS value
            public UInt16 e_sp; // Initial SP value
            public UInt16 e_csum; // Checksum
            public UInt16 e_ip; // Initial IP value
            public UInt16 e_cs; // Initial (relative) CS value
            public UInt16 e_lfarlc; // File address of relocation table
            public UInt16 e_ovno; // Overlay number

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1; // Reserved words

            public UInt16 e_oemid; // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo; // OEM information; e_oemid specific

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2; // Reserved words

            public Int32 e_lfanew; // File address of new exe header

            private string _e_magic
            {
                get { return new string(e_magic); }
            }

            public bool isValid
            {
                get { return _e_magic == "MZ"; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            [FieldOffset(0)] public UInt32 Signature;

            [FieldOffset(4)] public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)] public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)] public MagicType Magic;

            [FieldOffset(2)] public byte MajorLinkerVersion;

            [FieldOffset(3)] public byte MinorLinkerVersion;

            [FieldOffset(4)] public uint SizeOfCode;

            [FieldOffset(8)] public uint SizeOfInitializedData;

            [FieldOffset(12)] public uint SizeOfUninitializedData;

            [FieldOffset(16)] public uint AddressOfEntryPoint;

            [FieldOffset(20)] public uint BaseOfCode;

            [FieldOffset(24)] public ulong ImageBase;

            [FieldOffset(32)] public uint SectionAlignment;

            [FieldOffset(36)] public uint FileAlignment;

            [FieldOffset(40)] public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)] public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)] public ushort MajorImageVersion;

            [FieldOffset(46)] public ushort MinorImageVersion;

            [FieldOffset(48)] public ushort MajorSubsystemVersion;

            [FieldOffset(50)] public ushort MinorSubsystemVersion;

            [FieldOffset(52)] public uint Win32VersionValue;

            [FieldOffset(56)] public uint SizeOfImage;

            [FieldOffset(60)] public uint SizeOfHeaders;

            [FieldOffset(64)] public uint CheckSum;

            [FieldOffset(68)] public SubSystemType Subsystem;

            [FieldOffset(70)] public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)] public ulong SizeOfStackReserve;

            [FieldOffset(80)] public ulong SizeOfStackCommit;

            [FieldOffset(88)] public ulong SizeOfHeapReserve;

            [FieldOffset(96)] public ulong SizeOfHeapCommit;

            [FieldOffset(104)] public uint LoaderFlags;

            [FieldOffset(108)] public uint NumberOfRvaAndSizes;

            [FieldOffset(112)] public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)] public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)] public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)] public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)] public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)] public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)] public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)] public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)] public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)] public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)] public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)] public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)] public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)] public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        public enum SubSystemType : ushort
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

        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

    }
}
