using System;
using System.Runtime.InteropServices;
using static CS_Unhook.Imports;

namespace CS_Unhook
{
    class Program
    {
        static void Unhook()
        {
            IntPtr currentProcessHandle = GetCurrentProcess();
            MODULEINFO modInfo = new MODULEINFO();
            IntPtr dllHandle = GetModuleHandle("ntdll.dll");
            GetModuleInformation(currentProcessHandle, dllHandle, out modInfo, (uint)Marshal.SizeOf(modInfo));
            IntPtr dllBase = modInfo.lpBaseOfDll;
            string ntdll = "C:\\Windows\\System32\\ntdll.dll";
            IntPtr ntdllHandle = CreateFileA(ntdll, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            IntPtr ntdllMapping = CreateFileMapping(ntdllHandle, IntPtr.Zero, PageProtection.Readonly | PageProtection.SectionImage, 0, 0, null);
            IntPtr ntdllMmapped = MapViewOfFile(ntdllMapping, FileMapAccessType.Read, 0, 0, IntPtr.Zero);

            IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(dllBase, typeof(IMAGE_DOS_HEADER));
            IntPtr ptrtoNTHeader = (dllBase + dosHeader.e_lfanew);
            IMAGE_NT_HEADERS64 ntHeader = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrtoNTHeader, typeof(IMAGE_NT_HEADERS64));
            try
            {
                Console.WriteLine("[+] About to start Unhooking process...");
                for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++)
                {
                    IntPtr ptrtoSectionHeader = (ptrtoNTHeader + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));
                    IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((ptrtoSectionHeader + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)))), typeof(IMAGE_SECTION_HEADER));
                    string sectionName = new string(sectionHeader.Name);

                    if (sectionName.Contains(".text"))
                    {
                        uint oldProtect = 0;
                        IntPtr oldAddress = IntPtr.Add(dllBase, (int)sectionHeader.VirtualAddress);
                        IntPtr newAddress = IntPtr.Add(ntdllMmapped, (int)sectionHeader.VirtualAddress);
                        int vProtect = VirtualProtect(oldAddress, sectionHeader.VirtualSize, 0x40, out oldProtect);
                        memcpy(oldAddress, newAddress, sectionHeader.VirtualSize);
                        vProtect = VirtualProtect(oldAddress, sectionHeader.VirtualSize, oldProtect, out oldProtect);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            Console.WriteLine("[*] Unhooking completed. Press any key to exit...");
            Console.ReadKey();
        }

        static void Main(string[] args)
        {
            Unhook();
        }
    }
}
