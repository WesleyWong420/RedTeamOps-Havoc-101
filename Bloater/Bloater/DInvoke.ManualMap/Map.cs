using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

using DInvoke.DynamicInvoke;

namespace DInvoke.ManualMap
{
    /// <summary>
    /// Class for manually mapping PEs.
    /// </summary>
    public static class Map
    {
        /// <summary>
        /// Maps a DLL from disk into a Section using NtCreateSection.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="dllPath">Full path fo the DLL on disk.</param>
        /// <returns>PE.PE_MANUAL_MAP</returns>
        public static Data.PE.PE_MANUAL_MAP MapModuleFromDiskToSection(string dllPath)
        {
            if (!File.Exists(dllPath))
                throw new InvalidOperationException("Filepath not found.");

            var objectName = new Data.Native.UNICODE_STRING();
            Native.RtlInitUnicodeString(ref objectName, @"\??\" + dllPath);
            
            var pObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(objectName));
            Marshal.StructureToPtr(objectName, pObjectName, true);

            var objectAttributes = new Data.Native.OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf(objectAttributes);
            objectAttributes.ObjectName = pObjectName;
            objectAttributes.Attributes = 0x40;

            var ioStatusBlock = new Data.Native.IO_STATUS_BLOCK();

            var hFile = IntPtr.Zero;
            
            Native.NtOpenFile(
                ref hFile,
                Data.Win32.Kernel32.FileAccessFlags.FILE_READ_DATA |
                Data.Win32.Kernel32.FileAccessFlags.FILE_EXECUTE |
                Data.Win32.Kernel32.FileAccessFlags.FILE_READ_ATTRIBUTES |
                Data.Win32.Kernel32.FileAccessFlags.SYNCHRONIZE,
                ref objectAttributes, ref ioStatusBlock,
                Data.Win32.Kernel32.FileShareFlags.FILE_SHARE_READ |
                Data.Win32.Kernel32.FileShareFlags.FILE_SHARE_DELETE,
                Data.Win32.Kernel32.FileOpenFlags.FILE_SYNCHRONOUS_IO_NONALERT |
                Data.Win32.Kernel32.FileOpenFlags.FILE_NON_DIRECTORY_FILE
            );

            var hSection = IntPtr.Zero;
            ulong maxSize = 0;
            
            var ret = Native.NtCreateSection(
                ref hSection,
                (uint)Data.Win32.WinNT.ACCESS_MASK.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref maxSize,
                Data.Win32.WinNT.PAGE_READONLY,
                Data.Win32.WinNT.SEC_IMAGE,
                hFile
            );

            var pBaseAddress = IntPtr.Zero;
            
            Native.NtMapViewOfSection(
                hSection, (IntPtr)(-1), ref pBaseAddress,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                ref maxSize, 0x2, 0x0,
                Data.Win32.WinNT.PAGE_READWRITE
            );

            var secMapObject = new Data.PE.PE_MANUAL_MAP
            {
                PEINFO = Generic.GetPeMetaData(pBaseAddress),
                ModuleBase = pBaseAddress
            };

            Win32.CloseHandle(hFile);

            return secMapObject;
        }

        /// <summary>
        /// Allocate file to memory from disk
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="filePath">Full path to the file to be alloacted.</param>
        /// <returns>IntPtr base address of the allocated file.</returns>
        public static IntPtr AllocateFileToMemory(string filePath)
        {
            if (!File.Exists(filePath))
                throw new InvalidOperationException("Filepath not found.");

            var bFile = File.ReadAllBytes(filePath);
            return AllocateBytesToMemory(bFile);
        }

        /// <summary>
        /// Allocate a byte array to memory
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="fileBytes">Byte array to be allocated.</param>
        /// <returns>IntPtr base address of the allocated file.</returns>
        public static IntPtr AllocateBytesToMemory(byte[] fileBytes)
        {
            var pFile = Marshal.AllocHGlobal(fileBytes.Length);
            Marshal.Copy(fileBytes, 0, pFile, fileBytes.Length);
            return pFile;
        }

        /// <summary>
        /// Relocates a module in memory.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="peMetaData">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="moduleMemoryBase">Base address of the module in memory.</param>
        /// <returns>void</returns>
        public static void RelocateModule(Data.PE.PE_META_DATA peMetaData, IntPtr moduleMemoryBase)
        {
            var idd = peMetaData.Is32Bit ? peMetaData.OptHeader32.BaseRelocationTable : peMetaData.OptHeader64.BaseRelocationTable;
            var imageDelta = peMetaData.Is32Bit ? (long)((ulong)moduleMemoryBase - peMetaData.OptHeader32.ImageBase) :
                                                (long)((ulong)moduleMemoryBase - peMetaData.OptHeader64.ImageBase);

            var pRelocTable = (IntPtr)((ulong)moduleMemoryBase + idd.VirtualAddress);
            var nextRelocTableBlock = -1;

            while (nextRelocTableBlock != 0)
            {
                var ibr = new Data.PE.IMAGE_BASE_RELOCATION();
                ibr = (Data.PE.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocTable, typeof(Data.PE.IMAGE_BASE_RELOCATION));

                var relocCount = (ibr.SizeOfBlock - Marshal.SizeOf(ibr)) / 2;
                
                for (var i = 0; i < relocCount; i++)
                {
                    var pRelocEntry = (IntPtr)((ulong)pRelocTable + (ulong)Marshal.SizeOf(ibr) + (ulong)(i * 2));
                    var relocValue = (ushort)Marshal.ReadInt16(pRelocEntry);

                    var relocType = (ushort)(relocValue >> 12);
                    var relocPatch = (ushort)(relocValue & 0xfff);

                    if (relocType == 0) continue;
                    
                    try
                    {
                        var pPatch = (IntPtr)((ulong)moduleMemoryBase + ibr.VirtualAdress + relocPatch);
                        if (relocType == 0x3)
                        {
                            var originalPtr = Marshal.ReadInt32(pPatch);
                            Marshal.WriteInt32(pPatch, originalPtr + (int)imageDelta);
                        }
                        else
                        {
                            var originalPtr = Marshal.ReadInt64(pPatch);
                            Marshal.WriteInt64(pPatch, originalPtr + imageDelta);
                        }
                    }
                    catch
                    {
                        throw new InvalidOperationException("Memory access violation.");
                    }
                }

                pRelocTable = (IntPtr)((ulong)pRelocTable + ibr.SizeOfBlock);
                nextRelocTableBlock = Marshal.ReadInt32(pRelocTable);
            }
        }

        /// <summary>
        /// Rewrite IAT for manually mapped module.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="peMetaData">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="moduleMemoryBase">Base address of the module in memory.</param>
        /// <returns>void</returns>
        public static void RewriteModuleIAT(Data.PE.PE_META_DATA peMetaData, IntPtr moduleMemoryBase)
        {
            var idd = peMetaData.Is32Bit ? peMetaData.OptHeader32.ImportTable : peMetaData.OptHeader64.ImportTable;

            if (idd.VirtualAddress == 0)
                return;

            var pImportTable = (IntPtr)((ulong)moduleMemoryBase + idd.VirtualAddress);

            var osVersion = new Data.Native.OSVERSIONINFOEX();
            Native.RtlGetVersion(ref osVersion);
            
            var apiSetDict = new Dictionary<string, string>();
            
            if (osVersion.MajorVersion >= 10)
                apiSetDict = Generic.GetApiSetMapping();

            var counter = 0;
            var iid = new Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR();
            iid = (Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                (IntPtr)((ulong)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                typeof(Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
            );

            while (iid.Name != 0)
            {
                var dllName = string.Empty;

                try
                {
                    dllName = Marshal.PtrToStringAnsi((IntPtr)((ulong)moduleMemoryBase + iid.Name));
                }
                catch
                {
                    // ignore
                }

                if (dllName == string.Empty)
                    throw new InvalidOperationException("Failed to read DLL name.");


                var lookupKey = dllName!.Substring(0, dllName.Length - 6) + ".dll";
                
                if (osVersion.MajorVersion >= 10 && (dllName.StartsWith("api-") || dllName.StartsWith("ext-")) &&
                    apiSetDict.ContainsKey(lookupKey) && apiSetDict[lookupKey].Length > 0)
                {
                    dllName = apiSetDict[lookupKey];
                }

                var hModule = Generic.GetLoadedModuleAddress(dllName);
                
                if (hModule == IntPtr.Zero)
                {
                    hModule = Generic.LoadModuleFromDisk(dllName);
                    
                    if (hModule == IntPtr.Zero)
                        throw new FileNotFoundException(dllName + ", unable to find the specified file.");
                }

                if (peMetaData.Is32Bit)
                {
                    var oft_itd = new Data.PE.IMAGE_THUNK_DATA32();
                    for (var i = 0;; i++)
                    {
                        oft_itd = (Data.PE.IMAGE_THUNK_DATA32)Marshal.PtrToStructure(
                            (IntPtr)((ulong)moduleMemoryBase + iid.OriginalFirstThunk + (uint)(i * sizeof(uint))),
                            typeof(Data.PE.IMAGE_THUNK_DATA32));
                        
                        var ft_itd = (IntPtr)((ulong)moduleMemoryBase + iid.FirstThunk + (ulong)(i * sizeof(uint)));
                        
                        if (oft_itd.AddressOfData == 0)
                            break;

                        if (oft_itd.AddressOfData < 0x80000000)
                        {
                            var pImpByName = (IntPtr)((ulong)moduleMemoryBase + oft_itd.AddressOfData + sizeof(ushort));
                            var pFunc = IntPtr.Zero;
                            
                            pFunc = Generic.GetNativeExportAddress(hModule,
                                Marshal.PtrToStringAnsi(pImpByName));

                            Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                        }
                        else
                        {
                            ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                            
                            var pFunc = IntPtr.Zero;
                            pFunc = Generic.GetNativeExportAddress(hModule, (short)fOrdinal);

                            Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                        }
                    }
                }
                else
                {
                    var oft_itd = new Data.PE.IMAGE_THUNK_DATA64();
                    
                    for (var i = 0;; i++)
                    {
                        oft_itd = (Data.PE.IMAGE_THUNK_DATA64)Marshal.PtrToStructure(
                            (IntPtr)((ulong)moduleMemoryBase + iid.OriginalFirstThunk + (ulong)(i * sizeof(ulong))),
                            typeof(Data.PE.IMAGE_THUNK_DATA64));
                        
                        var ft_itd = (IntPtr)((ulong)moduleMemoryBase + iid.FirstThunk + (ulong)(i * sizeof(ulong)));
                        
                        if (oft_itd.AddressOfData == 0)
                            break;

                        if (oft_itd.AddressOfData < 0x8000000000000000) // !IMAGE_ORDINAL_FLAG64
                        {
                            var pImpByName = (IntPtr)((ulong)moduleMemoryBase + oft_itd.AddressOfData + sizeof(ushort));
                            var pFunc = IntPtr.Zero;
                            
                            pFunc = Generic.GetNativeExportAddress(hModule,
                                Marshal.PtrToStringAnsi(pImpByName));

                            Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                        }
                        else
                        {
                            var fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                            
                            var pFunc = IntPtr.Zero;
                            pFunc = Generic.GetNativeExportAddress(hModule, (short)fOrdinal);

                            Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                        }
                    }
                }

                counter++;
                
                iid = (Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                    (IntPtr)((ulong)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                    typeof(Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
                );
            }
        }

        /// <summary>
        /// Set correct module section permissions.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="peMetaData">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="moduleMemoryBase">Base address of the module in memory.</param>
        /// <returns>void</returns>
        public static void SetModuleSectionPermissions(Data.PE.PE_META_DATA peMetaData, IntPtr moduleMemoryBase)
        {
            var baseOfCode = peMetaData.Is32Bit ? (IntPtr)peMetaData.OptHeader32.BaseOfCode : (IntPtr)peMetaData.OptHeader64.BaseOfCode;
            Native.NtProtectVirtualMemory((IntPtr)(-1), ref moduleMemoryBase, ref baseOfCode, Data.Win32.WinNT.PAGE_READONLY);

            foreach (var ish in peMetaData.Sections)
            {
                var isRead = (ish.Characteristics & Data.PE.DataSectionFlags.MEM_READ) != 0;
                var isWrite = (ish.Characteristics & Data.PE.DataSectionFlags.MEM_WRITE) != 0;
                var isExecute = (ish.Characteristics & Data.PE.DataSectionFlags.MEM_EXECUTE) != 0;
                
                uint flNewProtect = 0;
                
                if (isRead & !isWrite & !isExecute)
                    flNewProtect = Data.Win32.WinNT.PAGE_READONLY;
                else if (isRead & isWrite & !isExecute)
                    flNewProtect = Data.Win32.WinNT.PAGE_READWRITE;
                else if (isRead & isWrite & isExecute)
                    flNewProtect = Data.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                else if (isRead & !isWrite & isExecute)
                    flNewProtect = Data.Win32.WinNT.PAGE_EXECUTE_READ;
                else if (!isRead & !isWrite & isExecute)
                    flNewProtect = Data.Win32.WinNT.PAGE_EXECUTE;
                else
                    throw new InvalidOperationException("Unknown section flag, " + ish.Characteristics);

                var pVirtualSectionBase = (IntPtr)((ulong)moduleMemoryBase + ish.VirtualAddress);
                var protectSize = (IntPtr)ish.VirtualSize;

                Native.NtProtectVirtualMemory((IntPtr)(-1), ref pVirtualSectionBase, ref protectSize, flNewProtect);
            }
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="modulePath">Full path to the module on disk.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(string modulePath)
        {
            var pModule = AllocateFileToMemory(modulePath);
            return MapModuleToMemory(pModule);
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="module">Full byte array of the module.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(byte[] module)
        {
            var pModule = AllocateBytesToMemory(module);
            return MapModuleToMemory(pModule);
        }

        /// <summary>
        /// Manually map module into current process starting at the specified base address.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="module">Full byte array of the module.</param>
        /// <param name="pImage">Address in memory to map module to.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(byte[] module, IntPtr pImage)
        {
            var pModule = AllocateBytesToMemory(module);
            return MapModuleToMemory(pModule, pImage);
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="pModule">Pointer to the module base.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule)
        {
            var peMetaData = Generic.GetPeMetaData(pModule);

            if (peMetaData.Is32Bit && IntPtr.Size == 8 || !peMetaData.Is32Bit && IntPtr.Size == 4)
            {
                Marshal.FreeHGlobal(pModule);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            var baseAddress = IntPtr.Zero;
            var regionSize = peMetaData.Is32Bit ? (IntPtr)peMetaData.OptHeader32.SizeOfImage : (IntPtr)peMetaData.OptHeader64.SizeOfImage;
            var pImage = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );
            
            return MapModuleToMemory(pModule, pImage, peMetaData);
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="pModule">Pointer to the module base.</param>
        /// <param name="pImage">Pointer to the PEINFO image.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage)
        {
            var peMetaData = Generic.GetPeMetaData(pModule);
            return MapModuleToMemory(pModule, pImage, peMetaData);
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="pModule">Pointer to the module base.</param>
        /// <param name="pImage">Pointer to the PEINFO image.</param>
        /// <param name="peMetaData">PE_META_DATA of the module being mapped.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage, Data.PE.PE_META_DATA peMetaData)
        {
            if (peMetaData.Is32Bit && IntPtr.Size == 8 || !peMetaData.Is32Bit && IntPtr.Size == 4)
            {
                Marshal.FreeHGlobal(pModule);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            var sizeOfHeaders = peMetaData.Is32Bit ? peMetaData.OptHeader32.SizeOfHeaders : peMetaData.OptHeader64.SizeOfHeaders;
            var bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, sizeOfHeaders);

            foreach (var ish in peMetaData.Sections)
            {
                var pVirtualSectionBase = (IntPtr)((ulong)pImage + ish.VirtualAddress);
                var pRawSectionBase = (IntPtr)((ulong)pModule + ish.PointerToRawData);

                bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                
                if (bytesWritten != ish.SizeOfRawData)
                    throw new InvalidOperationException("Failed to write to memory.");
            }

            RelocateModule(peMetaData, pImage);
            RewriteModuleIAT(peMetaData, pImage);
            SetModuleSectionPermissions(peMetaData, pImage);

            Marshal.FreeHGlobal(pModule);

            return new Data.PE.PE_MANUAL_MAP
            {
                ModuleBase = pImage,
                PEINFO = peMetaData
            };
        }

        /// <summary>
        /// Free a module that was mapped into the current process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="peManualMap">The metadata of the manually mapped module.</param>
        public static void FreeModule(Data.PE.PE_MANUAL_MAP peManualMap)
        {
            // Check if PE was mapped via module overloading
            if (!string.IsNullOrEmpty(peManualMap.DecoyModule))
            {
                Native.NtUnmapViewOfSection((IntPtr)(-1), peManualMap.ModuleBase);
            }
            else
            {
                var peMetaData = peManualMap.PEINFO;

                var size = peMetaData.Is32Bit ? (IntPtr)peMetaData.OptHeader32.SizeOfImage : (IntPtr)peMetaData.OptHeader64.SizeOfImage;
                var pModule = peManualMap.ModuleBase;

                Native.NtFreeVirtualMemory((IntPtr)(-1), ref pModule, ref size, Data.Win32.Kernel32.MEM_RELEASE);
            }
        }
        
                /// <summary>
        /// Read ntdll from disk, find/copy the appropriate syscall stub and free ntdll.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="functionName">The name of the function to search for (e.g. "NtAlertResumeThread").</param>
        /// <returns>IntPtr, Syscall stub</returns>
        public static IntPtr GetSyscallStub(string functionName)
        {
            var isWow64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            
            if (IntPtr.Size == 4 && isWow64)
                throw new InvalidOperationException("Generating Syscall stubs is not supported for WOW64.");

            var ntdllPath = string.Empty;
            var procModules = Process.GetCurrentProcess().Modules;
            
            foreach (ProcessModule module in procModules)
            {
                if (!module.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase)) continue;
                
                ntdllPath = module.FileName;
                break;
            }

            var pModule = AllocateFileToMemory(ntdllPath);
            var peMetaData = Generic.GetPeMetaData(pModule);

            var baseAddress = IntPtr.Zero;
            var regionSize = peMetaData.Is32Bit ? (IntPtr)peMetaData.OptHeader32.SizeOfImage : (IntPtr)peMetaData.OptHeader64.SizeOfImage;
            var sizeOfHeaders = peMetaData.Is32Bit ? peMetaData.OptHeader32.SizeOfHeaders : peMetaData.OptHeader64.SizeOfHeaders;

            var pImage = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );

            var bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, sizeOfHeaders);

            foreach (var ish in peMetaData.Sections)
            {
                var pVirtualSectionBase = (IntPtr)((ulong)pImage + ish.VirtualAddress);
                var pRawSectionBase = (IntPtr)((ulong)pModule + ish.PointerToRawData);

                bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                
                if (bytesWritten != ish.SizeOfRawData)
                    throw new InvalidOperationException("Failed to write to memory.");
            }

            var pFunc = Generic.GetExportAddress(pImage, functionName);
            
            if (pFunc == IntPtr.Zero)
                throw new InvalidOperationException("Failed to resolve ntdll export.");

            baseAddress = IntPtr.Zero;
            regionSize = (IntPtr)0x50;
            
            var pCallStub = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );

            bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pCallStub, pFunc, 0x50);
            
            if (bytesWritten != 0x50)
                throw new InvalidOperationException("Failed to write to memory.");

            Native.NtProtectVirtualMemory((IntPtr)(-1), ref pCallStub, ref regionSize, Data.Win32.WinNT.PAGE_EXECUTE_READ);
            
            Marshal.FreeHGlobal(pModule);
            regionSize = peMetaData.Is32Bit ? (IntPtr)peMetaData.OptHeader32.SizeOfImage : (IntPtr)peMetaData.OptHeader64.SizeOfImage;

            Native.NtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref regionSize, Data.Win32.Kernel32.MEM_RELEASE);

            return pCallStub;
        }
    }
}