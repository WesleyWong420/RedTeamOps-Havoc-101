// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace DInvoke.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
    /// </summary>
    public static class Native
    {
        public static Data.Native.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            object[] funcargs =
            {
                hProc, baseAddr
            };

            var result = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtUnmapViewOfSection", typeof(Delegates.NtUnmapViewOfSection), ref funcargs);

            return result;
        }



        public static void RtlInitUnicodeString(ref Data.Native.UNICODE_STRING destinationString, [MarshalAs(UnmanagedType.LPWStr)] string sourceString)
        {
            object[] funcargs =
            {
                destinationString, sourceString
            };

            Generic.DynamicApiInvoke("ntdll.dll", "RtlInitUnicodeString", typeof(Delegates.RtlInitUnicodeString), ref funcargs);

            destinationString = (Data.Native.UNICODE_STRING)funcargs[0];
        }

        public static Data.Native.NTSTATUS LdrLoadDll(IntPtr pathToFile, uint dwFlags, ref Data.Native.UNICODE_STRING moduleFileName, ref IntPtr moduleHandle)
        {
            object[] funcargs =
            {
                pathToFile, dwFlags, moduleFileName, moduleHandle
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "LdrLoadDll", typeof(Delegates.LdrLoadDll), ref funcargs);

            moduleHandle = (IntPtr)funcargs[3];

            return retValue;
        }

        public static void RtlZeroMemory(IntPtr destination, int length)
        {
            object[] funcargs =
            {
                destination, length
            };

            Generic.DynamicApiInvoke("ntdll.dll", "RtlZeroMemory", typeof(Delegates.RtlZeroMemory), ref funcargs);
        }

        public static Data.Native.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, Data.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            int processInformationLength;
            uint retLen = 0;

            switch (processInfoClass)
            {
                case Data.Native.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;
                
                case Data.Native.PROCESSINFOCLASS.ProcessBasicInformation:
                    var pbi = new Data.Native.PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(pbi));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(pbi));
                    Marshal.StructureToPtr(pbi, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(pbi);
                    break;
                
                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] funcargs =
            {
                hProcess, processInfoClass, pProcInfo, processInformationLength, retLen
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtQueryInformationProcess", typeof(Delegates.NtQueryInformationProcess), ref funcargs);
            
            if (retValue != Data.Native.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            pProcInfo = (IntPtr)funcargs[2];

            return retValue;
        }

        public static Data.Native.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
        {
            var retValue = NtQueryInformationProcess(hProcess, Data.Native.PROCESSINFOCLASS.ProcessBasicInformation, out var pProcInfo);
            
            if (retValue != Data.Native.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            return (Data.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(Data.Native.PROCESS_BASIC_INFORMATION));
        }

        public static IntPtr LdrGetProcedureAddress(IntPtr hModule, IntPtr functionName, IntPtr ordinal, ref IntPtr functionAddress)
        {
            object[] funcargs =
            {
                hModule, functionName, ordinal, functionAddress
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "LdrGetProcedureAddress", typeof(Delegates.LdrGetProcedureAddress), ref funcargs);
            
            if (retValue != Data.Native.NTSTATUS.Success)
                throw new InvalidOperationException("Failed get procedure address, " + retValue);

            functionAddress = (IntPtr)funcargs[3];
            return functionAddress;
        }

        public static void RtlGetVersion(ref Data.Native.OSVERSIONINFOEX versionInformation)
        {
            object[] funcargs =
            {
                versionInformation
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "RtlGetVersion", typeof(Delegates.RtlGetVersion), ref funcargs);
            
            if (retValue != Data.Native.NTSTATUS.Success)
                throw new InvalidOperationException("Failed get procedure address, " + retValue);

            versionInformation = (Data.Native.OSVERSIONINFOEX)funcargs[0];
        }

        public static IntPtr NtOpenFile(ref IntPtr fileHandle, Data.Win32.Kernel32.FileAccessFlags desiredAccess, ref Data.Native.OBJECT_ATTRIBUTES objectAttributes, ref Data.Native.IO_STATUS_BLOCK ioStatusBlock, Data.Win32.Kernel32.FileShareFlags shareAccess, Data.Win32.Kernel32.FileOpenFlags openOptions)
        {
            object[] funcargs =
            {
                fileHandle, desiredAccess, objectAttributes, ioStatusBlock, shareAccess, openOptions
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke(@"ntdll.dll", @"NtOpenFile", typeof(Delegates.NtOpenFile), ref funcargs);
            
            if (retValue != Data.Native.NTSTATUS.Success)
                throw new InvalidOperationException("Failed to open file, " + retValue);

            fileHandle = (IntPtr)funcargs[0];
            return fileHandle;
        }

        /// <summary>
        /// Holds delegates for API calls in the NT Layer.
        /// Must be public so that they may be used with SharpSploit.Execution.DynamicInvoke.Generic.DynamicFunctionInvoke
        /// </summary>
        /// <example>
        /// 
        /// // These delegates may also be used directly.
        ///
        /// // Get a pointer to the NtCreateThreadEx function.
        /// IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");
        /// 
        /// //  Create an instance of a NtCreateThreadEx delegate from our function pointer.
        /// DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
        ///    pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));
        ///
        /// //  Invoke NtCreateThreadEx using the delegate
        /// createThread(ref threadHandle, Data.Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Data.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
        ///     procHandle, startAddress, IntPtr.Zero, Data.Native.NT_CREATION_FLAGS.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
        /// 
        /// </example>
        private struct Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtUnmapViewOfSection(
                IntPtr hProc,
                IntPtr baseAddr);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint LdrLoadDll(
                IntPtr pathToFile,
                uint dwFlags,
                ref Data.Native.UNICODE_STRING moduleFileName,
                ref IntPtr moduleHandle);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlInitUnicodeString(
                ref Data.Native.UNICODE_STRING destinationString,
                [MarshalAs(UnmanagedType.LPWStr)]
                string sourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlZeroMemory(
                IntPtr destination,
                int length);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtQueryInformationProcess(
                IntPtr processHandle,
                Data.Native.PROCESSINFOCLASS processInformationClass,
                IntPtr processInformation,
                int processInformationLength,
                ref uint returnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint LdrGetProcedureAddress(
                IntPtr hModule,
                IntPtr functionName,
                IntPtr ordinal,
                ref IntPtr functionAddress);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint RtlGetVersion(
                ref Data.Native.OSVERSIONINFOEX versionInformation);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtOpenFile(
                ref IntPtr fileHandle,
                Data.Win32.Kernel32.FileAccessFlags accessFlags,
                ref Data.Native.OBJECT_ATTRIBUTES objectAttributes,
                ref Data.Native.IO_STATUS_BLOCK ioStatusBlock,
                Data.Win32.Kernel32.FileShareFlags shareAccess,
                Data.Win32.Kernel32.FileOpenFlags openOptions);
        }
    }
}