using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Mono.Options;

namespace SylantStrikeInject {

    class Program
    {
        private static List<string> processList = new List<string>();
        private static string dllPath;

        static void Main(string[] args)
        {

            RunThisAsAdmin(string.Join(" ", args));

            OptionSet option_set = new OptionSet()
            {
                {"p=|process=", "Process name to protect with CylantStrike", v => { processList.Add(v.ToLower()); }},
                {"d=|dll=", "Path to CylantStrike protection DLL", v => { dllPath = v; }}
            };

            try
            {
                option_set.Parse(args);

                new Thread(WaitForProcess) {IsBackground = true, Name = "worker"}.Start();
                Console.WriteLine("Waiting for process events");
                do
                {
                    Thread.Sleep(5000);
                } while (true);

            }
            catch (Exception e)
            {
                Console.WriteLine($"Failed to setup injector ${e.Message}");
            }
        }

        private static void RunThisAsAdmin(string args)
        {
            if (!IsAdministrator())
            {
                var exe = Process.GetCurrentProcess().MainModule.FileName;
                var startInfo = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Normal,
                    CreateNoWindow = false,

                };
                Process.Start(startInfo);
                Process.GetCurrentProcess().Kill();
            }
        }

        private static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void WaitForProcess()
        {
            try
            {
                var startWatch = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
                startWatch.EventArrived += new EventArrivedEventHandler(startWatch_EventArrived);
                startWatch.Start();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"+ Listening for the following processes: {string.Join(" ", processList)}\n");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(ex);
            }
        }

        static void startWatch_EventArrived(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var proc = GetProcessInfo(e);
                if (processList.Contains(proc.ProcessName.ToLower()))
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($" Injecting process {proc.ProcessName}({proc.PID}) with DLL {dllPath}");
                    BasicInject.Inject(proc.PID, dllPath);
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(ex);
            }
        }

        static ProcessInfo GetProcessInfo(EventArrivedEventArgs e)
        {
            var p = new ProcessInfo();
            var pid = 0;
            int.TryParse(e.NewEvent.Properties["ProcessID"].Value.ToString(), out pid);
            p.PID = pid;
            p.ProcessName = e.NewEvent.Properties["ProcessName"].Value.ToString();
            return p;
        }

        internal class ProcessInfo
        {
            public string ProcessName { get; set; }
            public int PID { get; set; }
        }
    }
}
