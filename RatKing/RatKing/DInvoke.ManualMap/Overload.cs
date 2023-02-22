using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace DInvoke.ManualMap
{
    public static class Overload
    {
        /// <summary>
        /// Locate a signed module with a minimum size which can be used for overloading.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="minSize">Minimum module byte size.</param>
        /// <param name="legitSigned">Whether to require that the module be legitimately signed.</param>
        /// <returns>
        /// String, the full path for the candidate module if one is found, or an empty string if one is not found.
        /// </returns>
        public static string FindDecoyModule(long minSize, bool legitSigned = true)
        {
            var systemDirectoryPath = Environment.GetEnvironmentVariable("WINDIR") + Path.DirectorySeparatorChar + "System32";
            var files = new List<string>(Directory.GetFiles(systemDirectoryPath, "*.dll"));
            
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (files.Any(s => s.Equals(module.FileName, StringComparison.OrdinalIgnoreCase)))
                    files.RemoveAt(files.FindIndex(x => x.Equals(module.FileName, StringComparison.OrdinalIgnoreCase)));
            }

            var r = new Random();
            var candidates = new List<int>();
            
            while (candidates.Count != files.Count)
            {
                var rInt = r.Next(0, files.Count);
                var currentCandidate = files[rInt];

                if (candidates.Contains(rInt) == false && new FileInfo(currentCandidate).Length >= minSize)
                {
                    if (legitSigned)
                    {
                        if (Utilities.FileHasValidSignature(currentCandidate))
                            return currentCandidate;
                        
                        candidates.Add(rInt);
                    }
                    else
                    {
                        return currentCandidate;
                    }
                }
                
                candidates.Add(rInt);
            }
            
            return string.Empty;
        }

        /// <summary>
        /// Load a signed decoy module into memory, creating legitimate file-backed memory sections within the process. Afterwards overload that
        /// module by manually mapping a payload in it's place causing the payload to execute from what appears to be file-backed memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="payloadPath">Full path to the payload module on disk.</param>
        /// <param name="decoyModulePath">Optional, full path the decoy module to overload in memory.</param>
        /// <param name="legitSigned">Whether to require that the module be legitimately signed.</param>
        /// <returns>PE.PE_MANUAL_MAP</returns>
        public static Data.PE.PE_MANUAL_MAP OverloadModule(string payloadPath, string decoyModulePath = null, bool legitSigned = true)
        {
            if (!File.Exists(payloadPath))
                throw new InvalidOperationException("Payload filepath not found.");
            
            var payload = File.ReadAllBytes(payloadPath);

            return OverloadModule(payload, decoyModulePath, legitSigned);
        }

        /// <summary>
        /// Load a signed decoy module into memory creating legitimate file-backed memory sections within the process. Afterwards overload that
        /// module by manually mapping a payload in it's place causing the payload to execute from what appears to be file-backed memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="payload">Full byte array for the payload module.</param>
        /// <param name="decoyModulePath">Optional, full path the decoy module to overload in memory.</param>
        /// <param name="legitSigned">Whether to require that the module be legitimately signed.</param>
        /// <returns>PE.PE_MANUAL_MAP</returns>
        public static Data.PE.PE_MANUAL_MAP OverloadModule(byte[] payload, string decoyModulePath = null, bool legitSigned = true)
        {
            if (!string.IsNullOrEmpty(decoyModulePath))
            {
                if (!File.Exists(decoyModulePath))
                    throw new InvalidOperationException("Decoy filepath not found.");
                
                var decoyFileBytes = File.ReadAllBytes(decoyModulePath);
                
                if (decoyFileBytes.Length < payload.Length)
                    throw new InvalidOperationException("Decoy module is too small to host the payload.");
            }
            else
            {
                decoyModulePath = FindDecoyModule(payload.Length, legitSigned);
                
                if (string.IsNullOrEmpty(decoyModulePath))
                    throw new InvalidOperationException("Failed to find suitable decoy module.");
            }

            var decoyMetaData = Map.MapModuleFromDiskToSection(decoyModulePath);
            var regionSize = decoyMetaData.PEINFO.Is32Bit ? (IntPtr)decoyMetaData.PEINFO.OptHeader32.SizeOfImage : (IntPtr)decoyMetaData.PEINFO.OptHeader64.SizeOfImage;

            DynamicInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref decoyMetaData.ModuleBase, ref regionSize, Data.Win32.WinNT.PAGE_READWRITE);
            DynamicInvoke.Native.RtlZeroMemory(decoyMetaData.ModuleBase, (int)regionSize);

            var overloadedModuleMetaData = Map.MapModuleToMemory(payload, decoyMetaData.ModuleBase);
            overloadedModuleMetaData.DecoyModule = decoyModulePath;

            return overloadedModuleMetaData;
        }
    }
}