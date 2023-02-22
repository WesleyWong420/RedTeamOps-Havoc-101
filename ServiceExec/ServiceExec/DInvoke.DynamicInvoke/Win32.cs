// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace DInvoke.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking Win32 API Calls.
    /// </summary>
    public static class Win32
    {
        /// <summary>
        /// Uses DynamicInvocation to call the CloseHandle Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
        /// </summary>
        /// <returns></returns>
        public static bool CloseHandle(IntPtr handle)
        {
            object[] funcargs =
            {
                handle
            };

            var retVal = (bool)Generic.DynamicApiInvoke("kernel32.dll", "CloseHandle", typeof(Delegates.CloseHandle), ref funcargs);

            return retVal;
        }

        private struct Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool CloseHandle(IntPtr hProcess);
        }
    }
}