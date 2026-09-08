using System;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>
    /// Transparent Win32/NT P/Invoke surface for EDR process inspection.
    ///
    /// v2.3.6 lesson (Kaspersky): split-string / GetProcAddress "hiding" of API names is
    /// scored as evasion by ML engines and is worse than a normal import table.
    /// v2.3.8: plain [DllImport] declarations — auditable, no dynamic resolution.
    /// Authenticode signing remains the path to near-zero VirusTotal detections.
    /// </summary>
    internal static class NativeResolver
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out NativeProcessMemory.MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
            int dwDesiredAccess, bool bInheritHandle, int dwOptions);

        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(int systemInformationClass,
            IntPtr systemInformation, int systemInformationLength, out int returnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryObject(IntPtr handle, int infoClass,
            IntPtr buffer, int bufferSize, out int returnLength);

        [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
        private static extern int NtQueryInformationProcessNative(IntPtr processHandle,
            int processInformationClass, IntPtr processInformation,
            int processInformationLength, out int returnLength);

        /// <summary>
        /// Calls NtQueryInformationProcess with a pinned struct buffer.
        /// </summary>
        public static int NtQueryInformationProcess<T>(IntPtr processHandle, int infoClass, ref T info, out int returnLength)
            where T : struct
        {
            int size = Marshal.SizeOf<T>();
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(info, buffer, false);
                int status = NtQueryInformationProcessNative(processHandle, infoClass, buffer, size, out returnLength);
                if (status == 0)
                    info = Marshal.PtrToStructure<T>(buffer);
                return status;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
