using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>
    /// Remote process inspection primitives used by the EDR engine.
    /// Standard read-only inspection and handle operations — transparent to AV scanners.
    /// </summary>
    internal static class NativeProcessMemory
    {
        public const uint AccessQuery = 0x0400;
        public const uint AccessQueryLimited = 0x1000;
        public const uint AccessVmRead = 0x0010;
        public const uint StateCommit = 0x1000;
        public const uint TypeImage = 0x1000000;
        public const uint ProtX = 0x10;
        public const uint ProtRX = 0x20;
        public const uint ProtRWX = 0x40;
        public const uint ProtXwc = 0x80;

        // Legacy aliases used by call sites
        public const uint PROCESS_QUERY_INFORMATION = AccessQuery;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = AccessQueryLimited;
        public const uint PROCESS_VM_READ = AccessVmRead;
        public const uint MEM_COMMIT = StateCommit;
        public const uint MEM_IMAGE = TypeImage;
        public const uint PAGE_EXECUTE = ProtX;
        public const uint PAGE_EXECUTE_READ = ProtRX;
        public const uint PAGE_EXECUTE_READWRITE = ProtRWX;
        public const uint PAGE_EXECUTE_WRITECOPY = ProtXwc;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        // CloseHandle stays here; process-inspection APIs go through NativeResolver
        // (plain [DllImport] — no GetProcAddress hiding; see NativeResolver remarks).

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public static bool CanInspect(int pid, string? imagePath = null)
        {
            if (pid <= 4) return false;
            // Name-first: Denuvo titles self-terminate on VM_READ even when path resolve races.
            if (SecurityValidation.IsGameOrAntiCheatProcess(pid, imagePath))
                return false;
            imagePath ??= SecurityValidation.GetProcessImagePath(pid);
            // Fail closed: unresolved path → no VM_READ (PPL / anti-cheat / startup race).
            // Prefer missing a scan over killing interactive games.
            if (string.IsNullOrEmpty(imagePath))
                return false;
            return !SecurityValidation.IsGameOrAntiCheatPath(imagePath);
        }

        public static IntPtr OpenRemoteHandle(uint access, int pid)
        {
            // Central gate: never grant VM_READ to game / unresolved PIDs.
            if ((access & AccessVmRead) != 0 && !CanInspect(pid))
                return IntPtr.Zero;
            return NativeResolver.OpenProcess(access, false, pid);
        }

        public static bool CopyRemote(IntPtr hProcess, IntPtr address, byte[] buffer, out int bytesRead)
        {
            bytesRead = 0;
            if (hProcess == IntPtr.Zero) return false;
            return NativeResolver.ReadProcessMemory(hProcess, address, buffer, buffer.Length, out bytesRead);
        }

        public static int QueryRemoteRegion(IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION mbi)
        {
            mbi = default;
            if (hProcess == IntPtr.Zero) return 0;
            return NativeResolver.VirtualQueryEx(hProcess, address, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
        }

        public static bool IsExecutableProtection(uint protect) =>
            protect is ProtX or ProtRX or ProtRWX or ProtXwc;

        public static bool LooksLikeMzPe(int processId, IntPtr address)
        {
            if (!CanInspect(processId) || address == IntPtr.Zero) return false;
            var buf = new byte[2];
            IntPtr h = OpenRemoteHandle(AccessQuery | AccessVmRead, processId);
            if (h == IntPtr.Zero) return false;
            try
            {
                if (!CopyRemote(h, address, buf, out int n) || n < 2) return false;
                return buf[0] == (byte)'M' && buf[1] == (byte)'Z';
            }
            catch { return false; }
            finally { CloseHandle(h); }
        }

        public static int QuerySystemInfo(int infoClass, IntPtr buffer, int size, out int returnLength)
        {
            return NativeResolver.NtQuerySystemInformation(infoClass, buffer, size, out returnLength);
        }

        public static bool DupHandle(IntPtr srcProc, IntPtr src, IntPtr dstProc, out IntPtr dst, int access, bool inherit, int options)
        {
            return NativeResolver.DuplicateHandle(srcProc, src, dstProc, out dst, access, inherit, options);
        }

        public static List<(string Name, string Path, IntPtr Base, int Size)> EnumModules(int pid)
        {
            var list = new List<(string, string, IntPtr, int)>();
            if (!CanInspect(pid)) return list;
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                {
                    list.Add((
                        mod.ModuleName ?? "",
                        mod.FileName ?? "",
                        mod.BaseAddress,
                        mod.ModuleMemorySize));
                }
            }
            catch { }
            MappedModuleCache.Replace(pid, list);
            return list;
        }
    }

    /// <summary>
    /// Image ranges from the one-shot EnumModules baseline + ETW ImageLoad.
    /// EtwThreatIntelMonitor must not EnumModules every 5s.
    /// </summary>
    internal static class MappedModuleCache
    {
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<int, List<(ulong Base, ulong End)>> Ranges = new();

        public static void Replace(int pid, List<(string Name, string Path, IntPtr Base, int Size)> modules)
        {
            var list = new List<(ulong, ulong)>(modules.Count);
            foreach (var m in modules)
            {
                if (m.Base == IntPtr.Zero) continue;
                ulong b = (ulong)m.Base;
                list.Add((b, b + (ulong)Math.Max(m.Size, 1)));
            }
            Ranges[pid] = list;
        }

        public static void Add(int pid, ulong imageBase, ulong imageSize)
        {
            if (imageBase == 0) return;
            var list = Ranges.GetOrAdd(pid, _ => new List<(ulong, ulong)>());
            lock (list)
                list.Add((imageBase, imageBase + Math.Max(imageSize, 1UL)));
        }

        public static List<(ulong Base, ulong End)> Get(int pid)
        {
            if (!Ranges.TryGetValue(pid, out var list) || list == null)
                return new List<(ulong, ulong)>();
            lock (list)
                return new List<(ulong, ulong)>(list);
        }

        /// <summary>Evict a PID on ProcessStop so dead entries don't accumulate.</summary>
        public static void Remove(int pid) => Ranges.TryRemove(pid, out _);
    }
}
