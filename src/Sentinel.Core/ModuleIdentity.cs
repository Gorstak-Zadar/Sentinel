using System;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// Identity of a mapped PE: path tree + Microsoft signature.
    /// Count is not identity (Chromium loading Edge DLLs is not injection).
    /// Hijack names (dbghelp, version, winmm, …) next to the exe are plants even
    /// when Microsoft-signed — DLL search order loads the local copy first.
    /// </summary>
    public static class ModuleIdentity
    {
        /// <summary>
        /// Loadable-module file extensions. The unloader enumerates every mapped PE via
        /// EnumProcessModules regardless of extension, so identity applies to all of them.
        /// This set is used by the filename-keyed helpers (bundled / sideload plant) so a
        /// non-.dll module (WinRT .winmd with MSIL, .ocx, .cpl, .node, .ax, .drv, …) is not
        /// silently treated as "not a module". A system-provided .winmd is pure metadata and
        /// stays keep-tree; a third-party managed .winmd can carry code, so it is in scope.
        /// </summary>
        public static readonly System.Collections.Generic.HashSet<string> ModuleExtensions =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ".dll",   // classic PE library
                ".winmd", // WinRT metadata (managed ones carry MSIL)
                ".ocx",   // ActiveX / OLE control
                ".cpl",   // Control Panel applet (PE)
                ".ax",    // DirectShow filter (PE)
                ".node",  // Node.js native addon (PE)
                ".drv",   // legacy driver-model user DLL
                ".acm",   // audio compression manager (PE)
                ".tsp",   // TAPI service provider (PE)
                ".mui",   // resource-only module
                ".efi",   // EFI application/driver (PE)
            };

        /// <summary>
        /// True when the file name (or path) ends with a known loadable-module extension.
        /// Executables (.exe) are their own process image and are handled separately.
        /// </summary>
        public static bool IsModuleFileName(string? pathOrName)
        {
            if (string.IsNullOrWhiteSpace(pathOrName)) return false;
            string ext;
            try { ext = Path.GetExtension(pathOrName) ?? ""; }
            catch { return false; }
            return ext.Length > 0 && ModuleExtensions.Contains(ext);
        }

        public readonly struct Verdict
        {
            public Verdict(bool allowed, string reason)
            {
                Allowed = allowed;
                Reason = reason;
            }

            public bool Allowed { get; }
            public string Reason { get; }
        }

        /// <summary>
        /// <paramref name="isMicrosoftSigned"/> is only consulted when path trees are not enough.
        /// Pass null to treat unknown signatures as unsigned (fail closed).
        /// </summary>
        public static Verdict Evaluate(
            string? processImagePath,
            string? modulePath,
            Func<string, bool>? isMicrosoftSigned = null)
        {
            if (string.IsNullOrWhiteSpace(modulePath))
                return Deny("empty-path");

            var mod = Normalize(modulePath);
            if (mod.Length == 0)
                return Deny("empty-path");

            if (IsOsServicingPath(mod))
                return Allow("os-servicing");

            var image = Normalize(processImagePath);
            if (image.Length > 0 && PathsEqual(mod, image))
                return Allow("process-image");

            if (IsGpuIcdName(mod))
                return Allow("gpu-icd");

            if (IsKeepTree(mod))
            {
                if (IsUserWritableDrop(mod) && DllUnloadEngine.IsSideloadTargetFileName(mod))
                    return Deny("sideload-name-in-writable");
                return Allow("keep-tree");
            }

            var procDir = image.Length > 0 ? DirOf(image) : "";
            var modDir = DirOf(mod);
            bool underApp = procDir.Length > 0 && IsUnderDirectory(modDir, procDir);

            if (underApp)
            {
                // Known hijack names must come from the OS keep-tree (already
                // allowed above). A real Microsoft dbghelp.dll copied next to
                // the exe is still a search-order hijack. Do not use module
                // count; do not unload every unsigned app DLL (games, plugins).
                if (DllUnloadEngine.IsSideloadTargetFileName(mod))
                    return Deny("sideload-plant-in-appdir");
                return Allow("app-directory");
            }

            if (MicrosoftSigned(mod, isMicrosoftSigned) &&
                IsProgramFilesTree(mod) &&
                !IsUserWritableDrop(mod))
                return Allow("microsoft-signed-programfiles");

            if (IsUserWritableDrop(mod))
                return Deny("user-writable-drop");

            return Deny("foreign-path");
        }

        public static bool IsAllowed(
            string? processImagePath,
            string? modulePath,
            Func<string, bool>? isMicrosoftSigned = null) =>
            Evaluate(processImagePath, modulePath, isMicrosoftSigned).Allowed;

        public static bool IsKeepTree(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;

            // Whole OS tree except Windows\Temp (that is still a drop folder).
            // NativeImages, Microsoft.NET, SystemApps, UUS were missed by the
            // system32-only check and got FreeLibrary'd — CLR 80131506 / StartMenu loop.
            var win = WindowsRoot();
            if (p.Equals(win, StringComparison.Ordinal) ||
                p.StartsWith(win + @"\", StringComparison.Ordinal))
            {
                if (ContainsDir(p, @"\windows\temp\") || ContainsDir(p, @"\windows\tmp\"))
                    return false;
                return true;
            }

            if (ContainsDir(p, @"\microsoft\edgewebview\")) return true;
            if (ContainsDir(p, @"\microsoft\edge\")) return true;
            if (ContainsDir(p, @"\microsoft\edgecore\")) return true;
            if (ContainsDir(p, @"\microsoft\edgeupdate\")) return true;
            if (ContainsDir(p, @"\microsoft shared\")) return true;
            if (ContainsDir(p, @"\windowsapps\")) return true;
            if (ContainsDir(p, @"\webview2userdata\")) return true;
            if (ContainsDir(p, @"\ebwebview\")) return true;
            if (ContainsDir(p, @"\dotnet\")) return true;
            if (ContainsDir(p, @"\microsoft.net\")) return true;
            // v2.5.5: NuGet package cache — Roslyn source generators and NuGet-cached DLLs
            // loaded by VBCSCompiler/dotnet/msbuild must not be quarantined as foreign-path.
            if (ContainsDir(p, @"\.nuget\packages\")) return true;
            if (ContainsDir(p, @"\nvidia corporation\")) return true;
            if (ContainsDir(p, @"\amd\")) return true;
            if (ContainsDir(p, @"\ati technologies\")) return true;
            if (ContainsDir(p, @"\intel\")) return true;
            return false;
        }

        public static bool IsUserWritableDrop(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;
            if (ContainsDir(p, @"\temp\")) return true;
            if (p.EndsWith(@"\temp", StringComparison.Ordinal)) return true;
            if (ContainsDir(p, @"\downloads\")) return true;
            if (ContainsDir(p, @"\desktop\")) return true;
            if (ContainsDir(p, @"\appdata\local\temp\")) return true;
            // AppData overlays except Edge/WebView user-data (keep-tree already matched those).
            if (ContainsDir(p, @"\appdata\local\") || ContainsDir(p, @"\appdata\roaming\"))
            {
                if (ContainsDir(p, @"\microsoft\edge")) return false;
                if (ContainsDir(p, @"\webview2userdata\")) return false;
                if (ContainsDir(p, @"\ebwebview\")) return false;
                return true;
            }
            return false;
        }

        public static bool IsOsServicingPath(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;
            if (ContainsDir(p, @"\nltmpscratch\")) return true;
            if (ContainsDir(p, @"\nltmps\")) return true;
            if (ContainsDir(p, @"\winsxs\")) return true;
            if (ContainsDir(p, @"\servicing\")) return true;
            if (ContainsDir(p, @"\cbstemp\")) return true;
            if (ContainsDir(p, @"\windows\system32\dism\")) return true;
            if (ContainsDir(p, @"\windows\syswow64\dism\")) return true;
            if (ContainsDir(p, @"\microsoft\windows\servicing\")) return true;
            return false;
        }

        public static bool IsGpuIcdName(string? path)
        {
            string file;
            try { file = Path.GetFileNameWithoutExtension(path) ?? ""; }
            catch { return false; }
            if (file.Length == 0) return false;
            file = file.ToLowerInvariant();
            foreach (var prefix in GpuIcdPrefixes)
            {
                if (file.StartsWith(prefix, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        public static bool IsProgramFilesTree(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;
            if (ContainsDir(p, @"\program files\")) return true;
            if (ContainsDir(p, @"\program files (x86)\")) return true;
            return false;
        }

        private static readonly string[] GpuIcdPrefixes =
        {
            "nvldumd", "nvwgf2um", "nvd3dum", "nvoglv", "nvapi", "nvopencl", "nvcuda",
            "atidxx", "atio6axx", "amdxc", "amdvlk", "atiadlxx", "atioglxx", "amdocl",
            "igc64", "igc32", "igd10", "igd12", "igdail", "igd9s", "ig4icd", "ig9icd",
            "ig11icd", "ig12icd", "igvk", "intelocl", "igdrcl",
        };

        private static bool MicrosoftSigned(string path, Func<string, bool>? isMicrosoftSigned)
        {
            if (isMicrosoftSigned == null) return false;
            try { return isMicrosoftSigned(path); }
            catch { return false; }
        }

        private static Verdict Allow(string reason) => new(true, reason);
        private static Verdict Deny(string reason) => new(false, reason);

        internal static string Normalize(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "";
            try
            {
                var p = path!.Trim().Replace('/', '\\');
                if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p.Substring(4);
                if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p.Substring(4);
                return p.TrimEnd('\\').ToLowerInvariant();
            }
            catch { return ""; }
        }

        private static string DirOf(string normalizedPath)
        {
            try
            {
                var d = Path.GetDirectoryName(normalizedPath);
                return string.IsNullOrEmpty(d) ? "" : d.TrimEnd('\\');
            }
            catch { return ""; }
        }

        private static bool PathsEqual(string a, string b) =>
            string.Equals(a, b, StringComparison.Ordinal);

        private static bool IsUnderDirectory(string childDir, string parentDir)
        {
            if (childDir.Length == 0 || parentDir.Length == 0) return false;
            if (childDir.Equals(parentDir, StringComparison.Ordinal)) return true;
            return childDir.StartsWith(parentDir + @"\", StringComparison.Ordinal);
        }

        private static bool ContainsDir(string normalizedPath, string needle) =>
            normalizedPath.IndexOf(needle, StringComparison.Ordinal) >= 0;

        private static string WindowsRoot()
        {
            try
            {
                var w = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                return string.IsNullOrEmpty(w) ? @"c:\windows" : w.TrimEnd('\\').ToLowerInvariant();
            }
            catch { return @"c:\windows"; }
        }
    }
}
