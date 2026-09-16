using System;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// Pure COM-hijack classifier (T1546.015).
    ///
    /// Sentinel previously only flagged *new* HKCR InprocServer32 keys and then baselined
    /// them forever, so hijacking an existing CLSID (the real attack) was invisible. It
    /// also scored anything under C:\Windows\ as fine, so a Component Based Servicing
    /// impersonation (cbsapi.dll outside WinSxS) was allowed.
    ///
    /// Registry keys are never deleted here. A hijacked well-known CLSID still belongs
    /// to the shell; deleting the class bricks explorer/logon. The payload DLL is what
    /// gets quarantined, via <see cref="ShouldQuarantinePayload"/>.
    /// </summary>
    public static class ComHijackEvaluator
    {
        public enum ServerKind
        {
            InprocServer32,
            InprocHandler32,
            LocalServer32,
            TreatAs
        }

        public readonly struct Registration
        {
            public Registration(
                string clsid,
                string hive,
                ServerKind kind,
                string serverValue,
                string? baselineValue = null,
                bool hkcuShadowsHklm = false,
                string? hklmValue = null)
            {
                Clsid = clsid ?? "";
                Hive = hive ?? "";
                Kind = kind;
                ServerValue = serverValue ?? "";
                BaselineValue = baselineValue;
                HkcuShadowsHklm = hkcuShadowsHklm;
                HklmValue = hklmValue;
            }

            public string Clsid { get; }
            public string Hive { get; }
            public ServerKind Kind { get; }
            public string ServerValue { get; }
            public string? BaselineValue { get; }
            public bool HkcuShadowsHklm { get; }
            public string? HklmValue { get; }
        }

        public readonly struct Verdict
        {
            public bool IsHijack { get; init; }
            public bool ShouldQuarantinePayload { get; init; }
            public double Confidence { get; init; }
            public string RuleName { get; init; }
            public string Reasoning { get; init; }
            public DetectionTier Tier { get; init; }
            public ResponseAction AuthorizedResponse { get; init; }
        }

        /// <summary>
        /// Expand REG_EXPAND_SZ and strip LocalServer32 arguments. TreatAs values are
        /// CLSIDs, not paths - callers should not run this on TreatAs.
        /// </summary>
        public static string ExtractServerPath(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return "";
            var s = raw.Trim();
            try { s = Environment.ExpandEnvironmentVariables(s); }
            catch { /* keep raw */ }
            s = s.Trim().Trim('"');
            if (s.Length == 0) return "";

            if (s.StartsWith("\"", StringComparison.Ordinal))
            {
                int end = s.IndexOf('"', 1);
                if (end > 1) s = s.Substring(1, end - 1);
            }
            else
            {
                int dotExe = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                int dotDll = s.IndexOf(".dll", StringComparison.OrdinalIgnoreCase);
                int ext = dotExe >= 0 ? dotExe + 4 : (dotDll >= 0 ? dotDll + 4 : -1);
                if (ext > 0 && ext < s.Length && s[ext] == ' ')
                    s = s.Substring(0, ext).Trim('"');
            }

            return s.Trim().Trim('"');
        }

        public static bool IsPublicDrop(string? path)
        {
            var p = ModuleIdentity.Normalize(path);
            if (p.Length == 0) return false;
            return p.IndexOf(@"\users\public\", StringComparison.Ordinal) >= 0
                || p.StartsWith(@"c:\public\", StringComparison.Ordinal)
                || p.Equals(@"c:\public", StringComparison.Ordinal);
        }

        public static bool IsScriptHostServer(string? path)
        {
            string file;
            try { file = Path.GetFileName(ExtractServerPath(path)) ?? ""; }
            catch { return false; }
            if (file.Length == 0) return false;
            return file.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("wscript.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("cscript.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("regsvr32.exe", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// The DLL/EXE the COM class points at is the payload. Never the CLSID key.
        /// Never an OS LOLBin (powershell/rundll32) - those stay observe-only.
        /// </summary>
        public static bool ShouldQuarantinePayload(string? rawServer)
        {
            var path = ExtractServerPath(rawServer);
            if (path.Length == 0) return false;
            if (ModuleIdentity.IsOsServicingPath(path)) return false;
            if (IsScriptHostServer(path)) return false;
            if (ModuleIdentity.IsServicingNameOutsideStore(path)) return true;
            if (ModuleIdentity.IsUserWritableDrop(path)) return true;
            if (IsPublicDrop(path)) return true;
            return false;
        }

        public static bool IsTrustedComServerPath(string? rawServer)
        {
            var path = ExtractServerPath(rawServer);
            if (path.Length == 0) return false;
            if (ModuleIdentity.IsServicingNameOutsideStore(path)) return false;
            if (ModuleIdentity.IsOsServicingPath(path)) return true;
            if (ModuleIdentity.IsKeepTree(path) && !ModuleIdentity.IsUserWritableDrop(path)) return true;
            if (ModuleIdentity.IsProgramFilesTree(path) && !ModuleIdentity.IsUserWritableDrop(path)) return true;
            return false;
        }

        public static Verdict Evaluate(in Registration r)
        {
            if (r.Kind == ServerKind.TreatAs)
                return EvaluateTreatAs(in r);

            var path = ExtractServerPath(r.ServerValue);
            if (path.Length == 0)
                return None();

            var baselinePath = string.IsNullOrEmpty(r.BaselineValue)
                ? ""
                : ExtractServerPath(r.BaselineValue);
            bool isNew = baselinePath.Length == 0;
            bool changed = !isNew && !string.Equals(baselinePath, path, StringComparison.OrdinalIgnoreCase);

            if (ModuleIdentity.IsOsServicingPath(path))
                return None();

            if (ModuleIdentity.IsServicingNameOutsideStore(path))
            {
                return Hijack(
                    0.92,
                    "Registry: COM Servicing-DLL Impersonation",
                    "COM InprocServer32/Handler points at a Component Based Servicing DLL name " +
                    "(cbsapi/cbscore/cbsmsg) that is not under WinSxS or Windows\\servicing. " +
                    "On current Windows the real CBS stack lives in the component store; a copy " +
                    "anywhere else - including System32 - is a plant. Quarantine the file, never the CLSID.");
            }

            if (ModuleIdentity.IsUserWritableDrop(path) || IsPublicDrop(path))
            {
                return Hijack(
                    0.88,
                    "Registry: COM Server in User-Writable Path",
                    "COM InprocServer32/LocalServer32 points at Temp/AppData/Downloads/Desktop/Public. " +
                    "Classic COM hijack persistence (T1546.015). Quarantine the payload DLL; do not delete the class.");
            }

            if (IsScriptHostServer(path))
            {
                return Hijack(
                    0.90,
                    "Registry: COM Server is Script Host",
                    "COM LocalServer32/InprocServer32 launches powershell/cmd/wscript/mshta/rundll32. " +
                    "Observe-only for the LOLBin itself; the CLSID key is not deleted.",
                    quarantine: false);
            }

            if (r.HkcuShadowsHklm
                && !string.IsNullOrEmpty(r.HklmValue)
                && !string.Equals(path, ExtractServerPath(r.HklmValue), StringComparison.OrdinalIgnoreCase)
                && !IsTrustedComServerPath(path))
            {
                return Hijack(
                    0.84,
                    "Registry: HKCU COM CLSID Shadow",
                    "HKCU\\Software\\Classes\\CLSID overrides an HKLM class with a different server path. " +
                    "HKCU wins at activation with no admin required.");
            }

            if (changed && !IsTrustedComServerPath(path))
            {
                return Hijack(
                    0.80,
                    "Registry: COM Server Path Changed",
                    "An existing CLSID server path changed to a location outside the OS / Program Files trees. " +
                    "This is the hijack Sentinel used to miss by only watching for *new* CLSIDs.");
            }

            if (isNew && !IsTrustedComServerPath(path))
            {
                return Hijack(
                    0.70,
                    "Registry: Suspicious COM CLSID Registration",
                    "New COM server registered outside System32/WinSxS/Program Files.");
            }

            return None();
        }

        private static Verdict EvaluateTreatAs(in Registration r)
        {
            var value = (r.ServerValue ?? "").Trim();
            if (value.Length == 0)
                return None();

            bool hkcu = r.Hive.IndexOf("HKCU", StringComparison.OrdinalIgnoreCase) >= 0;
            var baseline = (r.BaselineValue ?? "").Trim();
            bool isNew = baseline.Length == 0;
            bool changed = !isNew && !string.Equals(baseline, value, StringComparison.OrdinalIgnoreCase);

            if (!hkcu && !changed)
                return None();

            if (hkcu || changed)
            {
                return Hijack(
                    0.78,
                    "Registry: COM TreatAs Redirect",
                    "TreatAs redirects a CLSID to another class. HKCU TreatAs leaves the original " +
                    "InprocServer32 untouched and is a documented COM hijack. LogOnly - do not delete the class.",
                    quarantine: false);
            }

            return None();
        }

        private static Verdict None() => new()
        {
            IsHijack = false,
            ShouldQuarantinePayload = false,
            Confidence = 0,
            RuleName = "",
            Reasoning = "",
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly
        };

        private static Verdict Hijack(double confidence, string rule, string reasoning, bool quarantine = true) => new()
        {
            IsHijack = true,
            ShouldQuarantinePayload = quarantine,
            Confidence = confidence,
            RuleName = rule,
            Reasoning = reasoning,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly
        };
    }
}
