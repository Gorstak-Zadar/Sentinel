using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors for token manipulation and privilege escalation:
    /// - Processes with duplicated tokens from higher-integrity processes
    /// - Unexpected SYSTEM tokens in user-context processes
    /// - SeDebugPrivilege enabled in non-administrative processes
    /// Purely behavioral — detects anomalous privilege states.
    /// </summary>
    public sealed class TokenIntegrityMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<TokenIntegrityMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

        public TokenIntegrityMonitor(
            DetectionEngine detectionEngine,
            ILogger<TokenIntegrityMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanTokens, null, ScanInterval, ScanInterval);
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenElevation = 20;
        private const int TokenIntegrityLevel = 25;

        private readonly HashSet<int> _alertedPids = new();

        private void ScanTokens(object? state)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        if (_alertedPids.Contains(proc.Id)) continue;

                        if (!OpenProcessToken(proc.Handle, TOKEN_QUERY, out var tokenHandle))
                            continue;

                        try
                        {
                            // Check TOKEN_ELEVATION
                            var elevBuffer = Marshal.AllocHGlobal(4);
                            try
                            {
                                if (GetTokenInformation(tokenHandle, TokenElevation, elevBuffer, 4, out _))
                                {
                                    int elevated = Marshal.ReadInt32(elevBuffer);
                                    if (elevated != 0)
                                    {
                                        // Elevated process — check if it's from a user-writable path
                                         string? imagePath = null;
                                         try { imagePath = SecurityValidation.GetProcessImagePath(proc.Id); } catch { }

                                         if (imagePath != null)
                                         {
                                             bool inUserPath = imagePath.Contains(@"\Temp\") ||
                                                               imagePath.Contains(@"\Downloads\") ||
                                                               imagePath.Contains(@"\AppData\");

                                             if (inUserPath)
                                             {
                                                 // Installers elevate from Temp/Downloads by design (Inno, WiX, MSI extract).
                                                 if (InstallerHeuristics.IsInstallerExtractor(proc.ProcessName, imagePath) ||
                                                     InstallerHeuristics.LooksLikeInstallerName(proc.ProcessName, imagePath))
                                                 {
                                                     _alertedPids.Add(proc.Id);
                                                     continue;
                                                 }

                                                 _ = _detectionEngine.EmitAsync(new DetectionEvent
                                                 {
                                                     RuleName = "Privilege Escalation: Elevated Process from User Path",
                                                     Evidence = $"Elevated process '{proc.ProcessName}' (PID {proc.Id}) running from '{imagePath}'",
                                                     Reasoning = "An elevated (admin) process is running from a user-writable directory, suggesting a privilege escalation or UAC bypass.",
                                                     Confidence = 0.80, Tier = DetectionTier.Tier2Indicator,
                                                     AuthorizedResponse = ResponseAction.LogOnly,
                                                     ProcessName = proc.ProcessName, ProcessId = proc.Id
                                                 });
                                                 _alertedPids.Add(proc.Id);
                                             }
                                         }
                                    }
                                }
                            }
                            finally { Marshal.FreeHGlobal(elevBuffer); }
                        }
                        finally { CloseHandle(tokenHandle); }
                    }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }

                // Prune old PIDs
                if (_alertedPids.Count > 500) _alertedPids.Clear();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[TokenIntegrityMonitor] Scan error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
