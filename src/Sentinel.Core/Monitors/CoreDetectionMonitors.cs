// Core Detection Monitor Group — DLL scanning, entropy analysis, load failure detection, and module integrity

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    // ──────────────────────────────────────────────
    // DiskWideDllScanner — finds DLLs planted outside trusted directories
    // ──────────────────────────────────────────────
    public sealed class DiskWideDllScanner : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DiskWideDllScanner> _logger;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _alertedDlls = new(StringComparer.OrdinalIgnoreCase);

        public DiskWideDllScanner(DetectionEngine de, ILogger<DiskWideDllScanner> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DiskWideDllScanner] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(120000, ct);

                    var pruneCutoff = DateTime.UtcNow.AddMinutes(-10);
                    foreach (var kvp in _alertedDlls.Where(x => x.Value < pruneCutoff).ToList())
                    {
                        _alertedDlls.TryRemove(kvp.Key, out _);
                    }

                    var tempDir = Path.GetTempPath();
                    if (Directory.Exists(tempDir))
                    {
                        foreach (var dll in Directory.EnumerateFiles(tempDir, "*.dll", SearchOption.TopDirectoryOnly))
                        {
                            try
                            {
                                var fi = new FileInfo(dll);
                                if (fi.Length > 0 && 
                                    fi.CreationTimeUtc > DateTime.UtcNow.AddSeconds(-125) &&
                                    !_alertedDlls.ContainsKey(dll))
                                {
                                    _alertedDlls.TryAdd(dll, DateTime.UtcNow);

                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "DLL Sideloading: DLL in Temp Directory",
                                        Evidence = $"Recently created DLL in temp: {dll} ({fi.Length} bytes)",
                                        Reasoning = "A DLL was recently dropped into a temporary directory, which is a common DLL sideloading or injection staging technique.",
                                        Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                                        ProcessName = "SYSTEM", ProcessId = 0
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DiskWideDllScanner] Error"); }
            }
        }
    }


    // ──────────────────────────────────────────────
    // DLL Entropy Analyzer — detects packed/encrypted DLLs
    // ──────────────────────────────────────────────
    public sealed class DllEntropyAnalyzer : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DllEntropyAnalyzer> _logger;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _scanned = new(StringComparer.OrdinalIgnoreCase);

        public DllEntropyAnalyzer(DetectionEngine de, ILogger<DllEntropyAnalyzer> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DllEntropyAnalyzer] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(180000, ct);

                    foreach (var path in _scanned.Keys.ToList())
                    {
                        if (!File.Exists(path))
                        {
                            _scanned.TryRemove(path, out _);
                        }
                    }

                    var tempDir = Path.GetTempPath();
                    var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                    foreach (var dir in new[] { tempDir, downloadsDir })
                    {
                        if (!Directory.Exists(dir)) continue;
                        foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly))
                        {
                            try
                            {
                                var fi = new FileInfo(file);
                                var currentWriteTime = fi.LastWriteTimeUtc;

                                if (_scanned.TryGetValue(file, out var prevWriteTime) && prevWriteTime == currentWriteTime)
                                    continue;

                                _scanned[file] = currentWriteTime;

                                var entropy = CalculateEntropy(file);
                                if (entropy > 7.2)
                                {
                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "DLL Entropy: High Entropy DLL",
                                        Evidence = $"DLL '{file}' has entropy {entropy:F2} (threshold 7.2)",
                                        Reasoning = "A DLL with abnormally high entropy was found, suggesting it is packed or encrypted — common for malware payloads.",
                                        Confidence = 0.70, Tier = DetectionTier.Tier2Indicator,
                                        ProcessName = "SYSTEM", ProcessId = 0
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DllEntropyAnalyzer] Error"); }
            }
        }

        private static double CalculateEntropy(string filePath)
        {
            var freq = new long[256];
            long total = 0;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var buf = new byte[8192];
                int read;
                while ((read = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < read; i++) freq[buf[i]]++;
                    total += read;
                    if (total > 1_000_000) break; 
                }
            }
            if (total == 0) return 0;
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / total;
                entropy -= p * MathNet48.Log2(p);
            }
            return entropy;
        }
    }


    // ──────────────────────────────────────────────
    // DLL Load Failure Monitor — watches Windows event log for load failures
    // ──────────────────────────────────────────────
    public sealed class DllLoadFailureMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DllLoadFailureMonitor> _logger;

        public DllLoadFailureMonitor(DetectionEngine de, ILogger<DllLoadFailureMonitor> l) { _detectionEngine = de; _logger = l; }

        // Tracks the most recent event RecordNumber we have processed to avoid re-scanning
        private long _lastProcessedRecordNumber = -1;

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DllLoadFailureMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);
                    // Use EventLogQuery with a time-bounded XPath filter instead of iterating
                    // all entries — avoids O(N) scan on large Application logs every 15s.
                    try
                    {
                        var cutoff = DateTime.UtcNow.AddSeconds(-20).ToUniversalTime()
                            .ToString("o", System.Globalization.CultureInfo.InvariantCulture);
                        // Query only SideBySide error events in the last 20 seconds
                        var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                            "Application",
                            System.Diagnostics.Eventing.Reader.PathType.LogName,
                            $"*[System[Provider[@Name='SideBySide'] and Level=2 and TimeCreated[@SystemTime>='{cutoff}']]]");

                        using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
                        System.Diagnostics.Eventing.Reader.EventRecord? record;
                        while ((record = reader.ReadEvent()) != null)
                        {
                            using (record)
                            {
                                // Skip events we have already emitted
                                if (record.RecordId.HasValue && record.RecordId.Value <= _lastProcessedRecordNumber)
                                    continue;
                                if (record.RecordId.HasValue)
                                    _lastProcessedRecordNumber = record.RecordId.Value;

                                var desc = record.FormatDescription() ?? "";
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "DLL Load Failure: SideBySide Error",
                                    Evidence = $"SideBySide error at {record.TimeCreated}: {desc.Substring(0, Math.Min(200, desc.Length))}",
                                    Reasoning = "A DLL side-by-side loading failure was detected, which may indicate DLL hijacking or corruption.",
                                    Confidence = 0.50, Tier = DetectionTier.Tier2Indicator,
                                    ProcessName = "SYSTEM", ProcessId = 0
                                });
                                break; // One per cycle
                            }
                        }
                    }
                    catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DllLoadFailureMonitor] Error"); }
            }
        }
    }


    // ──────────────────────────────────────────────
    // Module Validation Monitor — checks loaded DLL integrity via hash
    // ──────────────────────────────────────────────
    public sealed class ModuleValidationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ModuleValidationMonitor> _logger;
        private readonly ConcurrentDictionary<string, string> _baselineHashes = new(StringComparer.OrdinalIgnoreCase);

        public ModuleValidationMonitor(DetectionEngine de, ILogger<ModuleValidationMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ModuleValidationMonitor] Started");
            // Baseline our own modules
            var selfDir = AppContext.BaseDirectory;
            foreach (var dll in Directory.EnumerateFiles(selfDir, "*.dll"))
            {
                try { _baselineHashes[dll] = HashFile(dll); } catch { }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    foreach (var (path, expectedHash) in _baselineHashes)
                    {
                        if (!File.Exists(path))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Self-Protection: Sentinel Module Deleted",
                                Evidence = $"Module was deleted: {path}",
                                Reasoning = "A Sentinel runtime module was removed from disk, indicating active tampering.",
                                Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            continue;
                        }
                        var currentHash = HashFile(path);
                        if (currentHash != expectedHash)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Self-Protection: Sentinel Module Tampered",
                                Evidence = $"Module hash mismatch: {path} (expected {expectedHash}, got {currentHash})",
                                Reasoning = "A Sentinel runtime module was modified on disk, indicating active tampering or DLL replacement.",
                                Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            _baselineHashes[path] = currentHash;
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ModuleValidationMonitor] Error"); }
            }
        }

        private static string HashFile(string path)
        {
            using var fs = File.OpenRead(path);
            var hash = System.Security.Cryptography.Sha256Net48.HashData(fs);
            return ConvertHex.ToHexString(hash);
        }
    }


    // ──────────────────────────────────────────────
    // Runtime Module Integrity Monitor — checks loaded module paths
    // ──────────────────────────────────────────────
    public sealed class RuntimeModuleIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RuntimeModuleIntegrityMonitor> _logger;

        public RuntimeModuleIntegrityMonitor(DetectionEngine de, ILogger<RuntimeModuleIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RuntimeModuleIntegrityMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    // Check that the Sentinel service's own loaded modules are from expected paths
                    var selfProc = Process.GetCurrentProcess();
                    foreach (ProcessModule mod in selfProc.Modules)
                    {
                        try
                        {
                            var modPath = mod.FileName ?? "";
                            if (!modPath.Contains(@"\Windows\") &&
                                !modPath.Contains(AppContext.BaseDirectory) &&
                                !modPath.Contains(@"\dotnet\") &&
                                !modPath.Contains(@"\Program Files") &&
                                !modPath.Contains(@"\Microsoft\Windows Defender\"))
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Self-Protection: Unexpected Module Loaded",
                                    Evidence = $"Unexpected module loaded into Sentinel process: {modPath}",
                                    Reasoning = "A module from an untrusted path was loaded into the Sentinel service process, indicating possible DLL injection.",
                                    Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = "Sentinel.Service", ProcessId = System.Net48Environment.ProcessId
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[RuntimeModuleIntegrityMonitor] Error"); }
            }
        }
    }


    // ──────────────────────────────────────────────
    // ADS Data Staging Monitor — detects NTFS Alternate Data Streams abuse
    // ──────────────────────────────────────────────
    public sealed class AdsDataStagingMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AdsDataStagingMonitor> _logger;
        private readonly HashSet<string> _alertedFiles = new(StringComparer.OrdinalIgnoreCase);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr FindFirstStreamW(string lpFileName, int infoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, int dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(IntPtr hFindFile);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_STREAM_DATA
        {
            public long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string cStreamName;
        }

        private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        public AdsDataStagingMonitor(DetectionEngine de, ILogger<AdsDataStagingMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[AdsDataStagingMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    // Scan temp + downloads for files with suspicious ADS streams
                    var tempDir = Path.GetTempPath();
                    var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

                    foreach (var dir in new[] { tempDir, downloadsDir })
                    {
                        if (!Directory.Exists(dir)) continue;
                        try
                        {
                            foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                            {
                                if (_alertedFiles.Contains(file)) continue;
                                try
                                {
                                    var streams = GetAlternateDataStreams(file);
                                    // Zone.Identifier is normal (Mark of the Web). Others are suspicious.
                                    foreach (var stream in streams)
                                    {
                                        if (stream.Name.Contains("Zone.Identifier")) continue;
                                        if (stream.Name == "::$DATA") continue; // Primary data stream

                                        if (stream.Size > 1024) // Only flag ADS > 1KB (payload-sized)
                                        {
                                            _alertedFiles.Add(file);
                                            await _detectionEngine.EmitAsync(new DetectionEvent
                                            {
                                                RuleName = "ADS Staging: Hidden Data in Alternate Data Stream",
                                                Evidence = $"File '{file}' has a suspicious ADS '{stream.Name}' ({stream.Size} bytes)",
                                                Reasoning = "A file in a user-writable directory has a non-standard Alternate Data Stream larger than 1KB. ADS is used to hide payloads, exfiltration data, or persistence mechanisms from normal file listings.",
                                                Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                                                ProcessName = "SYSTEM", ProcessId = 0
                                            });
                                            break;
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }

                    // Limit alertedFiles growth
                    if (_alertedFiles.Count > 500) _alertedFiles.Clear();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[AdsDataStagingMonitor] Error"); }
            }
        }

        private static List<(string Name, long Size)> GetAlternateDataStreams(string filePath)
        {
            var streams = new List<(string, long)>();
            var handle = FindFirstStreamW(filePath, 0, out var data, 0);
            if (handle == INVALID_HANDLE_VALUE) return streams;

            try
            {
                do
                {
                    streams.Add((data.cStreamName, data.StreamSize));
                } while (FindNextStreamW(handle, out data));
            }
            finally
            {
                FindClose(handle);
            }
            return streams;
        }
    }


}
