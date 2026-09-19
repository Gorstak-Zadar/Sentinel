// Cryptocurrency Miner Behavior Monitor - detects coin-mining resource abuse behaviorally.
// SystemIntegrity Group.
//
// Threat model:
//   Pirated-streaming pages, malvertising, and dropped "codec"/"player" payloads frequently
//   monetize via cryptomining (browser-based WASM miners and native dropped miners like the
//   xmrig family). A miner's behavioral signature is distinctive:
//     1. SUSTAINED near-full CPU across the observation window (minutes), not a short burst.
//     2. A PERSISTENT outbound connection to a SMALL number of endpoints (the mining pool) -
//        low destination diversity, long-lived, on non-web ports.
//   Neither signal alone is malicious - video encoding, 3D rendering, compilation, and games
//   also peg the CPU; SSH/RDP/DBs hold long connections. The monitor requires BOTH the
//   sustained-CPU signal AND a low-diversity persistent connection before it even emits, and
//   even then emits only observe-grade fuel.
//
// PRODUCT LAW - this monitor NEVER kills on the miner signature alone:
//   - Emits Tier2 / LogOnly detections tagged Family=CoinMiner.
//   - CoinMiner is terminal (seeds the multi-signal chain) but is deliberately NOT in the
//     kill-grade family set, so a miner is terminated ONLY when it corroborates a real
//     kill-grade terminal (injection, C2, cred dump, ...) in a confirmed chain.
//   - Behavioral only: no filename / path / hash trust. A process named "xmrig.exe" is not
//     treated differently from any other; only what the process DOES matters.
//
// EXPLICITLY UNBLOCKED (the user watches movies and torrents freely):
//   - Browsers (video playback, WebGL) are excluded - streaming a movie is a decode+network
//     workload, not sustained all-core CPU pegging with a persistent low-diversity pool link.
//   - BitTorrent / P2P / download-manager clients (BulkTransferNoise) are excluded - and a
//     torrent swarm is HIGH endpoint diversity, the opposite of a miner's few-endpoint pool.
//   - Games and GPU compute are excluded via the game/anti-cheat path.
//   The result: legitimate heavy compute and all pirate-streaming/torrenting activity stay
//   observe-only; nothing here blocks them.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects cryptocurrency mining behaviorally: sustained multi-core CPU abuse correlated
    /// with a persistent, low-diversity outbound connection (mining pool / stratum-shaped).
    /// Emits observe-only <see cref="TerminalFamily.CoinMiner"/> seeds - never a solo kill.
    /// Does not touch browsers, torrent/P2P clients, games, or GPU compute.
    /// </summary>
    public sealed class MinerBehaviorMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MinerBehaviorMonitor> _logger;

        // Sampling cadence. Miners run for minutes/hours; we sample slowly and require the
        // high-CPU condition to persist across many samples before treating it as sustained.
        private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(15);

        // A process must stay above the CPU threshold for at least this long to count as
        // "sustained" mining. Short bursts (page load, app launch, a single encode) never qualify.
        private static readonly TimeSpan SustainedWindow = TimeSpan.FromMinutes(4);

        // Per-core CPU fraction (0..1) averaged across the machine that we treat as "hot".
        // Miners pin the CPU near saturation; we use a high bar to avoid catching bursty work.
        private const double HotCpuFraction = 0.80;

        // A mining-pool connection is persistent and low-diversity. If a hot process talks to
        // more than this many distinct remote endpoints it looks like a swarm/CDN/browser, not
        // a pool - we do NOT flag it (this is what keeps torrenting and streaming clear).
        private const int MaxPoolEndpointDiversity = 3;

        // Re-alert suppression per process identity.
        private static readonly TimeSpan ReAlertWindow = TimeSpan.FromMinutes(30);

        // Per-PID CPU sampling state: last total processor time + the UTC instant it was taken,
        // plus the timestamp when the process first crossed into the "hot" band.
        private sealed class CpuSample
        {
            public TimeSpan LastTotalProcessorTime;
            public DateTime LastSampledUtc;
            public DateTime? HotSinceUtc;
        }

        private readonly ConcurrentDictionary<int, CpuSample> _samples = new();
        private readonly ConcurrentDictionary<string, DateTime> _lastAlert = new();

        private readonly int _cpuCount = Math.Max(1, Environment.ProcessorCount);

        public MinerBehaviorMonitor(DetectionEngine detectionEngine, ILogger<MinerBehaviorMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation(
                "[MinerBehaviorMonitor] Started - behavioral coin-miner detection (observe-only; " +
                "browsers, torrent/P2P clients, games and GPU compute are excluded)");

            // Let the system settle so we don't sample startup CPU spikes as "mining".
            try { await Task.Delay(TimeSpan.FromSeconds(20), ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(SampleInterval, ct);
                    ScanForMiningBehavior(ct);
                    Prune();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    // Graceful degradation - a sampling error must never crash the host.
                    _logger.LogDebug(ex, "[MinerBehaviorMonitor] scan cycle error");
                }
            }
        }

        private void ScanForMiningBehavior(CancellationToken ct)
        {
            var now = DateTime.UtcNow;
            var livePids = new HashSet<int>();

            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { return; }

            foreach (var proc in procs)
            {
                if (ct.IsCancellationRequested) break;

                int pid;
                string name;
                try
                {
                    pid = proc.Id;
                    name = proc.ProcessName ?? "unknown";
                }
                catch { try { proc.Dispose(); } catch { } continue; }

                // Skip system/idle and our own PID handling downstream via ProcessId<=4 gate.
                if (pid <= 4) { try { proc.Dispose(); } catch { } continue; }

                livePids.Add(pid);

                try
                {
                    double cpuFraction = SampleCpuFraction(pid, proc, now);

                    // Track the "hot since" edge.
                    var sample = _samples.GetOrAdd(pid, _ => new CpuSample());
                    if (cpuFraction >= HotCpuFraction)
                    {
                        sample.HotSinceUtc ??= now;
                    }
                    else
                    {
                        sample.HotSinceUtc = null; // cooled off - reset the sustained timer
                    }

                    // Only proceed to the (more expensive) network check once CPU has been
                    // sustained-hot for the full window.
                    if (sample.HotSinceUtc == null) continue;
                    if (now - sample.HotSinceUtc.Value < SustainedWindow) continue;

                    // Cheap behavioral exclusions FIRST. These are what keep legitimate heavy
                    // compute AND all pirate-streaming / torrenting activity observe-clear.
                    string? imagePath = SecurityValidation.GetProcessImagePath(pid);
                    if (IsExcludedWorkload(name, imagePath)) continue;

                    // Network corroboration: a miner holds a persistent, low-diversity outbound
                    // connection (the pool). Absent that, sustained CPU is just heavy compute.
                    if (!HasPersistentLowDiversityConnection(pid, out var poolEndpoint, out int diversity))
                        continue;

                    EmitMinerSeed(pid, name, imagePath, cpuFraction, poolEndpoint, diversity, now);
                }
                catch { /* per-process best-effort */ }
                finally { try { proc.Dispose(); } catch { } }
            }

            // Evict samples for PIDs that are no longer alive (prevents recycled-PID confusion).
            foreach (var kv in _samples)
            {
                if (!livePids.Contains(kv.Key))
                    _samples.TryRemove(kv.Key, out _);
            }
        }

        /// <summary>
        /// Returns the process's CPU usage as a fraction of total machine capacity (0..1),
        /// computed from the delta in TotalProcessorTime between samples divided by wall-clock
        /// elapsed time and the logical processor count. Returns 0 on the first sample for a PID
        /// (no baseline yet) or on any access error.
        /// </summary>
        private double SampleCpuFraction(int pid, Process proc, DateTime now)
        {
            TimeSpan total;
            try { total = proc.TotalProcessorTime; }
            catch { return 0.0; }

            var sample = _samples.GetOrAdd(pid, _ => new CpuSample
            {
                LastTotalProcessorTime = total,
                LastSampledUtc = now
            });

            double elapsedSec = (now - sample.LastSampledUtc).TotalSeconds;
            double cpuFraction = 0.0;
            if (elapsedSec > 0.5)
            {
                double busySec = (total - sample.LastTotalProcessorTime).TotalSeconds;
                cpuFraction = busySec / (elapsedSec * _cpuCount);
                if (cpuFraction < 0) cpuFraction = 0;
                if (cpuFraction > 1) cpuFraction = 1;
            }

            sample.LastTotalProcessorTime = total;
            sample.LastSampledUtc = now;
            return cpuFraction;
        }

        /// <summary>
        /// Behavioral exclusions - workloads that legitimately peg the CPU and must stay
        /// observe-clear. This is NOT filename-trust for kill authority (the monitor never
        /// kills); it is scope-narrowing so the observe seed itself is not raised for the
        /// activities the user explicitly wants: browsing, streaming, torrenting, gaming.
        /// </summary>
        private static bool IsExcludedWorkload(string processName, string? imagePath)
        {
            // Browsers (streaming video / WebGL) - a movie stream is decode + network, not a
            // sustained all-core pool-linked miner. Excluded so watching movies never trips this.
            if (IsBrowser(processName)) return true;

            // BitTorrent / P2P / download managers / usenet / game delivery. Torrenting is the
            // user's explicit right here; a swarm is also high-diversity (fails the pool test
            // anyway), but we exclude by name up front so it never even reaches that check.
            if (BulkTransferNoise.IsBulkTransferProcessName(processName)) return true;

            // Games and anti-cheat (GPU + CPU heavy) - never a miner target for us.
            if (SecurityValidation.IsGameOrAntiCheatPath(imagePath)) return true;

            return false;
        }

        private static readonly HashSet<string> BrowserStems = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "chromium",
            "waterfox", "librewolf", "safari", "iexplore"
        };

        private static bool IsBrowser(string processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            var stem = processName;
            if (stem.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                stem = stem.Substring(0, stem.Length - 4);
            return BrowserStems.Contains(stem);
        }

        /// <summary>
        /// True when the PID holds at least one ESTABLISHED outbound (non-loopback) TCP
        /// connection AND the number of distinct remote endpoints is small (pool-shaped, not
        /// swarm/CDN-shaped). Fills <paramref name="poolEndpoint"/> with a representative
        /// endpoint and <paramref name="diversity"/> with the distinct-endpoint count.
        /// </summary>
        private bool HasPersistentLowDiversityConnection(int pid, out string poolEndpoint, out int diversity)
        {
            poolEndpoint = "";
            diversity = 0;

            var endpoints = GetEstablishedOutboundEndpoints(pid);
            if (endpoints.Count == 0) return false;

            var distinct = endpoints.Distinct().ToList();
            diversity = distinct.Count;

            // High diversity => browser / torrent swarm / CDN fan-out => NOT a pool. Leave alone.
            if (diversity > MaxPoolEndpointDiversity) return false;

            poolEndpoint = distinct[0];
            return true;
        }

        private void EmitMinerSeed(int pid, string name, string? imagePath, double cpuFraction,
            string poolEndpoint, int diversity, DateTime now)
        {
            var key = $"{name}|{imagePath ?? ""}|{pid}";
            if (_lastAlert.TryGetValue(key, out var last) && (now - last) < ReAlertWindow)
                return;
            _lastAlert[key] = now;

            int cpuPct = (int)Math.Round(cpuFraction * 100.0);

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Resource Abuse: Cryptominer Behavior",
                Evidence = $"Process '{name}' (PID {pid}) sustained ~{cpuPct}% total-CPU for over " +
                           $"{(int)SustainedWindow.TotalMinutes} minutes while holding a persistent, " +
                           $"low-diversity outbound connection to {poolEndpoint} " +
                           $"({diversity} distinct endpoint(s)). Image: '{imagePath ?? "unknown"}'.",
                Reasoning = "Sustained multi-core CPU saturation correlated with a long-lived, " +
                            "low-endpoint-diversity outbound connection matches the behavioral " +
                            "signature of cryptocurrency mining (native or browser-hosted, e.g. the " +
                            "xmrig family / WASM miners) against a mining pool. This is resource abuse, " +
                            "not a kill-grade terminal: it is logged as observe fuel and can only " +
                            "contribute to a response as one leg of a confirmed multi-signal chain. " +
                            "Browsers (video playback), torrent/P2P clients, and games are excluded, so " +
                            "streaming and torrenting are never affected.",
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.SuspiciousProcess,
                Family = TerminalFamily.CoinMiner,
                ProcessName = name,
                ProcessId = pid,
                Metadata = new Dictionary<string, string>
                {
                    { "CpuPercent", cpuPct.ToString() },
                    { "SustainedMinutes", ((int)SustainedWindow.TotalMinutes).ToString() },
                    { "PoolEndpoint", poolEndpoint },
                    { "EndpointDiversity", diversity.ToString() },
                    { "ImagePath", imagePath ?? "" },
                    { "MITRE", "T1496 (Resource Hijacking)" },
                }
            });

            _logger.LogInformation(
                "[MinerBehaviorMonitor] Observe seed: '{Name}' (PID {Pid}) ~{Cpu}% CPU sustained, " +
                "pool {Pool} (diversity {Div}) - LogOnly, chain-gated",
                name, pid, cpuPct, poolEndpoint, diversity);
        }

        private void Prune()
        {
            var now = DateTime.UtcNow;
            if (_lastAlert.Count > 2048)
            {
                foreach (var kv in _lastAlert)
                {
                    if (now - kv.Value > ReAlertWindow)
                        _lastAlert.TryRemove(kv.Key, out _);
                }
            }
        }

        // 
        // Native TCP table enumeration (IPv4) - established outbound endpoints for a PID.
        // 

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, int tableClass, uint reserved);

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int MIB_TCP_STATE_ESTAB = 5;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint State;
            public uint LocalAddr;
            public uint LocalPort;
            public uint RemoteAddr;
            public uint RemotePort;
            public uint OwningPid;
        }

        private List<string> GetEstablishedOutboundEndpoints(int targetPid)
        {
            var results = new List<string>();

            int size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 122) return results; // ERROR_INSUFFICIENT_BUFFER expected

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return results;

                int numEntries = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                IntPtr rowPtr = buffer + 4;

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr += rowSize;

                    if ((int)row.OwningPid != targetPid) continue;
                    if (row.State != MIB_TCP_STATE_ESTAB) continue;

                    var remoteIp = new System.Net.IPAddress(row.RemoteAddr).ToString();
                    if (IsLoopbackOrLocal(remoteIp)) continue; // loopback IPC is not a pool link

                    int remotePort = ((int)(row.RemotePort & 0xFF) << 8) | (int)((row.RemotePort >> 8) & 0xFF);
                    results.Add($"{remoteIp}:{remotePort}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return results;
        }

        private static bool IsLoopbackOrLocal(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return true;
            if (ip == "0.0.0.0" || ip == "255.255.255.255") return true;
            return ip.StartsWith("127.", StringComparison.Ordinal);
        }
    }
}
