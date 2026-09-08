// ForumHrWatchMonitor — v1.7.6 dedicated surveillance for forum.hr
//
// The hosts-file block of forum.hr was removed as opinionated: legitimate users
// should be able to browse the forum. This monitor replaces blanket blocking with
// targeted detection of C2/relay-style abuse of that domain alone.
//
// Attack model (historical): rootkit/implant holds a persistent WebSocket or
// long-poll to forum.hr as a C2 relay. Browsers browsing the forum are fine;
// non-browser processes talking to forum.hr are not.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Special-purpose monitor for forum.hr only. Does not block the site.
    /// Detects non-browser processes resolving/connecting to forum.hr (and known
    /// subdomains), long-lived non-browser sessions (C2 pairing pattern), and
    /// DNS reconnect bursts after drops on that domain.
    /// </summary>
    public sealed class ForumHrWatchMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ForumHrWatchMonitor> _logger;
        private readonly SignerTrustService? _signerTrust;

        // Resolved A/AAAA records for watched hostnames
        private readonly ConcurrentDictionary<string, byte> _forumIps = new(StringComparer.OrdinalIgnoreCase);

        // Tracked TCP sessions to forum.hr IPs: "pid:ip:port" → first-seen
        private readonly ConcurrentDictionary<string, ForumConnState> _tracked = new();

        // DNS activity attributed to PIDs (via DnsQueryMonitor feed)
        private readonly ConcurrentDictionary<int, DnsActivity> _dnsByPid = new();

        private readonly ConcurrentDictionary<string, DateTime> _alertDedup = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan DnsRefreshInterval = TimeSpan.FromMinutes(15);
        private static readonly TimeSpan PersistentThreshold = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan DnsWindow = TimeSpan.FromMinutes(2);

        /// <summary>Hostnames under exclusive watch (apex + common subdomains).</summary>
        internal static readonly string[] WatchedHostnames =
        {
            "forum.hr",
            "www.forum.hr",
            "m.forum.hr",
            "cdn.forum.hr",
            "static.forum.hr",
            "api.forum.hr",
            "img.forum.hr",
            "mail.forum.hr",
            "ads.forum.hr",
            "tracker.forum.hr",
        };

        private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "msedgewebview2", "firefox", "brave", "opera",
            "vivaldi", "chromium", "iridium", "waterfox", "librewolf", "tor",
            "safari", "iexplore", "maxthon", "browser"
        };

        // Processes that may legitimately touch many sites (still demoted, not killed hard)
        private static readonly HashSet<string> SoftExemptProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "Sentinel.Service", "Sentinel.Agent",
            "svchost", // system DNS/network stack noise — demote only
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        private enum TCP_TABLE_CLASS { OWNER_PID_ALL = 5 }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int pdwSize, bool bOrder,
            uint ulAf, TCP_TABLE_CLASS tableClass, uint reserved);

        public ForumHrWatchMonitor(
            DetectionEngine detectionEngine,
            ILogger<ForumHrWatchMonitor> logger,
            SignerTrustService? signerTrust = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _signerTrust = signerTrust;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation(
                "[ForumHrWatchMonitor] Started — watching forum.hr for non-browser C2/relay abuse (site not blocked)");

            await Task.Delay(TimeSpan.FromSeconds(30), ct);

            DateTime lastDnsRefresh = DateTime.MinValue;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (DateTime.UtcNow - lastDnsRefresh >= DnsRefreshInterval)
                    {
                        await RefreshForumIpsAsync(ct);
                        lastDnsRefresh = DateTime.UtcNow;
                    }

                    ScanConnections();
                    PruneStale();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[ForumHrWatchMonitor] Scan error");
                }

                await Task.Delay(ScanInterval, ct);
            }
        }

        /// <summary>
        /// Returns true if <paramref name="domain"/> is forum.hr or a subdomain thereof.
        /// </summary>
        internal static bool IsForumHrDomain(string? domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return false;
            domain = domain!.Trim().TrimEnd('.').ToLowerInvariant();
            if (domain.StartsWith("http://")) domain = domain[7..];
            if (domain.StartsWith("https://")) domain = domain[8..];
            var slash = domain.IndexOf('/');
            if (slash >= 0) domain = domain[..slash];
            var colon = domain.IndexOf(':');
            if (colon >= 0) domain = domain[..colon];

            return domain == "forum.hr" || domain.EndsWith(".forum.hr");
        }

        /// <summary>
        /// Called by DnsQueryMonitor when a DNS query is observed. Correlates
        /// forum.hr resolutions with non-browser PIDs when attribution is available.
        /// </summary>
        public void RecordDnsQuery(int pid, string domain)
        {
            if (!IsForumHrDomain(domain)) return;

            var activity = _dnsByPid.GetOrAdd(pid, _ => new DnsActivity());
            activity.Record(domain);

            // PID 0 = unattributed DNS event log feed — track volume only, no kill
            if (pid <= 4)
            {
                if (activity.QueryCount >= 30 && !activity.AlertedVolume)
                {
                    activity.AlertedVolume = true;
                    EmitVolumeDnsAlert(activity);
                }
                return;
            }

            string procName = GetProcessName(pid);
            if (string.IsNullOrEmpty(procName)) return;
            if (BrowserProcesses.Contains(procName)) return;
            if (SoftExemptProcesses.Contains(procName)) return;

            // Non-browser process resolving forum.hr more than once → suspicious
            if (activity.QueryCount >= 2 && ShouldAlert($"dns:{pid}", AlertCooldown))
            {
                bool signed = _signerTrust?.IsSignedProcess(pid) ?? false;
                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Forum.hr Watch: Non-Browser DNS Resolution",
                    Evidence = $"Process '{procName}' (PID {pid}) resolved forum.hr domain(s) " +
                               $"{activity.QueryCount} time(s). Domains: {string.Join(", ", activity.TopDomains(5))}",
                    Reasoning = "forum.hr is a public forum and is not blocked. Legitimate access is via a web browser. " +
                                "A non-browser process resolving forum.hr is consistent with malware using the site as a " +
                                "C2 relay or dead-drop. Hosts-file blocking was removed as opinionated; this watch " +
                                "detects abuse of that domain instead." +
                                (signed ? " Process is Authenticode-signed; demoted to log-only." : ""),
                    Confidence = signed ? 0.55 : 0.82,
                    Tier = signed ? DetectionTier.Tier2Indicator : DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = signed ? ResponseAction.LogOnly : ResponseAction.KillProcessTree,
                    ProcessName = procName,
                    ProcessId = pid,
                    SignalType = SignalType.NetworkC2,
                    Metadata = new Dictionary<string, string>
                    {
                        ["Domain"] = domain,
                        ["QueryCount"] = activity.QueryCount.ToString(),
                        ["TopDomains"] = string.Join(", ", activity.TopDomains(5)),
                        ["WatchTarget"] = "forum.hr"
                    }
                });
            }
        }

        private void EmitVolumeDnsAlert(DnsActivity activity)
        {
            if (!ShouldAlert("dns:volume", AlertCooldown)) return;

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Forum.hr Watch: High DNS Volume",
                Evidence = $"Unattributed DNS feed shows {activity.QueryCount} queries for forum.hr domain(s) " +
                           $"within {DnsWindow.TotalMinutes:F0}m. Domains: {string.Join(", ", activity.TopDomains(5))}",
                Reasoning = "Elevated DNS volume for forum.hr without process attribution. Logged for analyst review; " +
                            "connection-based non-browser detection remains the primary enforcement path.",
                Confidence = 0.50,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.NetworkC2,
                Metadata = new Dictionary<string, string>
                {
                    ["QueryCount"] = activity.QueryCount.ToString(),
                    ["WatchTarget"] = "forum.hr"
                }
            });
        }

        private async Task RefreshForumIpsAsync(CancellationToken ct)
        {
            foreach (var host in WatchedHostnames)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var entries = await DnsNet48.GetHostAddressesAsync(host, ct);
                    foreach (var ip in entries)
                    {
                        if (IPAddress.IsLoopback(ip)) continue;
                        var s = ip.ToString();
                        if (s is "0.0.0.0" or "::") continue;
                        _forumIps[s] = 0;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[ForumHrWatchMonitor] DNS resolve failed for {Host}", host);
                }
            }

            _logger.LogDebug("[ForumHrWatchMonitor] Tracking {Count} forum.hr IP(s)", _forumIps.Count);
        }

        private void ScanConnections()
        {
            if (_forumIps.IsEmpty) return;

            var currentKeys = new HashSet<string>(StringComparer.Ordinal);
            var connections = GetEstablishedConnections();

            foreach (var conn in connections)
            {
                if (!_forumIps.ContainsKey(conn.RemoteIp)) continue;

                var key = $"{conn.Pid}:{conn.RemoteIp}:{conn.RemotePort}";
                currentKeys.Add(key);

                if (!_tracked.TryGetValue(key, out var state))
                {
                    state = new ForumConnState
                    {
                        Pid = conn.Pid,
                        ProcessName = conn.ProcessName,
                        RemoteIp = conn.RemoteIp,
                        RemotePort = conn.RemotePort,
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow
                    };
                    _tracked[key] = state;

                    // Immediate: non-browser talking to forum.hr at all
                    EvaluateNonBrowserConnection(state, duration: TimeSpan.Zero);
                }
                else
                {
                    state.LastSeen = DateTime.UtcNow;
                    var duration = state.LastSeen - state.FirstSeen;
                    if (duration >= PersistentThreshold)
                        EvaluatePersistentConnection(state, duration);
                }
            }

            // Drop tracking for closed connections
            foreach (var key in _tracked.Keys.Except(currentKeys).ToList())
                _tracked.TryRemove(key, out _);
        }

        private void EvaluateNonBrowserConnection(ForumConnState state, TimeSpan duration)
        {
            if (BrowserProcesses.Contains(state.ProcessName)) return;
            if (SoftExemptProcesses.Contains(state.ProcessName)) return;
            if (state.Pid <= 4) return;

            if (!ShouldAlert($"conn:{state.Pid}:{state.RemoteIp}", AlertCooldown)) return;

            bool signed = _signerTrust?.IsSignedProcess(state.Pid) ?? false;
            string imagePath = SecurityValidation.GetProcessImagePath(state.Pid) ?? "";

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Forum.hr Watch: Non-Browser Connection",
                Evidence = $"Process '{state.ProcessName}' (PID {state.Pid}, Path: {imagePath}) " +
                           $"connected to forum.hr IP {state.RemoteIp}:{state.RemotePort}" +
                           (duration > TimeSpan.Zero ? $" (held {duration.TotalSeconds:F0}s)" : ""),
                Reasoning = "forum.hr is intentionally not blocked so users can browse the forum. " +
                            "Only web browsers should connect to it. A non-browser process opening a " +
                            "TCP session to a forum.hr address matches the historical C2/relay abuse pattern " +
                            "that previously motivated a hosts-file block." +
                            (signed ? " Process is Authenticode-signed; demoted to log-only." : ""),
                Confidence = signed ? 0.58 : 0.88,
                Tier = signed ? DetectionTier.Tier2Indicator : DetectionTier.Tier1Behavioral,
                AuthorizedResponse = signed ? ResponseAction.LogOnly : ResponseAction.KillProcessTree,
                ProcessName = state.ProcessName,
                ProcessId = state.Pid,
                SignalType = SignalType.NetworkC2,
                Metadata = new Dictionary<string, string>
                {
                    ["RemoteIP"] = state.RemoteIp,
                    ["RemotePort"] = state.RemotePort.ToString(),
                    ["ImagePath"] = imagePath,
                    ["WatchTarget"] = "forum.hr",
                    ["DurationSeconds"] = duration.TotalSeconds.ToString("F0")
                }
            });

            _logger.LogWarning(
                "[ForumHrWatchMonitor] Non-browser connection: {Process} (PID {Pid}) → {Ip}:{Port}",
                state.ProcessName, state.Pid, state.RemoteIp, state.RemotePort);
        }

        private void EvaluatePersistentConnection(ForumConnState state, TimeSpan duration)
        {
            // Browsers holding long forum sessions are normal — no alert.
            if (BrowserProcesses.Contains(state.ProcessName)) return;
            if (SoftExemptProcesses.Contains(state.ProcessName)) return;

            if (!ShouldAlert($"persist:{state.Pid}:{state.RemoteIp}", AlertCooldown)) return;

            bool signed = _signerTrust?.IsSignedProcess(state.Pid) ?? false;
            string imagePath = SecurityValidation.GetProcessImagePath(state.Pid) ?? "";

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Forum.hr Watch: Persistent Non-Browser Session",
                Evidence = $"Process '{state.ProcessName}' (PID {state.Pid}, Path: {imagePath}) " +
                           $"held connection to forum.hr IP {state.RemoteIp}:{state.RemotePort} " +
                           $"for {duration.TotalMinutes:F1} minutes",
                Reasoning = "Long-lived non-browser TCP sessions to forum.hr match webhook/WebSocket C2 " +
                            "pairing behavior. Legitimate forum use is interactive browsing, not multi-minute " +
                            "silent sessions from arbitrary processes." +
                            (signed ? " Process is Authenticode-signed; demoted to log-only." : ""),
                Confidence = signed ? 0.60 : 0.92,
                Tier = signed ? DetectionTier.Tier2Indicator : DetectionTier.Tier1Behavioral,
                AuthorizedResponse = signed ? ResponseAction.LogOnly : ResponseAction.KillProcessTree,
                ProcessName = state.ProcessName,
                ProcessId = state.Pid,
                SignalType = SignalType.NetworkC2,
                Metadata = new Dictionary<string, string>
                {
                    ["RemoteIP"] = state.RemoteIp,
                    ["RemotePort"] = state.RemotePort.ToString(),
                    ["ImagePath"] = imagePath,
                    ["WatchTarget"] = "forum.hr",
                    ["DurationSeconds"] = duration.TotalSeconds.ToString("F0")
                }
            });
        }

        private bool ShouldAlert(string key, TimeSpan cooldown)
        {
            var now = DateTime.UtcNow;
            if (_alertDedup.TryGetValue(key, out var last) && now - last < cooldown)
                return false;
            _alertDedup[key] = now;
            return true;
        }

        private void PruneStale()
        {
            var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(30);
            foreach (var kv in _alertDedup)
            {
                if (kv.Value < cutoff)
                    _alertDedup.TryRemove(kv.Key, out _);
            }

            foreach (var kv in _dnsByPid)
            {
                kv.Value.Prune(DnsWindow);
                if (kv.Value.QueryCount == 0)
                    _dnsByPid.TryRemove(kv.Key, out _);
            }
        }

        private List<ActiveConn> GetEstablishedConnections()
        {
            var results = new List<ActiveConn>();
            int size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, TCP_TABLE_CLASS.OWNER_PID_ALL, 0);
            if (size == 0) return results;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buffer, ref size, true, 2, TCP_TABLE_CLASS.OWNER_PID_ALL, 0);
                if (ret != 0) return results;

                int count = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, 4);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    if (row.state != 5) continue; // MIB_TCP_STATE_ESTAB
                    if (row.owningPid <= 4) continue;

                    var remoteIp = new IPAddress(row.remoteAddr).ToString();
                    int remotePort = (int)(((row.remotePort & 0xFF) << 8) | ((row.remotePort >> 8) & 0xFF));

                    results.Add(new ActiveConn
                    {
                        Pid = (int)row.owningPid,
                        ProcessName = GetProcessName((int)row.owningPid),
                        RemoteIp = remoteIp,
                        RemotePort = remotePort
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return results;
        }

        private static string GetProcessName(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                return p.ProcessName;
            }
            catch { return string.Empty; }
        }

        // ── Internal types (testable) ────────────────────────────────────────

        private sealed class ForumConnState
        {
            public int Pid;
            public string ProcessName = "";
            public string RemoteIp = "";
            public int RemotePort;
            public DateTime FirstSeen;
            public DateTime LastSeen;
        }

        private sealed class ActiveConn
        {
            public int Pid;
            public string ProcessName = "";
            public string RemoteIp = "";
            public int RemotePort;
        }

        private sealed class DnsActivity
        {
            private readonly ConcurrentDictionary<string, int> _domains = new(StringComparer.OrdinalIgnoreCase);
            private readonly ConcurrentQueue<DateTime> _timestamps = new();
            public bool AlertedVolume;

            public int QueryCount
            {
                get
                {
                    Prune(DnsWindow);
                    return _timestamps.Count;
                }
            }

            public void Record(string domain)
            {
                _timestamps.Enqueue(DateTime.UtcNow);
                _domains.AddOrUpdate(domain, 1, (_, c) => c + 1);
            }

            public void Prune(TimeSpan window)
            {
                var cutoff = DateTime.UtcNow - window;
                while (_timestamps.TryPeek(out var t) && t < cutoff)
                    _timestamps.TryDequeue(out _);
            }

            public IEnumerable<string> TopDomains(int n) =>
                _domains.OrderByDescending(kv => kv.Value).Take(n).Select(kv => kv.Key);
        }
    }
}
