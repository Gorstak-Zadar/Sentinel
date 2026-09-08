using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public class AdvancedResponseEngine
    {
        private readonly SentinelConfig _config;
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;
        private readonly QuarantineManager _quarantineManager;
        private readonly AllowlistService? _allowlist;
        private readonly SentinelEventLogWriter? _windowsEventLog;
        private IncidentResponseService? _incidentResponse;
        private DllUnloadEngine? _dllUnloadEngine;
        private ChainTracer? _chainTracer;
        private ReinfectionCorrelator? _reinfectionCorrelator;

        // v1.6.0: Rolling kill budget to prevent response weaponization (FP kill storms)
        private readonly ConcurrentQueue<long> _killTimestampsMs = new();
        private long _lastRateLimitLogMs;
        // v1.6.1: NetworkIsolate budget + Tier1 alert hook
        private readonly ConcurrentQueue<long> _isolateTimestampsMs = new();
        private long _lastIsolateRateLimitLogMs;
        private DetectionEngine? _detectionEngine;

        // v1.8.1 RT-LOW-1: hard cap on timestamp queues (limit * 2) under pathological load
        private static int BudgetQueueCap(int limit) => Math.Max(limit * 2, 32);

        /// <summary>Set after DI construction to avoid circular dependency.</summary>
        public void SetReinfectionCorrelator(ReinfectionCorrelator correlator) => _reinfectionCorrelator = correlator;

        public AdvancedResponseEngine(
            SentinelConfig config,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger,
            QuarantineManager quarantineManager,
            AllowlistService? allowlist = null,
            SentinelEventLogWriter? windowsEventLog = null)
        {
            _config = config;
            _metrics = metrics;
            _eventLogger = eventLogger;
            _quarantineManager = quarantineManager;
            _allowlist = allowlist;
            _windowsEventLog = windowsEventLog;
        }

        private void TryWriteWindowsEventLog(DetectionEvent detection, string actionTaken, string reason)
        {
            try
            {
                if (_windowsEventLog == null || !_windowsEventLog.IsAvailable)
                    return;
                // Durable trail for real actions / chain confirms only (not observe LogOnly spam)
                if (string.IsNullOrEmpty(actionTaken) ||
                    actionTaken.StartsWith("LOG", StringComparison.OrdinalIgnoreCase))
                    return;
                if (reason != null &&
                    reason.IndexOf("ChainConfirmed", StringComparison.OrdinalIgnoreCase) < 0 &&
                    actionTaken.IndexOf("KILL", StringComparison.OrdinalIgnoreCase) < 0 &&
                    actionTaken.IndexOf("QUARANTINE", StringComparison.OrdinalIgnoreCase) < 0 &&
                    actionTaken.IndexOf("ISOLATE", StringComparison.OrdinalIgnoreCase) < 0 &&
                    actionTaken.IndexOf("NETWORK", StringComparison.OrdinalIgnoreCase) < 0)
                    return;

                _windowsEventLog.WriteChainResponse(detection, actionTaken, reason ?? "");
            }
            catch
            {
                // Absolute fail-soft — response path must never throw on Event Log
            }
        }

        /// <summary>
        /// v1.6.0: Returns false when MaxKillsPerMinute budget is exhausted.
        /// NetworkIsolate is gated separately via TryConsumeIsolateBudget.
        /// v2.1.7 B5: Chain-confirmed detections bypass the rate limit (separate unlimited budget).
        /// </summary>
        private bool TryConsumeKillBudget(bool chainConfirmed = false)
        {
            // v2.1.7: Chain-confirmed multi-signal detections bypass the per-minute rate limit.
            // Rationale: An attacker cannot forge chain-confirmed events (requires multi-rule convergence
            // on same PID within the correlation window). Rate-limiting was designed to prevent FP storms,
            // not to hamper confirmed attack response.
            if (chainConfirmed) return true;

            int limit = _config.MaxKillsPerMinute;
            if (limit <= 0) return true;

            long now = System.Net48Environment.TickCount64;
            long windowStart = now - 60_000;
            while (_killTimestampsMs.TryPeek(out long ts) && ts < windowStart)
                _killTimestampsMs.TryDequeue(out _);

            if (_killTimestampsMs.Count >= limit)
            {
                // Log at most once per 30s to avoid log floods
                long lastLog = Interlocked.Read(ref _lastRateLimitLogMs);
                if (now - lastLog > 30_000 &&
                    Interlocked.CompareExchange(ref _lastRateLimitLogMs, now, lastLog) == lastLog)
                {
                    _ = _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = 0,
                        ProcessName = "SYSTEM",
                        ActionTaken = "RATE_LIMITED",
                        Reason = $"Kill budget exhausted ({limit}/min). Subsequent kills demoted to LogOnly until window slides.",
                        ExecutionTimeMs = 0
                    });
                    // v1.6.1: Loud Tier1 so operators see weaponized FP / ransomware wave
                    EmitBudgetExhaustedAlert("KillBudget", limit);
                }
                return false;
            }

            _killTimestampsMs.Enqueue(now);
            TrimBudgetQueue(_killTimestampsMs, BudgetQueueCap(limit));
            return true;
        }

        /// <summary>
        /// v1.6.1: Cap new NetworkIsolate targets per minute.
        /// </summary>
        private bool TryConsumeIsolateBudget()
        {
            int limit = _config.MaxNetworkIsolatesPerMinute;
            if (limit <= 0) return true;

            long now = System.Net48Environment.TickCount64;
            long windowStart = now - 60_000;
            while (_isolateTimestampsMs.TryPeek(out long ts) && ts < windowStart)
                _isolateTimestampsMs.TryDequeue(out _);

            if (_isolateTimestampsMs.Count >= limit)
            {
                long lastLog = Interlocked.Read(ref _lastIsolateRateLimitLogMs);
                if (now - lastLog > 30_000 &&
                    Interlocked.CompareExchange(ref _lastIsolateRateLimitLogMs, now, lastLog) == lastLog)
                {
                    _ = _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = 0,
                        ProcessName = "SYSTEM",
                        ActionTaken = "ISOLATE_RATE_LIMITED",
                        Reason = $"NetworkIsolate budget exhausted ({limit}/min). Further isolates skipped until window slides.",
                        ExecutionTimeMs = 0
                    });
                    EmitBudgetExhaustedAlert("NetworkIsolateBudget", limit);
                }
                return false;
            }

            _isolateTimestampsMs.Enqueue(now);
            TrimBudgetQueue(_isolateTimestampsMs, BudgetQueueCap(limit));
            return true;
        }

        private static void TrimBudgetQueue(ConcurrentQueue<long> queue, int maxCount)
        {
            while (queue.Count > maxCount && queue.TryDequeue(out _)) { }
        }

        private void EmitBudgetExhaustedAlert(string budgetType, int limit)
        {
            var de = _detectionEngine;
            if (de == null) return;
            _ = de.EmitAsync(new DetectionEvent
            {
                RuleName = "Anti-Tamper: Response Budget Exhausted",
                Evidence = $"{budgetType} hit limit of {limit} actions per minute. " +
                           "Further destructive responses are demoted/skipped until the window slides.",
                Reasoning = "Exhausting the automated response budget can indicate either a true mass-infection " +
                            "event (ransomware) or an attacker weaponizing false positives / decoy beacons. " +
                            "Operators must review immediately; detection logging continues.",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.AntiTamper,
                Metadata = new Dictionary<string, string>
                {
                    ["BudgetType"] = budgetType,
                    ["LimitPerMinute"] = limit.ToString()
                }
            });
        }

        public void SetDllUnloadEngine(DllUnloadEngine engine) => _dllUnloadEngine = engine;

        public void SetChainTracer(ChainTracer tracer) => _chainTracer = tracer;

        public void SetIncidentResponseService(IncidentResponseService irs) => _incidentResponse = irs;

        /// <summary>v1.6.1: Wire DetectionEngine after DI to avoid circular construction.</summary>
        public void SetDetectionEngine(DetectionEngine engine) => _detectionEngine = engine;

        private static readonly HashSet<string> PresidentsLawKeywords = new(StringComparer.OrdinalIgnoreCase)
        {
            "lsass", "amsi", "etw", "ransomware", "shadow copy",
            "self-protection", "selfprotection", "honeypot", "chain-nuke",
            "composite", "verdictgate", "verdict gate",
            "webcamhijack", "webcam hijack", "audiohijack", "audio hijack",
            "antitamper", "anti-tamper", "tampering",
            "hollowing", "reverseshell", "reverse shell",
            "threatintel", "badusb", "canary",
            "tls:", "certificate"
        };

        private bool IsPresidentsLawRule(DetectionEvent detection)
        {
            // Delegate to ScoringEngine's authoritative enum-based categorization
            // to avoid divergence between the two parallel President's Law checks.
            return ScoringEngine.IsPresidentsLawRule(detection.RuleName);
        }

        /// <summary>
        /// v1.8.3: Single-signal heuristics that fire during normal user work (SSH, torrents,
        /// portable tools in Downloads, rclone backups, shell networking). These must never
        /// kill/quarantine alone. Confirmed attacks and multi-signal composites are excluded.
        /// </summary>
        internal static bool IsObserveOnlyUserActivityHeuristic(string? ruleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName)) return false;
            var r = ruleName!;

            // Composites / confirmed campaigns always act
            if (r.Contains("Composite") ||
                r.Contains("Fileless Attack") ||
                r.Contains("Covert RAT") ||
                r.Contains("Dropped Payload") ||
                r.Contains("Confirmed C2") ||
                r.Contains("SYSTEM Token") ||
                r.Contains("Non-Service Process with SYSTEM"))
                return false;

            return r.Contains("Reverse Shell: Suspicious Outbound") ||
                   r.Contains("Connection on Blocked Port") ||
                   r.Contains("Network UDP: Classic Malware Port") ||
                   r.Contains("Attack Tool: Connection from Suspicious Path") ||
                   r.Contains("Network Policy: Unusual Destination") ||
                   r.Contains("SeImpersonatePrivilege from Suspicious Path") ||
                   r.Contains("Cloud Sync Tool Running") ||
                   r.Contains("Data Exfiltration: Cloud Sync");
        }

        public async Task HandleAsync(DetectionEvent detection)
        {
            var stopwatch = Stopwatch.StartNew();

            bool shouldKill = false;
            bool shouldIsolateNetwork = false;
            bool shouldQuarantineAndKill = false;
            bool shouldRemoveCertAndKillAdder = false;
            bool shouldRemoveCert = false;
            bool shouldRemoveRegistryEntry = false;
            string reason = "LogOnly";

            // HARDENING v1.3.8: Absolute self-exclusion — never take action against our own processes.
            // The FileReputationEngine flags our unsigned dev builds as "Suspicious" (score ~43-48),
            // and the correlation engine can escalate these to kill responses. Force LogOnly.
            //
            // SECURITY: Path-verified, not name-based. An attacker naming their binary
            // "Sentinel.Agent.exe" in a user-writable directory is NOT excluded.
            // We resolve the actual image path and verify it resides in our installation directory.
            if (detection.ProcessId > 0)
            {
                try
                {
                    var detectedImagePath = SecurityValidation.GetProcessImagePath(detection.ProcessId);
                    // SECURITY v1.4.4: Normalize both paths with Path.GetFullPath() to resolve
                    // symlinks, junctions, and relative segments (../) before comparison.
                    // Also use trailing separator to prevent prefix collision attacks
                    // (e.g., C:\Program Files\Sentinel2\evil.exe matching our dir).
                    // v2.0 RT-HIGH-2: hardlink-aware self path (not string-prefix alone)
                    if (detectedImagePath != null &&
                        (SelfPathGuard.IsSentinelSelfBinary(detectedImagePath) ||
                         SelfPathGuard.IsUnderInstallDirectory(detectedImagePath)))
                    {
                        // Only skip response for our own binaries under install — not arbitrary hardlinks
                        if (SelfPathGuard.IsSentinelSelfBinary(detectedImagePath))
                        {
                            reason = "LogOnly (Self-exclusion: verified Sentinel install path)";
                            stopwatch.Stop();
                            _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                            var selfLog = new ResponseEvent
                            {
                                ProcessId = detection.ProcessId,
                                ProcessName = detection.ProcessName,
                                ActionTaken = "LOG",
                                Reason = reason,
                                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                            };
                            await _eventLogger.LogEventAsync("response", selfLog);
                            return;
                        }
                    }
                }
                catch { /* process may have exited — continue with normal handling */ }
            }

            // Standing product default: ObserveUntilChain=true → enforce tier law here
            // (Tier1 only for kill-grade terminals / composites). When ObserveUntilChain is
            // explicitly false (lab / unit tests of response paths), preserve author tier.
            // Live DetectionEngine always applies ApplyTierLaw before this gate.
            if (_config.ObserveUntilChain)
            {
                double minTier1 = _config.MinTier1Confidence > 0
                    ? _config.MinTier1Confidence
                    : ResponsePolicy.DefaultMinTier1Confidence;
                ResponsePolicy.ApplyTierLaw(detection, minTier1);
            }

            var isPresidentsLaw = IsPresidentsLawRule(detection);
            var effectiveTier = detection.Tier;
            var effectiveResponse = detection.AuthorizedResponse;
            var effectiveKillAuthorized = detection.KillAuthorized;

            string? imagePath = null;
            try
            {
                if (detection.ProcessId > 0)
                {
                    imagePath = SecurityValidation.GetProcessImagePath(detection.ProcessId);
                }
            }
            catch { }

            // v1.6.9: IDE / development tool protection — Electron/V8 apps generate JIT code
            // that matches syscall-stub patterns, RWX memory patterns, and other heuristics.
            // Killing an IDE is an irreversible false positive that destroys the developer's
            // session. Demote to LogOnly unless this is a President's Law rule (actual confirmed
            // malicious activity like process injection INTO the IDE).
            if (!isPresidentsLaw && detection.ProcessId > 0 &&
                ChainTracer.IsLegitimateIdeHost(imagePath, detection.ProcessName))
            {
                reason = $"LogOnly (IDE host protection: {detection.ProcessName} at '{imagePath}')";
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                var ideLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = reason,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", ideLog);
                return;
            }

            // v2.3.1 ALWAYS-ON: Game Protection Policy — checked BEFORE allowlist and
            // observe-until-chain. Game processes NEVER receive destructive actions.
            // This is a hard product invariant that cannot be overridden by config.
            if (!isPresidentsLaw && detection.ProcessId > 0 &&
                AlwaysOnPolicies.ApplyGameProtection(detection, imagePath))
            {
                reason = $"LogOnly (AlwaysOn: Game Protection — {detection.ProcessName} at '{imagePath}')";
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                var gameLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = reason,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", gameLog);
                return;
            }

            if (_allowlist != null && _allowlist.ShouldSuppress(detection.ProcessName, imagePath, detection.RuleName))
            {
                effectiveTier = DetectionTier.Tier2Indicator;
                effectiveResponse = ResponseAction.LogOnly;
                effectiveKillAuthorized = false;
                reason = "LogOnly (Suppressed by allowlist)";
            }

            // Global observe-until-chain: every monitor is silent LogOnly until multi-signal
            // proof points at BYOVD / exfil / token theft / reverse shell / cred dump.
            // v2.3.1: DLL unload is an ALWAYS-ON policy (AlwaysOnPolicies.IsDllUnloadAlwaysOn).
            // MitmDefense suite is also exempt: planted cert + ghost process + fake Chromecast /
            // FCM Send-Tab-to-Self is a confirmed post-incident chain that must act without waiting
            // for a second unrelated signal.
            // When chain confirms → full nuke (quarantine+kill + isolate + chain tracer).
            bool chainAuthorized = false;
            bool dllExempt = AlwaysOnPolicies.IsDllUnloadAlwaysOn(detection);
            bool mitmExempt = ResponsePolicy.IsMitmDefenseAction(detection, _config);
            if (_config.ObserveUntilChain)
            {
                chainAuthorized = ResponsePolicy.MayPerformDestructiveResponse(detection, _config);
                if (!chainAuthorized && !dllExempt && !mitmExempt)
                {
                    effectiveTier = DetectionTier.Tier2Indicator;
                    effectiveResponse = ResponseAction.LogOnly;
                    effectiveKillAuthorized = false;
                    reason = "LogOnly (observe-until-chain: no multi-signal terminal attack yet)";
                }
                else if (mitmExempt && !chainAuthorized)
                {
                    // Keep author response (RemoveCert / KillProcessTree / NetworkIsolate).
                    // Do not promote to full QuarantineAndKill — MitM suite is surgical.
                    effectiveTier = DetectionTier.Tier1Behavioral;
                    if (detection.AuthorizedResponse is ResponseAction.KillProcess
                        or ResponseAction.KillProcessTree
                        or ResponseAction.QuarantineAndKill)
                        effectiveKillAuthorized = true;
                    reason = $"MitmDefense action ({detection.AuthorizedResponse})";
                }
                else if (chainAuthorized && !dllExempt)
                {
                    // Nuke with everything once the chain is proven.
                    // Write authority back onto the detection so AutoIncidentReporter
                    // (and any post-response consumers) see kill-grade chain-confirmed state.
                    ResponsePolicy.PromoteChainConfirmedFields(detection);
                    effectiveTier = DetectionTier.Tier1Behavioral;
                    effectiveResponse = ResponseAction.QuarantineAndKill;
                    effectiveKillAuthorized = true;
                    var outcome = detection.Metadata != null &&
                                  detection.Metadata.TryGetValue(ResponsePolicy.TerminalOutcomeKey, out var o)
                        ? o : "chain";
                    reason = $"ChainConfirmed nuke ({outcome})";
                }
            }
            else if (IsObserveOnlyUserActivityHeuristic(detection.RuleName) &&
                     effectiveResponse is ResponseAction.KillProcess or ResponseAction.KillProcessTree
                         or ResponseAction.Quarantine or ResponseAction.QuarantineAndKill
                         or ResponseAction.NetworkIsolate)
            {
                // Legacy narrow safety net when ObserveUntilChain is explicitly off.
                effectiveTier = DetectionTier.Tier2Indicator;
                effectiveResponse = ResponseAction.LogOnly;
                effectiveKillAuthorized = false;
                reason = "LogOnly (observe-first: weak user-activity heuristic — no confirmed attack)";
            }

            // MitmDefense: cert remove / kill ghost / isolate rogue Cast without full multi-signal chain.
            bool ar = _config.ActiveResponse && (!_config.ObserveUntilChain || chainAuthorized || dllExempt || mitmExempt);

            if (effectiveResponse == ResponseAction.QuarantineAndKill && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldQuarantineAndKill = true;
                    if (!reason.StartsWith("ChainConfirmed"))
                        reason = $"QuarantineAndKill (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (observe-until-chain)";
                }
            }
            else if (effectiveResponse == ResponseAction.RemoveCertAndKillAdder && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldRemoveCertAndKillAdder = true;
                    reason = $"RemoveCertAndKillAdder (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (observe-until-chain)";
                }
            }
            else if (effectiveResponse == ResponseAction.RemoveRegistryEntry && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldRemoveRegistryEntry = true;
                    reason = $"RemoveRegistryEntry (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (observe-until-chain)";
                }
            }
            else if (effectiveResponse == ResponseAction.RemoveCert && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldRemoveCert = true;
                    reason = $"RemoveCert (AuthorizedResponse={effectiveResponse}, no process terminated)";
                }
                else
                {
                    reason = "LogOnly (observe-until-chain)";
                }
            }
            else if (effectiveResponse == ResponseAction.NetworkIsolate && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldIsolateNetwork = true;
                    reason = $"NetworkIsolate (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (observe-until-chain)";
                }
            }
            else if ((effectiveKillAuthorized ||
                      effectiveResponse is ResponseAction.KillProcess or ResponseAction.KillProcessTree) &&
                     effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldKill = true;
                    if (!reason.StartsWith("MitmDefense") && !reason.StartsWith("ChainConfirmed"))
                        reason = $"Killed (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (observe-until-chain)";
                }
            }
            else if (effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (reason == "LogOnly")
                    reason = "LogOnly (Tier1 without kill authorization)";
            }
            else
            {
                if (reason == "LogOnly")
                {
                    reason = "LogOnly (Tier2 Indicator)";
                }
            }

            // Chain-confirmed: also isolate if we have a target IP (nuke with everything).
            if (ar && chainAuthorized && !shouldIsolateNetwork &&
                detection.Metadata != null &&
                detection.Metadata.TryGetValue("TargetIP", out var tip) &&
                !string.IsNullOrEmpty(tip))
            {
                shouldIsolateNetwork = true;
            }

            if (shouldRemoveCertAndKillAdder)
            {
                var certThumb = detection.Metadata!.GetValueOrDefault("CertThumbprint", "Unknown");
                var adderPidStr = detection.Metadata!.GetValueOrDefault("AdderProcessId", "0");

                // Only remove certs that are MITM-related (planted for interception).
                // Non-MITM cert detections are logged but not actioned.
                bool isMitmCert = ResponsePolicy.IsMitmDefenseAction(detection, _config);

                if (!string.IsNullOrEmpty(certThumb) && certThumb != "Unknown" && isMitmCert)
                {
                    RemoveCertificateFromStore(certThumb);
                }
                else if (!isMitmCert)
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                    await _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. Cert removal skipped — not MITM-related. CertThumbprint={certThumb}",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                if (int.TryParse(adderPidStr, out int adderPid) && adderPid > 4 && isMitmCert)
                {
                    if (TryConsumeKillBudget())
                        HardeningModule.SafeKillProcessTree(adderPid);
                    else
                        reason += " [kill rate-limited]";
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = isMitmCert ? "REMOVE_CERT_AND_KILL_ADDER" : "LOG",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. CertThumbprint={certThumb}. AdderPID={adderPidStr}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else if (shouldRemoveCert)
            {
                var certThumb = detection.Metadata!.GetValueOrDefault("CertThumbprint", "Unknown");

                // Only remove certs that are MITM-related (planted for interception).
                bool isMitmCert = ResponsePolicy.IsMitmDefenseAction(detection, _config);

                if (!string.IsNullOrEmpty(certThumb) && certThumb != "Unknown" && isMitmCert)
                {
                    RemoveCertificateFromStore(certThumb);
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = isMitmCert ? "REMOVE_CERT" : "LOG",
                    Reason = isMitmCert
                        ? $"Triggered by rule: {detection.RuleName}. {reason}. CertThumbprint={certThumb}"
                        : $"Triggered by rule: {detection.RuleName}. Cert removal skipped — not MITM-related. CertThumbprint={certThumb}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
            }
            else if (shouldQuarantineAndKill)
            {
                // v1.6.0: rate-limit destructive responses
                // v2.1.7 B5: Chain-confirmed detections bypass rate limit
                if (!TryConsumeKillBudget(chainAuthorized))
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                    await _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. QuarantineAndKill rate-limited (MaxKillsPerMinute).",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                // DLL sideloading/injection: quarantine the malicious DLL, kill the host process
                var targetPidStr = detection.Metadata!.GetValueOrDefault("TargetProcessId", "0");
                int.TryParse(targetPidStr, out int targetPid);
                
                string quarantinedInfo = "None";
                if (targetPid > 0 && _dllUnloadEngine != null)
                {
                    var remediateResult = await _dllUnloadEngine.UnloadInjectedDllAsync(targetPid);
                    if (remediateResult.Success && remediateResult.UnloadedDlls.Count > 0)
                    {
                        quarantinedInfo = string.Join(", ", remediateResult.UnloadedDlls);
                    }
                }

                // HARDENING v1.5.9: Verify Authenticode before quarantining the injector binary.
                // Legitimate debugging/profiling tools (e.g., x64dbg, Process Hacker, AV hooking
                // engines) use injection APIs but are validly signed. Quarantining them is an
                // irreversible false positive that destroys the user's tool from disk.
                // Fix: signed injectors are still killed (stop the action) but NOT quarantined.
                // Unsigned/invalid-signature injectors are quarantined as before.
                bool injectorQuarantined = false;
                try
                {
                    using var proc = Process.GetProcessById(detection.ProcessId);
                    // QUERY_LIMITED only — MainModule uses PROCESS_VM_READ (breaks anti-cheat)
                    var quarantinePath = SecurityValidation.GetProcessImagePath(detection.ProcessId)
                                        ?? proc.MainModule?.FileName;
                    if (SecurityValidation.IsGameOrAntiCheatPath(quarantinePath))
                        quarantinePath = null; // never quarantine game binaries from path lookup races
                    if (!string.IsNullOrEmpty(quarantinePath) && File.Exists(quarantinePath))
                    {
                        // QuarantineManager refuses signed binaries by default (returns null).
                        var qPath = await _quarantineManager.QuarantineFileAtomicAsync(quarantinePath!);
                        injectorQuarantined = qPath != null;
                        // signed binary — kill process tree but preserve the file on disk
                    }
                }
                catch { }

                // Terminate injecting process tree
                if (detection.ProcessId > 4)
                {
                    HardeningModule.SafeKillProcessTree(detection.ProcessId);
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = injectorQuarantined ? "QUARANTINE_AND_KILL" : "KILL_ONLY (signed injector preserved)",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. Quarantined={quarantinedInfo}. InjectorQuarantined={injectorQuarantined}. TargetPID={targetPid}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
                TryWriteWindowsEventLog(detection, responseLog.ActionTaken, responseLog.Reason);
                NotifyReinfectionCorrelator(detection);
            }
            else if (shouldIsolateNetwork)
            {
                // v1.6.1: rate-limit isolate storms (decoy C2 / domain-fronting noise)
                if (!TryConsumeIsolateBudget())
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                    await _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. NetworkIsolate rate-limited (MaxNetworkIsolatesPerMinute).",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                // Network-level threat: block suspicious IPs extracted from evidence metadata
                var targetIp = detection.Metadata!.GetValueOrDefault("TargetIP", "");
                if (!string.IsNullOrEmpty(targetIp))
                {
                    // Validate IP before creating firewall rules
                    // v1.8.1 RT-NEW-3: never firewall-block private/LAN/gateway (decoy beaconing)
                    if (!System.Net.IPAddress.TryParse(targetIp, out var parsedIp) ||
                        System.Net.IPAddress.IsLoopback(parsedIp) ||
                        targetIp == "0.0.0.0" || targetIp == "255.255.255.255" ||
                        SecurityValidation.IsPrivateIpAddress(targetIp) ||
                        IsMulticastOrUnspecified(parsedIp) ||
                        IsLikelyCdnOrPublicResolver(parsedIp))
                    {
                        // Skip invalid/loopback/private/broadcast/CDN-or-resolver IPs (collateral)
                    }
                    else
                    {
                        IsolateNetworkTarget(targetIp, detection.RuleName);
                        // v1.8.1: restore ARP entry purge (lost in LOLBin-free rewrite).
                        // Was `arp -d` shell-out (v5.9.0); now DeleteIpNetEntry P/Invoke only.
                        FlushArpEntry(targetIp);
                    }
                }

                // Also flush DNS cache to clear poisoned entries
                FlushDnsCache();

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "NETWORK_ISOLATE",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. Target={targetIp}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
                TryWriteWindowsEventLog(detection, responseLog.ActionTaken, responseLog.Reason);
            }
            else if (shouldRemoveRegistryEntry)
            {
                var hive = detection.Metadata!.GetValueOrDefault("Hive", "HKLM");
                var keyPath = detection.Metadata!.GetValueOrDefault("KeyPath", "");
                var valueName = detection.Metadata!.GetValueOrDefault("ValueName", "");
                var subKey = detection.Metadata!.GetValueOrDefault("SubKey", "");
                var removed = false;
                var removalLog = "";

                try
                {
                    if (!string.IsNullOrEmpty(valueName) && !string.IsNullOrEmpty(keyPath))
                    {
                        // Remove a specific value from a key
                        var regHive = hive switch
                        {
                            "HKCU" => Microsoft.Win32.Registry.CurrentUser,
                            "HKCR" => Microsoft.Win32.Registry.ClassesRoot,
                            _ => Microsoft.Win32.Registry.LocalMachine
                        };
                        using var key = regHive.OpenSubKey(keyPath, writable: true);
                        if (key != null)
                        {
                            key.DeleteValue(valueName, throwOnMissingValue: false);
                            removed = true;
                            removalLog = $"Removed value '{valueName}' from {hive}\\{keyPath}";
                        }
                    }
                    else if (!string.IsNullOrEmpty(subKey) && keyPath.Contains("Services"))
                    {
                        // Remove a service subkey
                        using var servicesKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, writable: true);
                        if (servicesKey != null)
                        {
                            servicesKey.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
                            removed = true;
                            removalLog = $"Removed service subkey '{subKey}' from {hive}\\{keyPath}";
                        }
                    }
                    else if (!string.IsNullOrEmpty(keyPath) && keyPath.Contains("CLSID"))
                    {
                        // Remove a CLSID subkey tree
                        using var clsidKey = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(keyPath, writable: true);
                        if (clsidKey != null)
                        {
                            var parent = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey("CLSID", writable: true);
                            if (parent != null)
                            {
                                var clsid = detection.Metadata!.GetValueOrDefault("CLSID", "");
                                if (!string.IsNullOrEmpty(clsid))
                                {
                                    parent.DeleteSubKeyTree(clsid, throwOnMissingSubKey: false);
                                    removed = true;
                                    removalLog = $"Removed CLSID '{clsid}' from HKCR\\CLSID";
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    removalLog = $"Failed to remove registry entry: {ex.Message}";
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = removed ? "REMOVE_REGISTRY_ENTRY" : "REMOVE_REGISTRY_ENTRY_FAILED",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. {removalLog}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
                TryWriteWindowsEventLog(detection, responseLog.ActionTaken, responseLog.Reason);
            }
            else if (shouldKill && detection.ProcessId > 4)
            {
                // v1.6.0: rate-limit kill storms
                // v2.1.7 B5: Chain-confirmed detections bypass rate limit
                if (!TryConsumeKillBudget(chainAuthorized))
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                    await _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. Kill rate-limited (MaxKillsPerMinute).",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                // Collect forensic evidence before killing
                try { if (_incidentResponse != null) _ = _incidentResponse.CollectEvidenceAsync(detection); } catch { }

                var reasonText = $"Triggered by rule: {detection.RuleName}. {reason}";
                if (_chainTracer != null)
                {
                    var traceResult = await _chainTracer.TraceAndRespondAsync(detection);
                    if (traceResult != null && traceResult.Success)
                    {
                        if (traceResult.AttackRoot != null)
                        {
                            reasonText += $". Root source of attack: {traceResult.AttackRoot.ProcessName} (PID {traceResult.AttackRoot.ProcessId}, Path: '{traceResult.AttackRoot.ImagePath ?? "unknown"}')";
                        }
                        if (traceResult.QuarantinedFiles.Count > 0)
                        {
                            var files = string.Join(", ", traceResult.QuarantinedFiles.Select(f => $"{f.ProcessName} ('{f.OriginalPath}')"));
                            reasonText += $". Quarantined source files: {files}";
                        }
                    }
                }
                else
                {
                    HardeningModule.SafeKillProcessTree(detection.ProcessId);
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "KILL",
                    Reason = reasonText,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
                TryWriteWindowsEventLog(detection, responseLog.ActionTaken, responseLog.Reason);
                NotifyReinfectionCorrelator(detection);
            }
            else
            {
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = reason,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await _eventLogger.LogEventAsync("response", responseLog);
                // LogOnly never writes Windows Event Log (CriticalOnly trail)
            }
        }

        private void NotifyReinfectionCorrelator(DetectionEvent detection)
        {
            try
            {
                if (_reinfectionCorrelator == null) return;
                var hash = detection.Metadata?.GetValueOrDefault("SHA256", "");
                if (string.IsNullOrEmpty(hash))
                {
                    // Try to compute hash from process image
                    try
                    {
                        using var proc = Process.GetProcessById(detection.ProcessId);
                        var path = SecurityValidation.GetProcessImagePath(detection.ProcessId);
                        if (!string.IsNullOrEmpty(path) && File.Exists(path))
                        {
                            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                FileShare.ReadWrite | FileShare.Delete);
                            hash = ConvertHex.ToHexString(System.Security.Cryptography.Sha256Net48.HashData(fs)).ToLowerInvariant();
                        }
                    }
                    catch { }
                }
                if (!string.IsNullOrEmpty(hash))
                {
                    _reinfectionCorrelator.RegisterKilledHash(hash!, detection.ProcessName ?? "unknown", detection.ProcessName ?? "unknown");
                }
            }
            catch { }
        }

        private void RemoveCertificateFromStore(string thumbprint)
        {
            var stores = new (System.Security.Cryptography.X509Certificates.StoreName Name, System.Security.Cryptography.X509Certificates.StoreLocation Location)[]
            {
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser)
            };

            foreach (var (storeName, storeLocation) in stores)
            {
                try
                {
                    using var store = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation);
                    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);

                    var certs = store.Certificates.Find(
                        System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                        thumbprint,
                        validOnly: false);

                    foreach (var cert in certs)
                    {
                        store.Remove(cert);
                        _eventLogger.LogEventAsync("debug", new { Message = $"Successfully removed cert {thumbprint} from {storeName} ({storeLocation})" }).GetAwaiter().GetResult();
                    }
                }
                catch (Exception ex)
                {
                    _eventLogger.LogEventAsync("debug", new { Message = $"Failed to open/remove cert {thumbprint} from {storeName} ({storeLocation}): {ex.Message}" }).GetAwaiter().GetResult();
                }
            }
        }

        private void IsolateNetworkTarget(string ip, string ruleName)
        {
            var safeName = ip.Replace('.', '_').Replace(':', '_');
            var fwRule = $"Sentinel-Isolate-{safeName}";

            try
            {
                // Use Windows Firewall COM API (INetFwPolicy2) instead of shelling out to netsh.
                // This avoids Process.Start patterns that AV engines flag as malware behavior.
                var fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (fwPolicyType == null) return;
                dynamic? fwPolicy = Activator.CreateInstance(fwPolicyType);
                if (fwPolicy == null) return;

                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (ruleType == null) return;

                // Outbound block
                dynamic? outRule = Activator.CreateInstance(ruleType);
                if (outRule != null)
                {
                    outRule.Name = $"{fwRule}-OUT";
                    outRule.Description = $"Sentinel: Block outbound to {ip} ({ruleName})";
                    outRule.Direction = 2; // NET_FW_RULE_DIR_OUT
                    outRule.Action = 0;    // NET_FW_ACTION_BLOCK
                    outRule.RemoteAddresses = ip;
                    outRule.Enabled = true;
                    outRule.Profiles = 0x7FFFFFFF; // All profiles
                    fwPolicy.Rules.Add(outRule);
                }

                // Inbound block
                dynamic? inRule = Activator.CreateInstance(ruleType);
                if (inRule != null)
                {
                    inRule.Name = $"{fwRule}-IN";
                    inRule.Description = $"Sentinel: Block inbound from {ip} ({ruleName})";
                    inRule.Direction = 1; // NET_FW_RULE_DIR_IN
                    inRule.Action = 0;    // NET_FW_ACTION_BLOCK
                    inRule.RemoteAddresses = ip;
                    inRule.Enabled = true;
                    inRule.Profiles = 0x7FFFFFFF;
                    fwPolicy.Rules.Add(inRule);
                }
            }
            catch (Exception ex)
            {
                // Fallback: if COM fails (e.g., service not running), log and continue
                _eventLogger.LogEventAsync("debug", new { Message = $"Firewall COM failed for {ip}: {ex.Message}" }).GetAwaiter().GetResult();
            }
        }

        private static void FlushDnsCache()
        {
            try
            {
                // DnsFlushResolverCache is a documented public API — not a shell-out
                DnsFlushResolverCache();
            }
            catch { }
        }

        /// <summary>
        /// v1.8.1: Drop a single IPv4 ARP cache entry without shelling to <c>arp.exe</c>.
        /// Restores NetworkIsolate parity with v5.9.0 (firewall + ARP + DNS flush).
        /// </summary>
        private static void FlushArpEntry(string ip)
        {
            try
            {
                if (!IPAddress.TryParse(ip, out var addr) ||
                    addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    return;

                var ipBytes = addr.GetAddressBytes();
                uint ipInt = BitConverter.ToUInt32(ipBytes, 0);
                if (GetBestInterface(ipInt, out int ifIndex) != 0)
                    return;

                var row = new MibIpNetRow
                {
                    dwIndex = ifIndex,
                    dwAddr = unchecked((int)ipInt)
                };
                DeleteIpNetEntry(ref row);
            }
            catch { }
        }

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern uint DnsFlushResolverCache();

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetBestInterface(uint dwDestAddr, out int pdwBestIfIndex);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int DeleteIpNetEntry(ref MibIpNetRow pArpEntry);

        [StructLayout(LayoutKind.Sequential)]
        private struct MibIpNetRow
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

        /// <summary>
        /// v1.6.1: Avoid firewall-blocking major public resolvers / well-known CDN anycast
        /// prefixes when decoy beaconing tries to force NetworkIsolate collateral damage.
        /// Not exhaustive — best-effort guardrail.
        /// </summary>
        private static bool IsLikelyCdnOrPublicResolver(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4)
            {
                // Cloudflare 1.1.1.0/24, 1.0.0.0/24
                if (bytes[0] == 1 && (bytes[1] == 1 || bytes[1] == 0)) return true;
                // Google DNS 8.8.8.0/24, 8.8.4.0/24
                if (bytes[0] == 8 && bytes[1] == 8) return true;
                // Quad9 9.9.9.0/24
                if (bytes[0] == 9 && bytes[1] == 9 && bytes[2] == 9) return true;
            }
            return false;
        }

        private static bool IsMulticastOrUnspecified(IPAddress ip)
        {
            if (IPAddress.Any.Equals(ip) || IPAddress.IPv6Any.Equals(ip)) return true;
            if (ip.IsIPv6Multicast) return true;
            var bytes = ip.GetAddressBytes();
            // IPv4 multicast 224.0.0.0/4
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4
                && bytes[0] >= 224 && bytes[0] <= 239)
                return true;
            return false;
        }
    }
}
