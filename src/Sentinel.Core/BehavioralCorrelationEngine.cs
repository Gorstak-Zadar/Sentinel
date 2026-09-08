using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public class BehavioralCorrelationEngine
    {
        private readonly ConcurrentDictionary<int, List<DetectionEvent>> _signalBuffers = new();
        private Func<DetectionEvent, Task>? _emitCallback;
        private DateTime _lastPruneTime = DateTime.UtcNow;

        private static readonly HashSet<string> ElectronAndJitApps = new(StringComparer.OrdinalIgnoreCase)
        {
            "code", "cursor", "Devin", "discord", "slack", "teams", "steamwebhelper",
            "spotify", "brave", "chrome", "msedge", "fm", "kiro",
            "sppsvc", "WmiPrvSE", "MsMpEng", "MpDefenderCoreService",
            "NisSrv", "SgrmBroker", "OneDrive",
            "MicrosoftStartFeedProvider", "backgroundTaskHost", "widgets",
            "GameBarPresenceWriter", "sihost", "taskhostw",
            "SearchHost", "StartMenuExperienceHost", "explorer"
        };

        private const int MaxSignalsPerBuffer = 50;
        private const int MaxAllowlistedTier2Buffer = 5;
        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan PruneInterval = TimeSpan.FromSeconds(60);

        // v2.3.8: MotwBypassMonitor / WpadProxyMonitor emit ProcessId=0 (file/host fuel).
        // RegisterSignalAsync used to drop pid<=0, so claimed MOTW/WPAD composites never fired.
        private readonly List<DetectionEvent> _hostWideDelivery = new();

        public void Initialize(Func<DetectionEvent, Task> emitCallback)
        {
            _emitCallback = emitCallback;
        }

        public async Task RegisterSignalAsync(DetectionEvent signal)
        {
            var pid = signal.ProcessId;
            if (pid <= 0)
            {
                if (IsHostWideDeliveryFuel(signal))
                    BufferHostWideDelivery(signal);
                return;
            }

            if (ResponsePolicy.IsNonCorrelatingObserveNoise(signal))
                return;

            PruneStaleBuffers();

            var stem = Sentinel.Core.StringNet48.ReplaceIgnoreCase(signal.ProcessName, ".exe", "");
            if (ElectronAndJitApps.Contains(stem))
            {
                var path = ResolveImagePath(pid);
                if (!string.IsNullOrEmpty(path) && SecurityValidation.VerifyAuthenticodeSignature(path!))
                {
                    if (signal.Tier != DetectionTier.Tier1Behavioral)
                    {
                        var existingBuffer = _signalBuffers!.GetValueOrDefault(pid);
                        bool hasExistingSignals = false;
                        if (existingBuffer != null)
                        {
                            lock (existingBuffer)
                            {
                                hasExistingSignals = existingBuffer.Count > 0;
                            }
                        }
                        if (!hasExistingSignals)
                        {
                            var t2Buffer = _signalBuffers.GetOrAdd(pid, _ => new List<DetectionEvent>());
                            lock (t2Buffer)
                            {
                                if (t2Buffer.Count < MaxAllowlistedTier2Buffer)
                                {
                                    t2Buffer.Add(signal);
                                }
                            }
                            return;
                        }
                    }
                }
            }

            var buffer = _signalBuffers.GetOrAdd(pid, _ => new List<DetectionEvent>());
            lock (buffer)
            {
                buffer.Add(signal);
                if (buffer.Count > MaxSignalsPerBuffer)
                {
                    buffer.RemoveAt(0);
                }

                var cutoff = DateTime.UtcNow - CorrelationWindow;
                buffer.RemoveAll(s => s.Timestamp < cutoff);
            }

            await EvaluateCompositesAsync(pid, buffer);
        }

        private async Task EvaluateCompositesAsync(int pid, List<DetectionEvent> signals)
        {
            if (_emitCallback == null) return;

            List<DetectionEvent> currentSignals;
            lock (signals)
            {
                currentSignals = new List<DetectionEvent>(signals);
            }

            MergeHostWideDelivery(currentSignals);

            if (currentSignals.Count < 2) return;

            var types = new HashSet<SignalType>(currentSignals.Select(s => s.SignalType));
            var distinctRules = currentSignals.Select(s => s.RuleName).Distinct().Count();

            // Highest confidence composites first (return on match).
            // Active mass-encryption chain (0.99): multiple distinct encryption/wipe indicators.
            if (currentSignals.Count(s => s.SignalType == SignalType.Ransomware) >= 2 &&
                currentSignals.Where(s => s.SignalType == SignalType.Ransomware).Select(s => s.RuleName).Distinct().Count() >= 2)
            {
                await EmitCompositeAsync(pid, "Active Mass-Encryption Chain", 0.99,
                    "Multiple distinct mass-encryption indicators from independent sources.",
                    "Shadow copy destruction, backup deletion, or mass file encryption confirmed by cross-signal correlation.");
                return;
            }

            if (types.Contains(SignalType.ProcessInjection) && types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "Injected C2 Beacon", 0.98,
                    "Kernel-observed process injection followed by C2 network activity.",
                    "Code was injected into this process and it subsequently established command-and-control communication.");
                return;
            }

            if ((types.Contains(SignalType.LsassAccess) || types.Contains(SignalType.CredentialTheft)) &&
                types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "Credential Dump + Exfiltration", 0.96,
                    "Credential access combined with outbound network communication.",
                    "Credential material was accessed and network exfiltration was observed on the same process.");
                return;
            }

            if (types.Contains(SignalType.ProcessInjection) &&
                (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell)))
            {
                await EmitCompositeAsync(pid, "In-Memory Implant Active", 0.96,
                    "Memory anomaly (injection/RWX) combined with network callback.",
                    "Process exhibits in-memory code execution anomalies alongside active network communication - consistent with a loaded implant.");
                return;
            }

            if (currentSignals.Any(s => s.ProcessId > 0 &&
                    (s.SignalType == SignalType.AmsiTampering || s.SignalType == SignalType.EtwTampering || s.SignalType == SignalType.SecurityEvasion)) &&
                (types.Contains(SignalType.ReverseShell) || types.Contains(SignalType.NetworkC2)))
            {
                await EmitCompositeAsync(pid, "Fileless Attack Chain", 0.95,
                    "Security evasion (AMSI/ETW tampering) combined with shell or C2 activity.",
                    "Process disabled security telemetry then established external communication - hallmark of staged fileless attack.");
                return;
            }

            var hasDnsAnomaly = currentSignals.Any(s =>
                s.RuleName.Contains("DNS") &&
                (s.RuleName.Contains("DGA") ||
                 s.RuleName.Contains("Rapid") ||
                 s.RuleName.Contains("Tunnel")));
            if (hasDnsAnomaly && types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "DGA + C2 Beaconing", 0.94,
                    "Algorithmically-generated DNS queries correlated with periodic C2 callbacks.",
                    "Process resolved high-entropy or high-volume domains and maintains regular beacon timing - DGA-based C2 channel.");
                return;
            }

            var hasUnsignedOrSuspicious = currentSignals.Any(s =>
                s.ProcessId > 0 &&
                (s.SignalType == SignalType.SuspiciousProcess ||
                 s.RuleName.Contains("Unsigned") ||
                 s.RuleName.Contains("Suspicious Path") ||
                 s.RuleName.Contains("Attack Tool")));
            var hasStagingPath = currentSignals.Any(s =>
                s.RuleName.Contains("Staging") ||
                s.Evidence?.Contains("\\Temp\\") == true ||
                s.Evidence?.Contains("\\AppData\\") == true);
            var hasRecon = currentSignals.Any(s =>
                s.RuleName.Contains("Recon") ||
                s.RuleName.Contains("Enumeration") ||
                s.RuleName.Contains("Discovery"));
            if (hasUnsignedOrSuspicious && hasStagingPath && types.Contains(SignalType.NetworkC2))
            {
                double covertRatConfidence = hasRecon ? 0.92 : 0.88;
                await EmitCompositeAsync(pid, "Covert RAT: Unsigned + Hidden + Network", covertRatConfidence,
                    "Unsigned binary from staging path with sustained network activity.",
                    "A binary from a staging directory (Temp/AppData) initiated C2 networking - behavioral RAT pattern detected without campaign IOCs.");
                return;
            }

            var hasBeaconing = currentSignals.Any(s =>
                s.RuleName.Contains("Beaconing") ||
                s.RuleName.Contains("Beacon"));
            if (hasUnsignedOrSuspicious && hasBeaconing)
            {
                double beaconConfidence = hasStagingPath ? 0.93 : 0.88;
                await EmitCompositeAsync(pid, "Confirmed C2 Beacon: Unsigned Process", beaconConfidence,
                    "Unsigned binary exhibiting periodic beaconing pattern.",
                    "An unsigned process maintains regular-interval callbacks characteristic of C2 beaconing - confirms active command-and-control regardless of framework.");
                return;
            }

            var hasSustainedConnection = currentSignals.Any(s =>
                s.RuleName.Contains("Sustained") ||
                s.RuleName.Contains("Long-lived") ||
                s.RuleName.Contains("Persistent Connection") ||
                (s.SignalType == SignalType.NetworkC2 &&
                 s.Evidence?.Contains("60s") == true));
            if (hasUnsignedOrSuspicious && hasSustainedConnection)
            {
                await EmitCompositeAsync(pid, "Covert C2: Unsigned + Sustained Connection", 0.90,
                    "Unsigned binary maintaining a 60s+ outbound connection.",
                    "An unsigned binary holds a persistent outbound connection - matches PlugX/RAT pattern of fake updater from temp path holding HTTPS to C2.");
                return;
            }

            if (hasUnsignedOrSuspicious && types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "Dropped Payload Active", 0.93,
                    "Unsigned or staged binary established C2 communication.",
                    "A binary from an untrusted path initiated command-and-control networking - consistent with a deployed implant or RAT.");
                return;
            }

            var hasNamedPipe = currentSignals.Any(s =>
                s.RuleName.Contains("Named Pipe"));
            if (hasNamedPipe && types.Contains(SignalType.NetworkC2))
            {
                await EmitCompositeAsync(pid, "Named Pipe C2 + Network Beaconing", 0.95,
                    "Suspicious named pipe correlated with C2 network beaconing on the same process.",
                    "A process created a named pipe matching C2/lateral-movement patterns AND maintains periodic network beaconing - confirms active C2 implant using IPC for inter-process staging.");
                return;
            }

            var hasPpidSpoof = currentSignals.Any(s =>
                s.RuleName.Contains("Parent") &&
                s.RuleName.Contains("Spoof"));
            if (hasPpidSpoof && (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell)))
            {
                await EmitCompositeAsync(pid, "Spoofed Process Phoning Home", 0.92,
                    "Process with spoofed parent established network communication.",
                    "Parent PID spoofing was detected on a process that subsequently made outbound connections - evading parent-chain-based trust.");
                return;
            }

            var hasPersistence = currentSignals.Any(s =>
                s.RuleName.Contains("Autorun") ||
                s.RuleName.Contains("Service") ||
                s.RuleName.Contains("Scheduled Task") ||
                s.RuleName.Contains("Registry"));
            if (types.Contains(SignalType.SecurityEvasion) && hasPersistence)
            {
                await EmitCompositeAsync(pid, "Evasion + Persistence Install", 0.91,
                    "Security evasion combined with persistence mechanism installation.",
                    "Process evaded security controls then installed persistence - establishing long-term access.");
                return;
            }

            var hasTokenTheft = currentSignals.Any(s =>
                s.RuleName.Contains("Token Theft") ||
                s.RuleName.Contains("Impersonate"));
            var hasLateralMovement = currentSignals.Any(s =>
                s.RuleName.Contains("Lateral") ||
                s.RuleName.Contains("RPC") ||
                s.RuleName.Contains("Named Pipe") ||
                s.RuleName.Contains("Network Share"));
            if (hasTokenTheft && hasLateralMovement)
            {
                await EmitCompositeAsync(pid, "Token Theft + Lateral Movement", 0.93,
                    "Token manipulation combined with lateral movement indicators on the same process.",
                    "Process stole/impersonated a privileged token then initiated lateral movement (RPC/SMB/named pipe) - classic post-exploitation pivot pattern (MITRE T1134 + T1021).");
                return;
            }

            var hasPrivEsc = currentSignals.Any(s =>
                s.RuleName.Contains("Privilege") ||
                s.RuleName.Contains("Escalation") ||
                s.RuleName.Contains("Token") ||
                s.RuleName.Contains("LPE Scaffold"));
            if (hasPrivEsc && (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell)))
            {
                await EmitCompositeAsync(pid, "Escalation + C2 Channel", 0.90,
                    "Privilege escalation observed alongside outbound C2 communication.",
                    "Process escalated privileges then communicated externally - post-exploitation lateral movement preparation.");
                return;
            }

            var hasLpeScaffold = currentSignals.Any(s =>
                s.RuleName.Contains("LPE Scaffold") ||
                s.RuleName.Contains("Privilege Escalation Tool") ||
                s.RuleName.Contains("Elevated Process from Staging"));
            var hasUacOrPotato = currentSignals.Any(s =>
                s.RuleName.Contains("UAC Bypass") ||
                s.RuleName.Contains("Potato") ||
                s.RuleName.Contains("PrintSpoof") ||
                s.RuleName.Contains("PrivilegeEscalation"));
            if (hasLpeScaffold && (hasTokenTheft || hasUacOrPotato || types.Contains(SignalType.NetworkC2)))
            {
                await EmitCompositeAsync(pid, "LPE Campaign Scaffold", 0.93,
                    "Local privilege-escalation tooling or elevated staging binary correlated with token/network activity.",
                    "Userland LPE campaign pattern (potato-class / elevated unsigned staging + token or C2). " +
                    "Stops post-exploitation scaffolding; does not patch kernel races (apply OS updates for afd.sys-class bugs).");
                return;
            }

            var hasInitialAccess = currentSignals.Any(s =>
                s.RuleName.Contains("Initial Access:") ||
                s.RuleName.Contains("Browser Spawned LOLBin") ||
                s.RuleName.Contains("Office Spawned LOLBin") ||
                s.RuleName.Contains("LOLBin from Staging"));
            if (hasInitialAccess &&
                (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell) ||
                 types.Contains(SignalType.ProcessInjection) || hasUnsignedOrSuspicious ||
                 currentSignals.Any(s => s.RuleName.Contains("Script") || s.RuleName.Contains("Encoded"))))
            {
                await EmitCompositeAsync(pid, "Initial Access Execution Chain", 0.92,
                    "Browser/Office/staging LOLBin correlated with network, injection, or script abuse.",
                    "Classic initial-access chain: document or download path spawning LOLBin with corroborating " +
                    "C2/injection/script signals (ISO/smuggling/macro-adjacent).");
                return;
            }

            var hasWmiPersist = currentSignals.Any(s =>
                s.RuleName.Contains("Hostile Event Subscription") ||
                s.RuleName.Contains("WMI-Activity: Permanent") ||
                s.RuleName.Contains("WMI Persistence:"));
            var hasWmiPolicy = currentSignals.Any(s =>
                s.RuleName.Contains("WMI Policy Rewrite"));
            if (hasWmiPersist && hasWmiPolicy)
            {
                await EmitCompositeAsync(pid, "WMI Persistence + Policy Rewrite", 0.94,
                    "WMI filter/consumer/binding correlated with SOFTWARE\\Policies hive write from a WMI host.",
                    "Fileless stay-behind (T1546.003) plus StdRegProv policy overwrite from WmiPrvSE/wmiadap/scrcons.");
                return;
            }

            var hasPersistSurface = currentSignals.Any(s =>
                s.RuleName.Contains("Persistence:") ||
                s.RuleName.Contains("IFEO") ||
                s.RuleName.Contains("COM/Protocol Handler") ||
                s.RuleName.Contains("Accessibility") ||
                s.RuleName.Contains("Winlogon"));
            if (hasPersistSurface &&
                (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell) ||
                 hasLpeScaffold || hasUacOrPotato))
            {
                await EmitCompositeAsync(pid, "Persistence + Abuse Channel", 0.91,
                    "IFEO/COM/accessibility/Winlogon persistence correlated with LPE or network channel.",
                    "Host persistence surface modified alongside escalation or remote channel - post-compromise stay-behind pattern.");
                return;
            }

            var hasDreamJob = currentSignals.Any(s =>
                s.RuleName.Contains("Dream Job") ||
                s.RuleName.Contains("Lazarus") ||
                s.RuleName.Contains("SecurityPDF") ||
                s.RuleName.Contains("FudModule") ||
                s.RuleName.Contains("MuPDF sideload"));
            bool IsDreamJobRule(DetectionEvent s) =>
                s.RuleName.Contains("Dream Job") ||
                s.RuleName.Contains("Lazarus") ||
                s.RuleName.Contains("SecurityPDF") ||
                s.RuleName.Contains("FudModule") ||
                s.RuleName.Contains("MuPDF sideload");
            var dreamJobDistinct = currentSignals
                .Where(IsDreamJobRule)
                .Select(s => s.RuleName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            var hasDreamJobCorroboration =
                dreamJobDistinct >= 2 ||
                currentSignals.Any(s => !IsDreamJobRule(s) &&
                    (s.SignalType == SignalType.NetworkC2 ||
                     s.SignalType == SignalType.ProcessInjection ||
                     s.SignalType == SignalType.ReverseShell)) ||
                hasLpeScaffold || hasTokenTheft || hasUacOrPotato;
            if (hasDreamJob && hasDreamJobCorroboration)
            {
                await EmitCompositeAsync(pid, "Lazarus Dream Job Chain", 0.95,
                    "Operation Dream Job loader/sideload/C2 correlated with LPE, injection, token, or network.",
                    "Lazarus userland chain around CVE-2026-68820 (SecurityPDF / libmupdf sideload / FudModule / Troy C2). " +
                    "Stops the campaign; does not patch afd.sys - install KB5121003.");
                return;
            }

            var hasLegacyHive = currentSignals.Any(s => s.RuleName.Contains("LegacyHive"));
            if (hasLegacyHive && (hasPrivEsc || hasTokenTheft || hasUacOrPotato || hasLpeScaffold))
            {
                await EmitCompositeAsync(pid, "LegacyHive Privilege Escalation Chain", 0.92,
                    "Another user's registry hive loaded (CVE-2026-62832) correlated with token/UAC/LPE.",
                    "LegacyHive: User Profile Service / custom HKU load plus escalation tooling.");
                return;
            }

            var hasCloudFiles = currentSignals.Any(s =>
                s.RuleName.Contains("Cloud Files:") ||
                s.RuleName.Contains("ShieldBreak"));
            var hasSystemWrite = currentSignals.Any(s =>
                s.RuleName.IndexOf("System32", StringComparison.OrdinalIgnoreCase) >= 0 ||
                s.RuleName.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) >= 0 ||
                s.RuleName.IndexOf("File Integrity", StringComparison.OrdinalIgnoreCase) >= 0);
            if (hasCloudFiles && (hasPrivEsc || hasSystemWrite || hasLpeScaffold || hasUacOrPotato))
            {
                await EmitCompositeAsync(pid, "Cloud Files Hydration Tamper Chain", 0.91,
                    "Unauthorized CfApi sync root or Cloud Files placeholder correlated with tamper/escalation.",
                    "ShieldBreak / CVE-2026-62713 class: Cloud Files hydration TOCTOU plus a system-path or LPE leg. " +
                    "Does not disable OneDrive.");
                return;
            }

            var hasKernelExploitLoader = currentSignals.Any(s =>
                s.RuleName.Contains("Kernel Exploit Loader") ||
                s.RuleName.Contains("Isolation Filter Driver"));
            if (hasKernelExploitLoader && (hasTokenTheft || hasLpeScaffold || hasUacOrPotato || hasPrivEsc))
            {
                await EmitCompositeAsync(pid, "Kernel Exploit Loader Chain", 0.94,
                    "Kernel-EoP loader or isolation-filter staging correlated with token/LPE.",
                    "Userland exploit-host pattern for AFD/WinSock/unionfs-class elevation. Stops the loader; does not patch the kernel race.");
                return;
            }

            var hasInstallerEop = currentSignals.Any(s =>
                s.RuleName.Contains("Installer EoP") ||
                s.RuleName.Contains("AlwaysInstallElevated") ||
                s.RuleName.Contains("Package Manager EoP"));
            if (hasInstallerEop && (hasLpeScaffold || hasTokenTheft || hasUacOrPotato || hasPrivEsc))
            {
                await EmitCompositeAsync(pid, "Installer / Package Manager EoP Chain", 0.92,
                    "MSI repair/winget/AlwaysInstallElevated correlated with token or LPE.",
                    "Windows Installer / Package Manager elevation class (CVE-2026-61925 / CVE-2026-68821) plus an escalation leg.");
                return;
            }

            var hasMotwDelivery = currentSignals.Any(s =>
                s.RuleName.Contains("Mark-of-the-Web") ||
                s.RuleName.Contains("Disk Image in Delivery") ||
                s.RuleName.Contains("AppInstaller Package") ||
                s.RuleName.Contains("ClickFix Encoded") ||
                s.RuleName.Contains("Script Dropper"));
            if (hasMotwDelivery &&
                (hasInitialAccess || types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell) ||
                 currentSignals.Any(s => s.RuleName.Contains("Script") || s.RuleName.Contains("Encoded"))))
            {
                await EmitCompositeAsync(pid, "MOTW Bypass Execution Chain", 0.91,
                    "MOTW-strip / ISO / ClickFix delivery correlated with LOLBin, script, or C2.",
                    "Initial-access delivery that bypasses Mark-of-the-Web plus execution or callback.");
                return;
            }

            var hasVsCodeAbuse = currentSignals.Any(s =>
                s.RuleName.Contains("VS Code Encoded") ||
                s.RuleName.Contains("VSIX in Delivery"));
            if (hasVsCodeAbuse &&
                (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell) ||
                 hasInitialAccess || currentSignals.Any(s => s.RuleName.Contains("Script"))))
            {
                await EmitCompositeAsync(pid, "VS Code Workspace Abuse Chain", 0.91,
                    "VS Code / Copilot encoded shell or sideloaded VSIX correlated with script or C2.",
                    "Editor security-feature-bypass class (CVE-2026-58650 / CVE-2026-70335) plus corroborating execution.");
                return;
            }

            var hasWpadHijack = currentSignals.Any(s =>
                s.RuleName.IndexOf("WPAD", StringComparison.OrdinalIgnoreCase) >= 0 ||
                s.RuleName.IndexOf("Auto-Proxy PAC", StringComparison.OrdinalIgnoreCase) >= 0);
            if (hasWpadHijack &&
                (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell) ||
                 currentSignals.Any(s => s.RuleName.Contains("Exfil") || s.RuleName.Contains("Beacon"))))
            {
                await EmitCompositeAsync(pid, "WPAD Proxy Hijack Chain", 0.9,
                    "Rogue/changed auto-proxy PAC correlated with outbound C2 or data exfiltration.",
                    "DHCP Option 252 / WPAD man-in-the-middle: an attacker-controlled PAC URL reroutes browser " +
                    "traffic through a hostile proxy, plus corroborating C2/exfil. Does not revert the proxy setting.");
                return;
            }

            var hasSurveillance = currentSignals.Any(CoercionAbusePolicy.IsSurveillanceRule);
            var hasRemoteLeg = currentSignals.Any(CoercionAbusePolicy.IsRemoteControlRule) ||
                               types.Contains(SignalType.ReverseShell) ||
                               types.Contains(SignalType.NetworkC2);
            if (hasSurveillance && hasRemoteLeg)
            {
                await EmitCompositeAsync(pid, "Covert Surveillance + Remote Channel", 0.94,
                    "Screen/camera/input surveillance correlated with remote control or outbound C2.",
                    "Covert capture (screen/webcam/keystroke-class) plus remote channel on the same process - " +
                    "endpoint pattern used in stalkerware and coercive remote control of a victim PC. " +
                    "Platform-agnostic (messaging, social, email, browsers, games - host traces only).",
                    tagCoercionToolkit: true);
                return;
            }

            var hasRemoteTool = currentSignals.Any(s =>
                CoercionAbusePolicy.IsRemoteAccessToolProcess(s.ProcessName) ||
                CoercionAbusePolicy.IsRemoteControlRule(s));
            var hasStagingOrInject =
                hasStagingPath ||
                types.Contains(SignalType.ProcessInjection) ||
                hasUnsignedOrSuspicious;
            var hasRemoteChannel = types.Contains(SignalType.NetworkC2) ||
                                   types.Contains(SignalType.ReverseShell);
            if (hasRemoteTool && hasStagingOrInject && hasRemoteChannel)
            {
                await EmitCompositeAsync(pid, "Remote Control Abuse Toolkit", 0.93,
                    "Remote-control tooling from untrusted context with network or injection corroboration.",
                    "Remote administration / RAT-class tooling combined with staging path, unsigned binary, " +
                    "or injection - common in coercive takeover of a victim workstation (AnyDesk/TeamViewer-class " +
                    "abuse, commodity RATs). Not a judgment about the operator's identity.",
                    tagCoercionToolkit: true);
                return;
            }

            var hasSessionTheft = currentSignals.Any(CoercionAbusePolicy.IsSessionTheftRule);
            if (hasSessionTheft &&
                (types.Contains(SignalType.NetworkC2) || types.Contains(SignalType.ReverseShell) ||
                 currentSignals.Any(s => s.RuleName.Contains("Exfil") || s.RuleName.Contains("Upload"))))
            {
                await EmitCompositeAsync(pid, "Session Theft + Abuse Channel", 0.95,
                    "Credential/session store access correlated with outbound abuse channel.",
                    "Browser/OS credential or session material accessed with concurrent network/exfil channel - " +
                    "account takeover toolkit for email, messaging, social, banking, games (not limited to one app).",
                    tagCoercionToolkit: true);
                return;
            }

            var hasPersistForSpy = currentSignals.Any(s =>
                s.RuleName.Contains("Autorun") ||
                s.RuleName.Contains("Scheduled Task") ||
                s.RuleName.Contains("Persistence") ||
                s.RuleName.Contains("Run Key") ||
                s.RuleName.Contains("Startup"));
            if (hasSurveillance && hasPersistForSpy)
            {
                await EmitCompositeAsync(pid, "Stalkerware Persistence Chain", 0.92,
                    "Covert surveillance capability combined with persistence installation.",
                    "Capture/surveillance signal plus autorun/persistence - classic stalkerware footprint " +
                    "for long-term monitoring of a victim device.",
                    tagCoercionToolkit: true);
                return;
            }
        }

        private async Task EmitCompositeAsync(
            int pid,
            string ruleName,
            double confidence,
            string evidence,
            string reasoning,
            bool tagCoercionToolkit = false)
        {
            string name = "unknown";
            if (_signalBuffers.TryGetValue(pid, out var buffer))
            {
                lock (buffer)
                {
                    name = buffer.FirstOrDefault()?.ProcessName ?? "unknown";
                }
            }

            var compositeEvent = new DetectionEvent
            {
                RuleName = ruleName,
                ProcessId = pid,
                ProcessName = name,
                Confidence = confidence,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                Evidence = $"[COMPOSITE] {evidence} (PID {pid})",
                Reasoning = reasoning,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    [ResponsePolicy.ChainConfirmedKey] = "true",
                    [ResponsePolicy.TerminalOutcomeKey] = "Composite",
                }
            };

            if (tagCoercionToolkit)
                CoercionAbusePolicy.TagAsCoercionToolkit(compositeEvent);

            await _emitCallback!(compositeEvent);
        }

        internal static bool IsHostWideDeliveryFuel(DetectionEvent signal)
        {
            var n = signal?.RuleName ?? "";
            return n.IndexOf("Mark-of-the-Web", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Disk Image", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("AppInstaller Package", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Script Dropper", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("WPAD", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Auto-Proxy PAC", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void BufferHostWideDelivery(DetectionEvent signal)
        {
            lock (_hostWideDelivery)
            {
                _hostWideDelivery.Add(signal);
                PruneHostWideLocked();
            }
        }

        private void MergeHostWideDelivery(List<DetectionEvent> currentSignals)
        {
            lock (_hostWideDelivery)
            {
                PruneHostWideLocked();
                foreach (var s in _hostWideDelivery)
                    currentSignals.Add(s);
            }
        }

        private void PruneHostWideLocked()
        {
            var cutoff = DateTime.UtcNow - CorrelationWindow;
            _hostWideDelivery.RemoveAll(s => s.Timestamp < cutoff);
            while (_hostWideDelivery.Count > 40)
                _hostWideDelivery.RemoveAt(0);
        }

        private static string? ResolveImagePath(int pid)
        {
            return SecurityValidation.GetProcessImagePath(pid);
        }

        private void PruneStaleBuffers()
        {
            var now = DateTime.UtcNow;
            if (now - _lastPruneTime < PruneInterval)
                return;
            _lastPruneTime = now;

            var cutoff = now - CorrelationWindow;
            var staleKeys = new List<int>();

            foreach (var kvp in _signalBuffers)
            {
                lock (kvp.Value)
                {
                    kvp.Value.RemoveAll(s => s.Timestamp < cutoff);
                    if (kvp.Value.Count == 0)
                    {
                        staleKeys.Add(kvp.Key);
                    }
                }
            }

            foreach (var key in staleKeys)
            {
                _signalBuffers.TryRemove(key, out _);
            }
        }
    }
}
