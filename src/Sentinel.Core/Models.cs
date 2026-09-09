using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    public enum DetectionTier
    {
        Tier1Behavioral,
        Tier2Indicator
    }

    public enum ResponseAction
    {
        LogOnly,
        NetworkIsolate,
        RemoveCert,
        KillProcess,
        KillProcessTree,
        Quarantine,
        QuarantineAndKill,
        RemoveCertAndKillAdder,
        RemoveRegistryEntry,
        DismountVolume
    }

    public enum SignalType
    {
        Generic,
        LsassAccess,
        AmsiTampering,
        EtwTampering,
        Ransomware,
        ReverseShell,
        NetworkC2,
        CredentialTheft,
        ProcessInjection,
        SuspiciousProcess,
        AntiTamper,
        SecurityEvasion,
        PhantomKeystroke
    }

    public class CveShieldConfig
    {
        public bool Enabled { get; set; } = true;
        public string FeedUrl { get; set; } = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        public int PollIntervalHours { get; set; } = 4;
        public string? CustomFeedPath { get; set; } // Local fallback JSON for offline testing
    }

    /// <summary>
    /// Post-incident MITM hardening - cert plant + FCM tab injection + fake Chromecast C2 relay.
    /// Observed chain (2026-06-13/14):
    ///   1. Plant self-signed root (CN=WINDOWS-PC / long validity) -> TLS intercept
    ///   2. Steal Chrome sync tokens during intercept window
    ///   3. "Send Tab to Self" via FCM push (TCP 5228) opens attacker URLs in open Chrome
    ///   4. Rogue LAN device (e.g. 192.168.1.100, OUI B0-B3-69) on Cast :8009 as C2 relay
    ///      through the browser's open Cast/tab channel
    /// </summary>
    public class MitmDefenseConfig
    {
        /// <summary>Master switch for the suite. Default false (clean install work-first).</summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Remove high-confidence planted MitM roots even under ObserveUntilChain.
        /// </summary>
        public bool RemovePlantedCerts { get; set; } = true;

        /// <summary>
        /// Block Google FCM TCP 5228 - severs "Send Tab to Self" after token theft.
        /// When MitmDefense.Enabled, this overrides Sentinel:BlockFcmPushChannel=false.
        /// </summary>
        public bool BlockFcmPushChannel { get; set; } = true;

        /// <summary>
        /// Auto firewall-block rogue Cast / fake Chromecast devices when detected.
        /// </summary>
        public bool AutoBlockRogueCast { get; set; } = true;

        /// <summary>
        /// MAC OUI prefixes treated as cast-spoof / known hostile (normalized XX-XX-XX).
        /// B0-B3-69 is Shenzhen SDMC, historically spoofed as "Google Chromecast" in-incident.
        /// </summary>
        public string[] RogueCastMacPrefixes { get; set; } = { "B0-B3-69" };

        /// <summary>Explicit rogue Cast / MITM relay IPs (e.g. confirmed 192.168.1.100).</summary>
        public string[] KnownRogueCastIps { get; set; } = Array.Empty<string>();
    }

    public class SentinelConfig
    {
        /// <summary>
        /// v2.0.4: ActiveResponse is always true. The setter is retained for deserialization
        /// compatibility but silently ignores attempts to set it to false.
        /// There is no way to disable response actions from configuration.
        /// </summary>
        public bool ActiveResponse
        {
            get => true; // Always armed - no off switch
            set { } // No-op: cannot be disabled
        }
        public string? LogPath { get; set; }
        public string? WatchPath { get; set; }
        /// <summary>
        /// Explicit allowlist of Cast device IPs on the LAN.
        /// v1.8.3: Empty = observe-only (log Cast traffic, do not firewall-block) unless
        /// <see cref="MitmDefense"/> is enabled (then rogue Cast IOCs are blocked).
        /// Non-empty = enforce allowlist (block LAN Cast IPs not listed).
        /// </summary>
        public string[] TrustedCastDevices { get; set; } = Array.Empty<string>();

        /// <summary>
        /// v1.9.10: Post-incident MITM defense suite (June 13-14 chain).
        /// When Enabled: plant MitM certs are removed, FCM "Send Tab to Self" is blocked,
        /// and fake Chromecast / rogue Cast LAN relays are firewall-blocked.
        /// Does not require RestrictivePortHardening (narrow exception for this threat class).
        /// Default off for clean installs; enable after confirmed MitM / fake Cast.
        /// </summary>
        public MitmDefenseConfig MitmDefense { get; set; } = new();

        // Dynamic polling intervals (configurable)
        public int DnsPollIntervalSeconds { get; set; } = 15;
        public int RouteTableScanIntervalSeconds { get; set; } = 15;
        public int RawDiskScanIntervalSeconds { get; set; } = 20;
        public int AntiTamperTimingTickMs { get; set; } = 2000;
        public int AntiTamperIntegrityTickMs { get; set; } = 10000;

        /// <summary>
        /// v1.6.0: Maximum process kill/quarantine-kill actions per rolling 60 seconds.
        /// Prevents weaponized false-positive storms. NetworkIsolate is not counted.
        /// 0 = unlimited (not recommended).
        /// </summary>
        public int MaxKillsPerMinute { get; set; } = 15;

        /// <summary>
        /// v1.6.1: Maximum new NetworkIsolate firewall targets per rolling 60 seconds.
        /// Prevents isolate-storm DoS / CDN collateral from decoy beacons.
        /// 0 = unlimited (not recommended).
        /// </summary>
        public int MaxNetworkIsolatesPerMinute { get; set; } = 10;

        /// <summary>
        /// When true, ActiveResponse=false at startup is treated as tampering and force re-enabled.
        /// <summary>
        /// v2.0.4: Removed. ActiveResponse is now always true (no off switch).
        /// This property is retained as a no-op for deserialization compatibility only.
        /// </summary>
        [System.Obsolete("v2.0.4: ActiveResponse cannot be disabled. This property is a no-op.")]
        public bool EnforceActiveResponse { get; set; } = true;

        /// <summary>
        /// When true (default): all monitors log only until a multi-signal chain points at a
        /// kill-grade terminal (token theft, credential dump, reverse shell, C2 beaconing)
        /// or a composite proves one. DLL unload remediations remain active.
        /// </summary>
        public bool ObserveUntilChain { get; set; } = true;

        /// <summary>
        /// Minimum confidence (0-1) for a kill-grade family to remain Tier1.
        /// Below this, signals demote to Tier2 observe (still feed correlation).
        /// </summary>
        public double MinTier1Confidence { get; set; } = 0.85;

        /// <summary>
        /// Distinct rule names on the same PID required (within ChainConfirmWindowSeconds)
        /// plus at least one terminal-outcome signal before destructive response.
        /// </summary>
        public int ChainConfirmMinSignals { get; set; } = 2;

        /// <summary>
        /// Rolling window for multi-signal chain confirmation (seconds).
        /// </summary>
        public int ChainConfirmWindowSeconds { get; set; } = 300;

        /// <summary>
        /// When true (default): no toasts and no auto evidence packs unless chain-confirmed nuke.
        /// Detection still writes to events.jsonl for correlation.
        /// </summary>
        public bool SilentObserve { get; set; } = true;

        /// <summary>
        /// v1.9.5: Optional Windows Event Log trail (Application / source Sentinel).
        /// Disabled automatically on barebone/custom images where Event Log is stripped.
        /// </summary>
        public WindowsEventLogConfig WindowsEventLog { get; set; } = new();

        /// <summary>
        /// v1.8.3: When true, ThreatIntelFeedBlocker pre-creates Windows Firewall block rules
        /// for every feed IP/CIDR. Default <c>false</c> - observe connections to listed IPs
        /// and only act reactively (NetworkIsolate on live hit when ActiveResponse is on).
        /// Pre-blocking thousands of ranges breaks legitimate TLS/OCSP/CDN traffic.
        /// </summary>
        public bool ThreatIntelProactiveFirewall { get; set; } = false;

        /// <summary>
        /// v1.8.3: When true, permanently block Google FCM (TCP 5228 + mtalk hosts).
        /// Default <c>false</c> - do not break Chrome push for normal users.
        /// Enable after confirmed MitM / Chrome sync token theft (see CHANGELOG 0.8.6 June 13-14 chain).
        /// </summary>
        public bool BlockFcmPushChannel { get; set; } = false;

        /// <summary>
        /// v2.5.5: Hardening is now unconditional - always active. The setter is retained
        /// for deserialization compatibility but is a no-op. IPSec port lockdown, ASR Block
        /// rules, RPC/DCOM firewall, remote session guard, registry hardening, credential
        /// hardening, browser hardening, and LGPO security policy always run.
        /// </summary>
        [System.Obsolete("v2.5.5: RestrictivePortHardening is always true. This property is a no-op.")]
        public bool RestrictivePortHardening
        {
            get => true;
            set { } // No-op: hardening is always-on as of v2.5.5
        }

        /// <summary>
        /// v1.6.3: Trusted USB devices as VID:PID (hex, e.g. "0951:1666" for Kingston DataTraveler).
        /// New mass-storage/composite devices matching these IDs are baselined at low severity
        /// and never auto-disabled. HID BadUSB rules still apply to unknown keyboards.
        /// </summary>
        public string[] TrustedUsbDevices { get; set; } = Array.Empty<string>();

        /// <summary>
        /// v1.9.7: When true, auto-disable USB nodes that fail descriptor requests
        /// (VID_0000 / "Device Descriptor Request Failed") via registry ConfigFlags.
        /// Default <c>false</c> - do not kill flaky USB devices on normal desktops.
        /// </summary>
        public bool AutoDisableFailedUsbEnumeration { get; set; } = false;

        public CveShieldConfig CveShield { get; set; } = new();

        /// <summary>
        /// v1.9.9: Observe optional vendor/OS services that phone home (DiagTrack, whesvc, ...).
        /// Default Mode=Observe - log only; never stop services or firewall-block for privacy noise.
        /// Destructive host mutation remains reserved for chain-confirmed malice
        /// (cred dump, C2, ransomware, reverse shell, token theft, proven exfil chains).
        /// </summary>
        public ServiceExfilPostureConfig ServiceExfilPosture { get; set; } = new();

        /// <summary>
        /// v2.0: Explainable weighted multi-signal correlation (complements hand-authored composites).
        /// Compiled default; optional DPAPI override via EncryptedConfigStore.
        /// </summary>
        public WeightedCorrelationConfig WeightedCorrelation { get; set; } = new();
    }

    /// <summary>
    /// How Sentinel treats optional OS/vendor services that perform outbound telemetry.
    /// MVP ships Observe only; Soft/Hard are reserved for future opt-in (not default).
    /// </summary>
    public enum ServiceExfilPostureMode
    {
        /// <summary>Log inventory + outbound remotes only. No host mutation.</summary>
        Observe = 0,
        /// <summary>Future: NetworkIsolate public remotes for inventory services (opt-in).</summary>
        SoftReact = 1,
        /// <summary>Future: stop inventory services via SCM (opt-in; never kill svchost).</summary>
        HardReact = 2
    }

    /// <summary>
    /// v1.9.9 - Awareness of optional services that may phone home while remaining legitimate.
    /// Product law: 99% of software is observe-only; act only on kill-grade malice chains.
    /// </summary>
    public sealed class ServiceExfilPostureConfig
    {
        /// <summary>Master switch for PrivacyServiceOutboundMonitor. Default true (observe).</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Always Observe in shipped defaults. Soft/Hard must stay off unless operator opts in later.</summary>
        public ServiceExfilPostureMode Mode { get; set; } = ServiceExfilPostureMode.Observe;

        public int ScanIntervalSeconds { get; set; } = 15;

        /// <summary>
        /// Extra service short names to treat as privacy/phone-home inventory.
        /// Merged with built-in defaults (DiagTrack, whesvc, ...).
        /// </summary>
        public string[] Inventory { get; set; } = Array.Empty<string>();

        /// <summary>Service names the operator chooses to ignore (no privacy events).</summary>
        public string[] Allowlist { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Services that must never be stopped/disabled even if HardReact is added later.
        /// Empty uses built-in NeverTouch set (EventLog, BFE, Defender, ...).
        /// </summary>
        public string[] NeverTouch { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// v1.9.5 - Durable secondary audit trail via Windows Event Log.
    /// Primary product log remains JSONL. All writes fail-soft on stripped Windows.
    /// </summary>
    public class WindowsEventLogConfig
    {
        /// <summary>Master switch. Default on; writer self-disables if Event Log is unusable.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Event source name (registered under LogName on first successful create).</summary>
        public string SourceName { get; set; } = "Sentinel";

        /// <summary>
        /// Target log. Default Application - most available on custom/stripped images.
        /// Custom logs require extra ACLs and fail more often; avoid for barebone hosts.
        /// </summary>
        public string LogName { get; set; } = "Application";

        /// <summary>
        /// When true (default): only service lifecycle, chain response, evidence pack,
        /// quarantine, anti-tamper, heartbeat - never Tier2 observe spam.
        /// </summary>
        public bool CriticalOnly { get; set; } = true;

        /// <summary>Rolling write budget (0 = unlimited). Protects broken log stacks.</summary>
        public int MaxWritesPerMinute { get; set; } = 30;

        /// <summary>Low-frequency "still alive" events for SIEM gap detection.</summary>
        public bool HeartbeatEnabled { get; set; } = true;

        /// <summary>Heartbeat interval in minutes (minimum 15 enforced at runtime).</summary>
        public int HeartbeatMinutes { get; set; } = 60;
    }

    public class ThreatReportingConfig
    {
        public bool Enabled { get; set; } = true;
        public string? AbuseIpDbApiKey { get; set; }
        public string? UrlhausAuthToken { get; set; }
        public string? MalwareBazaarApiKey { get; set; }
        public bool ReportToMalwareBazaar { get; set; } = true;
        public bool ReportToUrlhaus { get; set; } = true;

        /// <summary>
        /// URL of the Cloudflare Worker proxy that holds API keys server-side.
        /// When set, reports go to this endpoint instead of directly to abuse.ch.
        /// This allows open-source distribution without leaking API keys.
        /// Default endpoint compiled into the binary.
        /// </summary>
        public string? ProxyEndpoint { get; set; } = "https://sentinel-threat-proxy.znastidobrostoje-6ee.workers.dev";

        /// <summary>
        /// HMAC key for the threat-proxy Worker. Compiled into the binary.
        /// Must match Worker env SENTINEL_SHARED_SECRET. Split concat so a PE
        /// dump is not one line. Admin --set-config can rotate via DPAPI
        /// config.enc (length >= 16). Short plants are ignored.
        /// </summary>
        public string? ProxySharedSecret { get; set; } = CompiledProxySharedSecret;

        /// <summary>Built-in Worker HMAC. Not disk config.</summary>
        public static string CompiledProxySharedSecret =>
            string.Concat("SntlHmac/", "CroatiaSecurity/", "v254/", "e7a91c4b2f6d80e3", "15c8a0d47b9e2f63");
    }

    /// <summary>
    /// v1.7.7+ - Automatic local evidence packs + optional TI indicator share
    /// for high-confidence hacking / attack detections.
    /// Does not file police reports (no public LE API); prepares packs and portal links.
    /// v1.7.8: reportable-grade policy, integrity manifest/HMAC, victim affidavit.
    /// </summary>
    public class AutoIncidentReportingConfig
    {
        /// <summary>Master switch. Default on.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Write police-ready packs under ProgramData\Sentinel\IncidentReports.</summary>
        public bool GenerateLocalEvidencePack { get; set; } = true;

        /// <summary>
        /// B1 (durable evidence survival): when true, a signed <b>summary</b> of each
        /// chain-confirmed evidence pack is mirrored off-host via the existing HMAC-signed
        /// ThreatReporting proxy so a local admin who suppresses Sentinel cannot also erase the
        /// proof. Default <b>false</b> (opt-in) - matches the honest, no-covert-exfil posture.
        /// Requires a configured ThreatReporting ProxyEndpoint + shared secret; fails closed
        /// (skips silently) when the secret is missing. Never uploads file contents or secrets.
        /// </summary>
        public bool MirrorEvidenceOffHost { get; set; } = false;

        /// <summary>
        /// Submit hashes/URLs/IPs via ThreatReportService (MalwareBazaar/URLhaus/AbuseIPDB).
        /// Requires ThreatReporting proxy secret. Community intel - not law enforcement.
        /// </summary>
        public bool ReportThreatIntel { get; set; } = true;

        /// <summary>Show a critical toast when a pack is written.</summary>
        public bool NotifyUser { get; set; } = true;

        /// <summary>
        /// v1.7.8: When true (default), only reportable-grade events produce packs:
        /// kill-authorized at high confidence, NetworkIsolate for C2-class signals,
        /// or Tier1 attack signals at MinConfidence - no low-signal noise.
        /// </summary>
        public bool ReportableGradeOnly { get; set; } = true;

        /// <summary>Minimum confidence for reportable-grade Tier1 / isolate paths (default 0.85).</summary>
        public double MinConfidence { get; set; } = 0.85;

        /// <summary>
        /// Floor confidence for kill-authorized packs when ReportableGradeOnly is true (default 0.80).
        /// When ReportableGradeOnly is false, uses min(MinConfidence, 0.70) for broader capture.
        /// </summary>
        public double KillAuthorizedMinConfidence { get; set; } = 0.80;

        /// <summary>Report kill-authorized detections (above KillAuthorizedMinConfidence).</summary>
        public bool IncludeKillAuthorized { get; set; } = true;

        /// <summary>Include NetworkIsolate when signal looks like C2 / attack (not every isolate).</summary>
        public bool IncludeNetworkIsolate { get; set; } = true;

        /// <summary>
        /// v1.7.8: Write MANIFEST.sha256, evidence_manifest.json, MANIFEST.hmac, chain_of_custody.txt.
        /// </summary>
        public bool IncludeIntegrityManifest { get; set; } = true;

        /// <summary>v1.7.8: Write victim_affidavit.txt fill-in template for the complainant.</summary>
        public bool IncludeVictimAffidavit { get; set; } = true;

        /// <summary>v1.7.8: Also create a .zip of the pack after integrity sealing.</summary>
        public bool CreateZipExport { get; set; } = true;

        /// <summary>Optional pre-fill for affidavit (user may complete remaining fields by hand).</summary>
        public string? VictimFullName { get; set; }
        public string? VictimEmail { get; set; }
        public string? VictimPhone { get; set; }
        public string? VictimAddress { get; set; }

        /// <summary>
        /// ISO 3166-1 alpha-2 override for filing portal (e.g. "HR", "US").
        /// Null = detect from Windows region.
        /// </summary>
        public string? CountryCode { get; set; }

        /// <summary>Override pack output directory. Null = ProgramData\Sentinel\IncidentReports.</summary>
        public string? ReportDirectory { get; set; }

        /// <summary>Per rule+pid cooldown in seconds (default 5 minutes).</summary>
        public int CooldownSeconds { get; set; } = 300;

        /// <summary>Hard cap on packs written per rolling hour (default 20).</summary>
        public int MaxPacksPerHour { get; set; } = 20;
    }

    public class TelemetryEvent
    {
        public string Type { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
    }

    public class ProcessTelemetry : TelemetryEvent
    {
        public string ImagePath { get; set; } = string.Empty;
        public int ParentProcessId { get; set; }
        public string ParentProcessName { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
    }

    public class NetworkTelemetry : TelemetryEvent
    {
        public string LocalAddress { get; set; } = string.Empty;
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string State { get; set; } = "ESTABLISHED";
    }

    public class FileActivityTelemetry : TelemetryEvent
    {
        public string FilePath { get; set; } = string.Empty;
        public string OperationType { get; set; } = string.Empty; // WRITE, RENAME, DELETE, etc.
        public string? TargetPath { get; set; }
    }

    public class ThreatIntelTelemetry : TelemetryEvent
    {
        public int TargetProcessId { get; set; }
        public string ApiName { get; set; } = string.Empty; // observed API name when known
        public string Protection { get; set; } = string.Empty;
    }

    public class DetectionEvent
    {
        public string RuleName { get; set; } = string.Empty;
        /// <summary>
        /// Stable rule identifier (e.g. "SENT-001") used for central action mapping,
        /// deduplication, and audit correlation. Optional - legacy rules leave this null.
        /// Ported from GorstaksProtection (GRS-00X scheme).
        /// </summary>
        public string? RuleId { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public string Reasoning { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public DetectionTier Tier { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public SignalType SignalType { get; set; } = SignalType.Generic;
        /// <summary>
        /// v2.6: Optional TYPED terminal-outcome family. When a monitor sets this explicitly,
        /// <see cref="ResponsePolicy.ClassifyTerminalOutcome"/> trusts it directly instead of
        /// inferring the family from rule-name substrings - removing the "renamed a rule,
        /// silently lost its kill-grade classification" bug class. Null for legacy detections,
        /// which continue to flow through the proven substring classifier unchanged.
        /// </summary>
        public TerminalFamily? Family { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public ResponseAction AuthorizedResponse { get; set; } = ResponseAction.LogOnly;
        public bool KillAuthorized => AuthorizedResponse >= ResponseAction.KillProcess;
    }

    public class ResponseEvent
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ActionTaken { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public double ExecutionTimeMs { get; set; }
    }
}
