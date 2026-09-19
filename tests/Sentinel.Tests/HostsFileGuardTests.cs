using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    public class HostsFileGuardTests
    {
        private static string? FindCoreSourceFile(string fileName)
        {
            // tests/Sentinel.Tests/bin/{Config}/net*/ -> five levels up to repo root
            var candidates = new[]
            {
                Path.GetFullPath(Path.Combine(
                    AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                    "src", "Sentinel.Core", "Monitors", fileName)),
                Path.GetFullPath(Path.Combine(
                    AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                    "src", "Sentinel.Core", fileName)),
            };
            foreach (var c in candidates)
                if (File.Exists(c)) return c;
            return null;
        }

        [Fact]
        public void HostsFileGuard_NoLongerEnforcesAdBlocklist()
        {
            // v2.1: HostsFileGuard no longer ships an embedded ad-blocking hosts file.
            // It monitors for suspicious modifications instead.
            var sourceFile = FindCoreSourceFile("SystemIntegrityMonitors.cs");
            if (sourceFile == null) return; // CI without source tree

            var content = File.ReadAllText(sourceFile);

            // Must not contain any hardcoded ad-blocking entries
            Assert.DoesNotContain("TrustedHostsContentBase", content);
            Assert.DoesNotContain("BuildTrustedHostsContent", content);
            Assert.DoesNotContain("0.0.0.0 doubleclick.net", content);
            Assert.DoesNotContain("0.0.0.0 google-analytics.com", content);
            Assert.DoesNotContain("0.0.0.0 hotjar.com", content);
            Assert.DoesNotContain("0.0.0.0 taboola.com", content);
        }

        [Fact]
        public void HostsFileGuard_DoesNotOverwriteUserContent()
        {
            // v2.1: The guard must NOT contain logic to overwrite the entire hosts file
            var sourceFile = FindCoreSourceFile("SystemIntegrityMonitors.cs");
            if (sourceFile == null) return;

            var content = File.ReadAllText(sourceFile);

            // Old enforcement patterns must be gone
            Assert.DoesNotContain("File.WriteAllText(HostsFilePath, _trustedContent", content);
            Assert.DoesNotContain("Reverted hosts to trusted baseline", content);
            Assert.DoesNotContain("DeleteUnauthorizedFilesAsync", content);
        }

        [Fact]
        public void HostsFileGuard_MitmLinesDefinedForFcmBlock()
        {
            // When MitmDefense is enabled, FCM mtalk lines should be enforced
            var sourceFile = FindCoreSourceFile("SystemIntegrityMonitors.cs");
            if (sourceFile == null) return;

            var content = File.ReadAllText(sourceFile);

            // MitM defense lines must still be present for enforcement
            Assert.Contains("mtalk.google.com", content);
            Assert.Contains("alt1-mtalk.google.com", content);
            Assert.Contains("EnsureMitmLinesAsync", content);
        }

        [Fact]
        public void HostsFileGuard_DetectsSuspiciousPatterns()
        {
            // The guard should have suspicious IP detection and protected domain lists
            var sourceFile = FindCoreSourceFile("SystemIntegrityMonitors.cs");
            if (sourceFile == null) return;

            var content = File.ReadAllText(sourceFile);

            // Should detect redirects to known C2 IP ranges
            Assert.Contains("SuspiciousRedirectTargets", content);
            // Should protect security update domains
            Assert.Contains("ProtectedDomains", content);
            Assert.Contains("windowsupdate.com", content);
            Assert.Contains("virustotal.com", content);
        }

        [Fact]
        public void BlockFcmPushChannel_DefaultsOff()
        {
            // v1.8.3: do not break Chrome push for normal users until opted in post-incident
            Assert.False(new SentinelConfig().BlockFcmPushChannel);
        }

        [Fact]
        public void TrustedCastDevices_EmptyMeansObserveNotKill()
        {
            // v1.8.3 docs in Models: empty allowlist is observe-only
            // (unless MitmDefense.Enabled - then rogue Cast IOCs are blocked)
            var cfg = new SentinelConfig();
            Assert.Empty(cfg.TrustedCastDevices);
            Assert.False(cfg.MitmDefense.Enabled);
        }

        [Fact]
        public void MitmDefense_DefaultOff_ButSuiteFieldsPresent()
        {
            var cfg = new SentinelConfig();
            Assert.False(cfg.MitmDefense.Enabled);
            Assert.True(cfg.MitmDefense.RemovePlantedCerts);
            Assert.True(cfg.MitmDefense.BlockFcmPushChannel);
            Assert.True(cfg.MitmDefense.AutoBlockRogueCast);
            Assert.Contains("B0-B3-69", cfg.MitmDefense.RogueCastMacPrefixes);
        }

        [Fact]
        public void MitmDefense_WhenEnabled_AllowsMutationsAndClassifiesActions()
        {
            var cfg = new SentinelConfig
            {
                ActiveResponse = true,
                ObserveUntilChain = true,
                MitmDefense = new MitmDefenseConfig { Enabled = true }
            };
            Assert.True(ProductPosture.AllowsMitmDefenseMutations(cfg));
            Assert.False(ResponsePolicy.MayPerformInlineHostMutation(cfg));

            var castEvt = new DetectionEvent
            {
                RuleName = "Cast Device Guard: Fake Chromecast / Rogue Cast Blocked",
                AuthorizedResponse = ResponseAction.NetworkIsolate,
                Metadata = new Dictionary<string, string> { ["MitmDefense"] = "true" }
            };
            Assert.True(ResponsePolicy.IsMitmDefenseAction(castEvt, cfg));

            var ghostEvt = new DetectionEvent
            {
                RuleName = "Ghost Process: Invisible Process -> Fake Chromecast / Rogue Cast (MitM chain)",
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string> { ["MitmDefense"] = "true" }
            };
            Assert.True(ResponsePolicy.IsMitmDefenseAction(ghostEvt, cfg));

            var certEvt = new DetectionEvent
            {
                RuleName = "TLS: MitM Planted Root Certificate - Removing",
                AuthorizedResponse = ResponseAction.RemoveCert
            };
            Assert.True(ResponsePolicy.IsMitmDefenseAction(certEvt, cfg));
        }

        [Fact]
        public async Task HostsFileGuard_StartsAndStopsCleanly()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_hosts_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);

            try
            {
                var cache = new SecureCacheStore(tempDir);
                var metrics = new SentinelMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var config = new SentinelConfig { ActiveResponse = false };
                var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
                var responseEngine = new AdvancedResponseEngine(config, metrics, logger, new QuarantineManager(tempDir));
                var iocScanner = new IoCScanner(cache);
                var reputationService = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
                var correlationEngine = new BehavioralCorrelationEngine();
                var scoringEngine = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
                var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
                var fileReputationEngine = new FileReputationEngine(reputationService, signerTrust, cache, NullLogger<FileReputationEngine>.Instance);

                var rules = new List<IDetectionRule>();
                var engine = new DetectionEngine(
                    rules, metrics, logger, responseEngine,
                    iocScanner, reputationService, fileReputationEngine, correlationEngine, scoringEngine,
                    NullLogger<DetectionEngine>.Instance
                );

                var guard = new HostsFileGuard(engine, config, NullLogger<HostsFileGuard>.Instance);

                await guard.StartAsync(CancellationToken.None);
                await Task.Delay(100);
                await guard.StopAsync(CancellationToken.None);

                engine.Stop();
                await logger.DisposeAsync();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        // ---- forum.hr block coverage (v2.6.9) ------------------------------

        [Theory]
        [InlineData("127.0.0.1 localhost")]
        [InlineData("127.0.0.1 localhost.localdomain")]
        [InlineData("127.0.0.1 local")]
        [InlineData("255.255.255.255 broadcasthost")]
        [InlineData("::1 localhost")]
        [InlineData("::1 ip6-localhost")]
        [InlineData("::1 ip6-loopback")]
        [InlineData("fe80::1%lo0 localhost")]
        [InlineData("ff00::0 ip6-localnet")]
        [InlineData("ff00::0 ip6-mcastprefix")]
        [InlineData("ff02::1 ip6-allnodes")]
        [InlineData("ff02::2 ip6-allrouters")]
        [InlineData("ff02::3 ip6-allhosts")]
        [InlineData("0.0.0.0 0.0.0.0")]
        public void HostsBaseline_ContainsLocalhostHeader(string expectedLine)
        {
            Assert.Contains(expectedLine, HostsFileGuard.HostsBaselineLinesForTest);
        }

        [Fact]
        public void HostsBaseline_ContainsNoDomainBlock_HeaderIsLoopbackOnly()
        {
            // The localhost/loopback baseline header contains no external domain. forum.hr is
            // blocked again (v2.7.7) but via EnforcedDomainBlocks (hosts + wildcard NRPT), NOT
            // by being baked into this baseline header - the two mechanisms stay separate.
            Assert.DoesNotContain(
                HostsFileGuard.HostsBaselineLinesForTest,
                l => l.IndexOf("forum.hr", System.StringComparison.OrdinalIgnoreCase) >= 0);
        }

        [Fact]
        public void HostsBaseline_UsesGpManagedPolicyHive_NotDnscacheParameters()
        {
            // The generic NRPT capability (kept for future blocks) targets the policy-scope
            // hive (authoritative), not the local effective table.
            Assert.Equal(
                @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig",
                HostsFileGuard.DnsPolicyConfigKeyForTest);
            Assert.DoesNotContain("Dnscache", HostsFileGuard.DnsPolicyConfigKeyForTest);
        }

        // ---- Proactive host mutation gate (default-deny seam) --------------

        [Fact]
        public void HostsBaseline_ProactiveMutation_GatesOnProductPosture()
        {
            // The hosts-baseline write + retired-artifact cleanup are proactive host mutations.
            // They route through ProductPosture.AllowsProactiveHostLockdown. Under the always-on
            // hardening posture (v2.5.5+) that returns true, so it is enforced for the default
            // config and even a null config - the "deny" branch exists as a single seam.
            Assert.True(HostsFileGuard.MayEnforceHostsBaseline(new SentinelConfig()));
            Assert.True(HostsFileGuard.MayEnforceHostsBaseline(null));
            Assert.Equal(
                ProductPosture.AllowsProactiveHostLockdown(new SentinelConfig()),
                HostsFileGuard.MayEnforceHostsBaseline(new SentinelConfig()));
        }

        // ---- Operator-defined reusable blocks (v2.7.6, option B) ----

        [Fact]
        public void EnforcedBlocks_DefaultsSeedForumHr()
        {
            // v2.7.7: forum.hr is restored as a default enforced domain block (via the generic
            // hosts + wildcard-NRPT mechanism). IP blocks remain empty by default.
            var cfg = new SentinelConfig();
            Assert.Contains("forum.hr", cfg.EnforcedDomainBlocks);
            Assert.Empty(cfg.EnforcedIpBlocks);
        }

        // ---- Runtime blocklist store (v2.7.7) ------------------------------

        [Fact]
        public void DomainBlocklistStore_MergesConfigAndRuntimeDomains()
        {
            DomainBlocklistStore.ResetForTests();
            try
            {
                Assert.True(DomainBlocklistStore.AddDomain("https://Evil.example.com/x"));
                // Normalized, de-duplicated union of config + runtime.
                var merged = DomainBlocklistStore.MergeDomains(new[] { "forum.hr", "forum.hr" });
                Assert.Contains("forum.hr", merged);
                Assert.Contains("evil.example.com", merged);
                Assert.Equal(merged.Length, merged.Distinct(System.StringComparer.OrdinalIgnoreCase).Count());
            }
            finally { DomainBlocklistStore.ResetForTests(); }
        }

        [Fact]
        public void DomainBlocklistStore_AddIsIdempotentAndRemovable()
        {
            DomainBlocklistStore.ResetForTests();
            try
            {
                Assert.True(DomainBlocklistStore.AddDomain("bad.test"));
                Assert.False(DomainBlocklistStore.AddDomain("bad.test"));   // already present
                Assert.True(DomainBlocklistStore.ContainsDomain("BAD.test")); // case-insensitive
                Assert.True(DomainBlocklistStore.RemoveDomain("bad.test"));
                Assert.False(DomainBlocklistStore.ContainsDomain("bad.test"));
            }
            finally { DomainBlocklistStore.ResetForTests(); }
        }

        [Fact]
        public void DomainBlocklistStore_NormalizeMatchesGuard()
        {
            // The store and the guard must normalize identically so a runtime-added domain maps
            // to the same hosts line / NRPT rule GUID the config path would produce.
            Assert.Equal(
                HostsFileGuard.NormalizeBlockDomain("https://WWW.Example.com:8080/p"),
                DomainBlocklistStore.NormalizeDomain("https://WWW.Example.com:8080/p"));
        }

        [Fact]
        public void DomainBlocklistStore_RejectsEmptyOrNull()
        {
            DomainBlocklistStore.ResetForTests();
            Assert.False(DomainBlocklistStore.AddDomain(null));
            Assert.False(DomainBlocklistStore.AddDomain("   "));
        }

        // ---- Domain-block enforcement detection: Tier2 / LogOnly contract ----

        [Fact]
        public void DomainBlockEnforced_Detection_IsTier2LogOnly()
        {
            // The "Hardening: Domain Block Enforced" event that EnforceConfiguredBlocks emits is a
            // hardening notice, not a behavioral kill signal. It must honor the Tier2 log-only
            // contract: even under an active-response config it stays LogOnly and never authorizes
            // a process action. (Mirrors the shape emitted by the guard.)
            var d = new DetectionEvent
            {
                RuleName = "Hardening: Domain Block Enforced",
                Evidence = "forum.hr blackholed via hosts + wildcard NRPT",
                Confidence = 0.99,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.AntiTamper,
            };

            ResponsePolicy.ApplyTierLaw(d);
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.False(d.KillAuthorized);
            // A hardening notice is not a terminal family and can never authorize a kill alone.
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.False(ResponsePolicy.MayPerformDestructiveResponse(d, new SentinelConfig
            {
                ActiveResponse = true,
                ObserveUntilChain = true,
                ChainConfirmMinSignals = 2,
                MinTier1Confidence = 0.85,
            }));
        }

        [Fact]
        public void EnforcedBlocks_ProactiveMutation_GatesOnProductPosture()
        {
            Assert.True(HostsFileGuard.MayEnforceConfiguredBlocks(new SentinelConfig()));
            Assert.True(HostsFileGuard.MayEnforceConfiguredBlocks(null));
            Assert.Equal(
                ProductPosture.AllowsProactiveHostLockdown(new SentinelConfig()),
                HostsFileGuard.MayEnforceConfiguredBlocks(new SentinelConfig()));
        }

        [Fact]
        public void NrptRuleGuidForDomain_IsStableAndCaseInsensitive()
        {
            // Same domain must always map to the same rule GUID (find/repair/remove), and be
            // insensitive to case/whitespace so "Example.COM " == "example.com".
            var a = HostsFileGuard.NrptRuleGuidForDomain("example.com");
            var b = HostsFileGuard.NrptRuleGuidForDomain("  Example.COM ");
            Assert.Equal(a, b);
            Assert.NotEqual(a, HostsFileGuard.NrptRuleGuidForDomain("other.com"));
            Assert.StartsWith("{", a);
        }

        [Theory]
        [InlineData("https://www.Example.com/path", "www.example.com")]
        [InlineData("example.com:8080", "example.com")]
        [InlineData(".example.com", "example.com")]
        [InlineData("  EXAMPLE.com  ", "example.com")]
        public void NormalizeBlockDomain_StripsSchemePortPathAndLeadingDot(string raw, string expected)
        {
            Assert.Equal(expected, HostsFileGuard.NormalizeBlockDomain(raw));
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void NormalizeBlockDomain_EmptyOrNull_ReturnsNull(string? raw)
        {
            Assert.Null(HostsFileGuard.NormalizeBlockDomain(raw));
        }
    }
}
