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
        [InlineData("0.0.0.0 forum.hr")]
        [InlineData("0.0.0.0 www.forum.hr")]
        [InlineData("0.0.0.0 m.forum.hr")]
        [InlineData("0.0.0.0 cdn.forum.hr")]
        [InlineData("0.0.0.0 static.forum.hr")]
        [InlineData("0.0.0.0 api.forum.hr")]
        [InlineData("0.0.0.0 img.forum.hr")]
        [InlineData("0.0.0.0 mail.forum.hr")]
        [InlineData("0.0.0.0 ads.forum.hr")]
        [InlineData("0.0.0.0 tracker.forum.hr")]
        public void ForumHrBlock_ContainsApexAndAllSubdomains(string expectedLine)
        {
            Assert.Contains(expectedLine, HostsFileGuard.ForumHrBlockLinesForTest);
        }

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
        public void ForumHrBlock_ContainsLocalhostHeader(string expectedLine)
        {
            Assert.Contains(expectedLine, HostsFileGuard.ForumHrBlockLinesForTest);
        }

        [Fact]
        public void ForumHrBlock_EveryForumHrLineSinkholesToZero()
        {
            var forumLines = new List<string>();
            foreach (var line in HostsFileGuard.ForumHrBlockLinesForTest)
                if (line.Contains("forum.hr"))
                    forumLines.Add(line);

            Assert.Equal(10, forumLines.Count); // apex + 9 subdomains
            Assert.All(forumLines, l => Assert.StartsWith("0.0.0.0 ", l));
        }

        [Fact]
        public void ForumHrDnsPolicy_WildcardSuffixCoversAllSubdomains()
        {
            // Leading-dot suffix is what makes the NRPT rule match forum.hr AND every subdomain.
            Assert.Equal(".forum.hr", HostsFileGuard.ForumHrDnsSuffixForTest);
            Assert.Equal("0.0.0.0", HostsFileGuard.ForumHrDnsSinkholeForTest);
        }

        [Fact]
        public void ForumHrDnsPolicy_UsesGpManagedPolicyHive_NotDnscacheParameters()
        {
            // Must be the policy-scope hive (authoritative), not the local effective table.
            Assert.Equal(
                @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig",
                HostsFileGuard.DnsPolicyConfigKeyForTest);
            Assert.DoesNotContain("Dnscache", HostsFileGuard.DnsPolicyConfigKeyForTest);
        }

        // ---- Proactive host mutation gate (default-deny seam) --------------

        [Fact]
        public void ForumHrBlock_ProactiveMutation_GatesOnProductPosture()
        {
            // The forum.hr hosts-file write and NRPT rule are proactive host mutations. They
            // route through ProductPosture.AllowsProactiveHostLockdown. Under the always-on
            // hardening posture (v2.5.5+) that returns true, so the block is enforced for the
            // default config and even a null config - the "deny" branch exists as a single seam.
            Assert.True(HostsFileGuard.MayEnforceForumHrBlock(new SentinelConfig()));
            Assert.True(HostsFileGuard.MayEnforceForumHrBlock(null));
            // The gate is exactly the always-on posture predicate - not an independent flag.
            Assert.Equal(
                ProductPosture.AllowsProactiveHostLockdown(new SentinelConfig()),
                HostsFileGuard.MayEnforceForumHrBlock(new SentinelConfig()));
        }
    }
}
