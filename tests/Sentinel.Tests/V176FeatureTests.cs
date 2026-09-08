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
    /// <summary>
    /// v1.7.6: forum.hr hosts block removed; ForumHrWatchMonitor is the dedicated watch.
    /// </summary>
    public class V176FeatureTests
    {
        #region Domain matching

        [Theory]
        [InlineData("forum.hr", true)]
        [InlineData("www.forum.hr", true)]
        [InlineData("FORUM.HR", true)]
        [InlineData("api.forum.hr", true)]
        [InlineData("cdn.forum.hr", true)]
        [InlineData("tracker.forum.hr", true)]
        [InlineData("evil.forum.hr", true)]
        [InlineData("forum.hr.", true)]
        [InlineData("https://forum.hr/path", true)]
        [InlineData("http://www.forum.hr:443/x", true)]
        [InlineData("notforum.hr", false)]
        [InlineData("forum.hr.evil.com", false)]
        [InlineData("example.com", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void ForumHrWatchMonitor_IsForumHrDomain_ClassifiesCorrectly(string? domain, bool expected)
        {
            Assert.Equal(expected, ForumHrWatchMonitor.IsForumHrDomain(domain));
        }

        [Fact]
        public void ForumHrWatchMonitor_WatchedHostnames_IncludeApexAndCommonSubs()
        {
            Assert.Contains("forum.hr", ForumHrWatchMonitor.WatchedHostnames);
            Assert.Contains("www.forum.hr", ForumHrWatchMonitor.WatchedHostnames);
            Assert.Contains("api.forum.hr", ForumHrWatchMonitor.WatchedHostnames);
            Assert.All(ForumHrWatchMonitor.WatchedHostnames, h =>
                Assert.True(ForumHrWatchMonitor.IsForumHrDomain(h)));
        }

        #endregion

        #region Lifecycle + DNS feed

        private static (DetectionEngine engine, JsonlEventLogger logger, string tempDir) CreateTestEngine()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_fhr_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);

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

            var engine = new DetectionEngine(
                new List<IDetectionRule>(), metrics, logger, responseEngine,
                iocScanner, reputationService, fileReputationEngine, correlationEngine, scoringEngine,
                NullLogger<DetectionEngine>.Instance
            );

            return (engine, logger, tempDir);
        }

        [Fact]
        public async Task ForumHrWatchMonitor_StartsAndStopsCleanly()
        {
            var (engine, logger, tempDir) = CreateTestEngine();
            try
            {
                var monitor = new ForumHrWatchMonitor(engine, NullLogger<ForumHrWatchMonitor>.Instance);
                await monitor.StartAsync(CancellationToken.None);
                await Task.Delay(50);
                await monitor.StopAsync(CancellationToken.None);
                engine.Stop();
                await logger.DisposeAsync();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task ForumHrWatchMonitor_RecordDnsQuery_IgnoresUnrelatedDomains()
        {
            var (engine, logger, tempDir) = CreateTestEngine();
            try
            {
                var monitor = new ForumHrWatchMonitor(engine, NullLogger<ForumHrWatchMonitor>.Instance);
                // Must not throw
                monitor.RecordDnsQuery(1234, "example.com");
                monitor.RecordDnsQuery(1234, "google.com");
                monitor.RecordDnsQuery(0, "microsoft.com");
                engine.Stop();
                await logger.DisposeAsync();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task ForumHrWatchMonitor_RecordDnsQuery_AcceptsForumHrWithoutThrow()
        {
            var (engine, logger, tempDir) = CreateTestEngine();
            try
            {
                var monitor = new ForumHrWatchMonitor(engine, NullLogger<ForumHrWatchMonitor>.Instance);
                monitor.RecordDnsQuery(0, "forum.hr");
                monitor.RecordDnsQuery(0, "www.forum.hr");
                monitor.RecordDnsQuery(99999, "api.forum.hr"); // non-existent PID — no crash
                engine.Stop();
                await logger.DisposeAsync();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        #endregion
    }
}
