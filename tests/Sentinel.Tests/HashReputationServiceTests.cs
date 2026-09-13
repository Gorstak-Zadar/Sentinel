using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    public class HashReputationServiceTests
    {
        [Fact]
        public async Task GetVerdictAsync_ReturnsSafe_ForPredefinedSafeHash()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig();
                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);

                var verdict = await service.GetVerdictAsync("0000000000000000000000000000000000000000000000000000000000000000");

                Assert.Equal(HashVerdict.Safe, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task GetVerdictAsync_ReturnsUnsafe_ForPredefinedUnsafeHash()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig();
                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);

                var verdict = await service.GetVerdictAsync("bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1");

                Assert.Equal(HashVerdict.Unsafe, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task GetVerdictAsync_ReturnsCachedVerdict_FromDiskStore()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig();
                
                var sha256 = "c0ffee0000000000000000000000000000000000000000000000000000000000";
                cache.Save("reputation", sha256, HashVerdict.Unsafe.ToString());

                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);
                var verdict = await service.GetVerdictAsync(sha256);

                Assert.Equal(HashVerdict.Unsafe, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task GetVerdictAsync_DegradesGracefullyToUnknown_OnNetworkFailure()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig { MalwareBazaarApiKey = "dummy_key" };
                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);

                // A random non-cached hash will attempt live query and timeout/fail without actual network or invalid target.
                var sha256 = "1234567890123456789012345678901234567890123456789012345678901234";
                var verdict = await service.GetVerdictAsync(sha256);

                Assert.Equal(HashVerdict.Unknown, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }
}
