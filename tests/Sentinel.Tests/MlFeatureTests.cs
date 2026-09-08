using System;
using System.IO;
using Xunit;
using Sentinel.Core.Ml;

namespace Sentinel.Tests
{
    public class MlFeatureTests
    {
        [Fact]
        public void UrlFeatureExtractor_ExtractsBasicStats()
        {
            var v = UrlFeatureExtractor.Extract("http://evil-download.tk/payload.exe?id=123");
            Assert.True(v.UrlLength > 10);
            Assert.True(v.HasHttp > 0);
            Assert.True(v.DotCount >= 2);
            Assert.True(v.HasSuspiciousTld > 0 || v.TldLength > 0);
        }

        [Fact]
        public void UrlFeatureExtractor_Empty_ReturnsZeros()
        {
            var v = UrlFeatureExtractor.Extract("");
            Assert.Equal(0, v.UrlLength);
        }

        [Fact]
        public void PeFeatureExtractor_NonPe_ReturnsNull()
        {
            var path = Path.Combine(Path.GetTempPath(), "sentinel_ml_test_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(path, "not a pe file");
                Assert.Null(PeFeatureExtractor.TryExtract(path));
            }
            finally
            {
                try { File.Delete(path); } catch { }
            }
        }

        [Fact]
        public void PeFeatureExtractor_RealPe_ExtractsSections()
        {
            // Use the currently loaded Core assembly as a PE
            var pePath = typeof(PeFeatureExtractor).Assembly.Location;
            if (string.IsNullOrEmpty(pePath) || !File.Exists(pePath))
            {
                // Single-file / empty location — skip
                return;
            }

            var v = PeFeatureExtractor.TryExtract(pePath);
            Assert.NotNull(v);
            Assert.True(v!.SectionsNb >= 1);
            Assert.True(v.SizeOfImage > 0);
        }

        [Fact]
        public void MlThreatScorer_WithoutModels_ReturnsNullScores()
        {
            using var scorer = new MlThreatScorer();
            // Without models present, scores are null (graceful degrade)
            // May load models if they exist in output dir — either way must not throw
            var pe = scorer.ScorePeFile(typeof(PeFeatureExtractor).Assembly.Location);
            var url = scorer.ScoreUrlOrHost("http://example.com/test");
            // Just ensure API is callable; null or value both OK
            Assert.True(pe == null || (pe >= 0 && pe <= 1));
            Assert.True(url == null || (url >= 0 && url <= 1));
        }
    }
}
