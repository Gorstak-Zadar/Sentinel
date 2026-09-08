using System;
using System.IO;
using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.ML;

namespace Sentinel.Core.Ml
{
    /// <summary>
    /// Offline ML.NET FastTree scorers for PE binaries and URLs/hosts.
    /// Soft signal only: returns malicious probability in [0,1], or null if unavailable.
    /// Models are loaded from MlModels/ next to the app, or from embedded resources.
    /// </summary>
    public sealed class MlThreatScorer : IDisposable
    {
        private readonly ILogger<MlThreatScorer>? _logger;
        private readonly object _gate = new();
        private MLContext? _ml;
        private PredictionEngine<PeFeatureVector, MlBinaryPrediction>? _peEngine;
        private PredictionEngine<UrlFeatureVector, MlBinaryPrediction>? _urlEngine;
        private bool _initAttempted;
        private bool _peReady;
        private bool _urlReady;

        public bool PeModelReady
        {
            get { EnsureInit(); return _peReady; }
        }

        public bool UrlModelReady
        {
            get { EnsureInit(); return _urlReady; }
        }

        public MlThreatScorer(ILogger<MlThreatScorer>? logger = null)
        {
            _logger = logger;
        }

        /// <summary>
        /// Malware probability for a PE file path, or null if not PE / model missing / error.
        /// </summary>
        public double? ScorePeFile(string filePath)
        {
            EnsureInit();
            if (!_peReady || _peEngine == null) return null;

            var features = PeFeatureExtractor.TryExtract(filePath);
            if (features == null) return null;

            try
            {
                lock (_gate)
                {
                    var pred = _peEngine.Predict(features);
                    return Clamp01(pred.Probability);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[MlThreatScorer] PE score failed for {Path}", filePath);
                return null;
            }
        }

        /// <summary>
        /// Malicious probability for a URL or hostname, or null if model missing / error.
        /// Well-known platform domains are dampened (lexical models false-positive on popular sites).
        /// </summary>
        public double? ScoreUrlOrHost(string urlOrHost)
        {
            EnsureInit();
            if (!_urlReady || _urlEngine == null) return null;
            if (string.IsNullOrWhiteSpace(urlOrHost)) return null;

            try
            {
                var features = UrlFeatureExtractor.Extract(urlOrHost);
                double p;
                lock (_gate)
                {
                    var pred = _urlEngine.Predict(features);
                    p = Clamp01(pred.Probability);
                }

                // Lexical URL models over-score popular CDN/OS domains; keep as weak signal only.
                if (IsWellKnownBenignHost(urlOrHost))
                    p = Math.Min(p, 0.25);

                return p;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[MlThreatScorer] URL score failed for {Url}", urlOrHost);
                return null;
            }
        }

        private static bool IsWellKnownBenignHost(string urlOrHost)
        {
            string host = urlOrHost.Trim().ToLowerInvariant();
            try
            {
                if (!host.Contains("://") && host.IndexOf('/') >= 0)
                    host = "http://" + host;
                if (Uri.TryCreate(host.Contains("://") ? host : "http://" + host, UriKind.Absolute, out var uri))
                    host = uri.IdnHost ?? uri.Host ?? host;
            }
            catch { }

            host = host.TrimEnd('.');
            // Suffix match for common platforms (not a security boundary — ML dampening only)
            string[] suffixes =
            {
                "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "office365.com",
                "live.com", "github.com", "githubusercontent.com", "google.com", "gstatic.com",
                "googleapis.com", "cloudflare.com", "akamai.net", "akamaiedge.net", "apple.com",
                "icloud.com", "mozaws.net", "mozilla.org", "firefox.com", "ubuntu.com",
                "debian.org", "python.org", "nuget.org", "npmjs.com", "nodejs.org",
                "golang.org", "rust-lang.org", "docker.com", "amazon.com", "amazonaws.com",
                "azure.com", "azure.net", "visualstudio.com", "vsassets.io"
            };
            foreach (var s in suffixes)
            {
                if (host == s || host.EndsWith("." + s))
                    return true;
            }
            return false;
        }

        /// <summary>0–100 risk contribution from PE model (null → caller ignores).</summary>
        public int? PeRiskScore100(string filePath)
        {
            var p = ScorePeFile(filePath);
            return p.HasValue ? (int)Math.Round(p.Value * 100.0) : null;
        }

        /// <summary>0–100 risk contribution from URL model.</summary>
        public int? UrlRiskScore100(string urlOrHost)
        {
            var p = ScoreUrlOrHost(urlOrHost);
            return p.HasValue ? (int)Math.Round(p.Value * 100.0) : null;
        }

        private void EnsureInit()
        {
            if (_initAttempted) return;
            lock (_gate)
            {
                if (_initAttempted) return;
                _initAttempted = true;
                try
                {
                    _ml = new MLContext(seed: 42);
                    _peReady = TryLoadPeModel();
                    _urlReady = TryLoadUrlModel();
                    _logger?.LogInformation(
                        "[MlThreatScorer] Models loaded: PE={Pe}, URL={Url}",
                        _peReady, _urlReady);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "[MlThreatScorer] Model init failed — ML scoring disabled");
                    _peReady = false;
                    _urlReady = false;
                }
            }
        }

        private bool TryLoadPeModel()
        {
            var path = ResolveModelPath("pe_model.zip");
            if (path == null || _ml == null) return false;
            using var fs = File.OpenRead(path);
            var model = _ml.Model.Load(fs, out _);
            _peEngine = _ml.Model.CreatePredictionEngine<PeFeatureVector, MlBinaryPrediction>(model);
            return true;
        }

        private bool TryLoadUrlModel()
        {
            var path = ResolveModelPath("url_model.zip");
            if (path == null || _ml == null) return false;
            using var fs = File.OpenRead(path);
            var model = _ml.Model.Load(fs, out _);
            _urlEngine = _ml.Model.CreatePredictionEngine<UrlFeatureVector, MlBinaryPrediction>(model);
            return true;
        }

        private static string? ResolveModelPath(string fileName)
        {
            // 1) Next to the executable / single-file extract dir
            var baseDir = AppContext.BaseDirectory;
            var candidates = new[]
            {
                Path.Combine(baseDir, "MlModels", fileName),
                Path.Combine(baseDir, fileName),
                Path.Combine(baseDir, "models", fileName),
            };

            foreach (var c in candidates)
            {
                if (File.Exists(c)) return c;
            }

            // 2) Dev layout: repo src/Sentinel.Core/MlModels
            try
            {
                var asm = Assembly.GetExecutingAssembly().Location;
                if (!string.IsNullOrEmpty(asm))
                {
                    var dir = Path.GetDirectoryName(asm);
                    for (int i = 0; i < 6 && dir != null; i++)
                    {
                        var p = Path.Combine(dir, "MlModels", fileName);
                        if (File.Exists(p)) return p;
                        var p2 = Path.Combine(dir, "src", "Sentinel.Core", "MlModels", fileName);
                        if (File.Exists(p2)) return p2;
                        dir = Directory.GetParent(dir)?.FullName;
                    }
                }
            }
            catch { }

            return null;
        }

        private static double Clamp01(float v) => MathNet48.Clamp(v, 0f, 1f);

        public void Dispose()
        {
            lock (_gate)
            {
                _peEngine?.Dispose();
                _urlEngine?.Dispose();
                _peEngine = null;
                _urlEngine = null;
            }
        }
    }
}
