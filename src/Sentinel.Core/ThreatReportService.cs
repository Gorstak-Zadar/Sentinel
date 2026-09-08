using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Reports detected threats to threat intelligence platforms via the Cloudflare Worker proxy.
    /// The proxy holds API keys server-side so they never appear in the open-source repo.
    ///
    /// SECURITY v1.6.0:
    ///   - All requests HMAC-signed with ThreatReporting:ProxySharedSecret (server-known).
    ///   - Never uses a client-generated key; never sends X-Sentinel-Key.
    ///   - Reporting is skipped (fail closed) when ProxySharedSecret is missing.
    ///   - Replay protection via X-Sentinel-Timestamp + X-Sentinel-Nonce (60s window, v2.0.8).
    ///   - TLS certificate pinning on the proxy HttpClient (v2.0.8).
    ///
    /// If ProxyEndpoint is null or secret is unset, reporting is silently skipped
    /// (lookups still work via HashReputationService / FileReputationEngine when configured).
    /// </summary>
    public class ThreatReportService
    {
        private readonly ThreatReportingConfig _config;
        private readonly ILogger<ThreatReportService> _logger;
        // v2.0.8: pinned TLS for proxy endpoint (same pins as FileReputationEngine VT path)
        private readonly HttpClient _httpClient;

        public ThreatReportService(ThreatReportingConfig config, ILogger<ThreatReportService> logger, SecureCacheStore? cacheStore = null)
        {
            _config = config;
            _logger = logger;
            _httpClient = ProxyAuthHelper.CreatePinnedHttpClient(10);

            if (_config.Enabled && !string.IsNullOrWhiteSpace(_config.ProxyEndpoint) && !ProxyAuthHelper.HasSharedSecret(_config))
            {
                _logger.LogWarning(
                    "ThreatReporting is enabled and ProxyEndpoint is set, but ProxySharedSecret is missing or too short. " +
                    "Outbound reports will be skipped until a secret (≥16 chars) matching the Worker SENTINEL_SHARED_SECRET is configured.");
            }
        }

        public async Task ReportHashAsync(string sha256, string[] tags, string comment)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/hash", new
            {
                type = "hash",
                value = sha256,
                tags,
                comment
            });
        }

        public async Task ReportUrlAsync(string url, string threat, string[] tags)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/url", new
            {
                type = "url",
                value = url,
                threat,
                tags
            });
        }

        public async Task ReportIpAsync(string ip, int[] categories, string comment)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/ip", new
            {
                type = "ip",
                value = ip,
                categories,
                comment
            });
        }

        private bool CanReport()
        {
            if (!_config.Enabled) return false;
            if (string.IsNullOrWhiteSpace(_config.ProxyEndpoint)) return false;
            // v1.6.0: fail closed without shared secret
            if (!ProxyAuthHelper.HasSharedSecret(_config)) return false;
            return true;
        }

        private async Task SendReportAsync(string path, object payload)
        {
            try
            {
                var json = JsonSerializer.Serialize(payload);
                var (request, error) = ProxyAuthHelper.CreateAuthenticatedPost(
                    _config.ProxyEndpoint!, path, json, _config);

                if (request == null)
                {
                    _logger.LogDebug("Threat report skipped: {Error}", error);
                    return;
                }

                using (request)
                {
                    var response = await _httpClient.SendAsync(request);

                    if (response.IsSuccessStatusCode)
                    {
                        _logger.LogDebug("Threat report submitted: {Path}", path);
                    }
                    else
                    {
                        _logger.LogWarning("Threat report failed ({Status}): {Path}",
                            (int)response.StatusCode, path);
                    }
                }
            }
            catch (Exception ex)
            {
                // Never crash on reporting failure — detection/response is more important
                _logger.LogDebug("Threat report error: {Message}", ex.Message);
            }
        }
    }
}
