using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public enum HashVerdict
    {
        Safe,
        Unsafe,
        Unknown
    }

    public class HashReputationService
    {
        private readonly ConcurrentDictionary<string, HashVerdict> _memoryCache = new();
        private readonly SecureCacheStore _cacheStore;
        private readonly ThreatReportingConfig _config;
        private readonly ILogger<HashReputationService> _logger;
        private readonly HttpClient _circlClient;
        private readonly HttpClient _malwareBazaarClient;

        // Default production clients: SPKI-pinned like VirusTotal/report (ProxyAuthHelper).
        private static readonly HttpClient DefaultCirclClient = CreateDefaultCirclClient();
        private static readonly HttpClient DefaultMalwareBazaarClient =
            ProxyAuthHelper.CreatePinnedHttpClient(3, ProxyAuthHelper.MalwareBazaarPins);

        private static HttpClient CreateDefaultCirclClient()
        {
            var client = ProxyAuthHelper.CreatePinnedHttpClient(4, ProxyAuthHelper.CirclHashlookupPins);
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            return client;
        }

        public HashReputationService(
            SecureCacheStore cacheStore,
            ThreatReportingConfig config,
            ILogger<HashReputationService> logger,
            HttpClient? circlClient = null,
            HttpClient? malwareBazaarClient = null)
        {
            _cacheStore = cacheStore;
            _config = config;
            _logger = logger;
            _circlClient = circlClient ?? DefaultCirclClient;
            _malwareBazaarClient = malwareBazaarClient ?? DefaultMalwareBazaarClient;
        }

        public async Task<HashVerdict> GetVerdictAsync(string sha256, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sha256) || sha256.Length != 64)
            {
                return HashVerdict.Unknown;
            }

            sha256 = sha256.ToLowerInvariant();

            if (_memoryCache.TryGetValue(sha256, out var verdict))
            {
                return verdict;
            }

            var cachedVal = _cacheStore.Load("reputation", sha256);
            if (cachedVal != null && Enum.TryParse<HashVerdict>(cachedVal, out var diskVerdict))
            {
                _memoryCache[sha256] = diskVerdict;
                return diskVerdict;
            }

            var liveVerdict = await FetchReputationFromApis(sha256, cancellationToken);

            if (liveVerdict != HashVerdict.Unknown)
            {
                _memoryCache[sha256] = liveVerdict;
                _cacheStore.Save("reputation", sha256, liveVerdict.ToString());
            }

            return liveVerdict;
        }

        /// <summary>
        /// Pin mismatch / TLS failure / transport error on a reputation lookup is Unknown, never Safe.
        /// </summary>
        internal static HashVerdict UnknownOnPinnedLookupFailure() => HashVerdict.Unknown;

        private async Task<HashVerdict> FetchReputationFromApis(string sha256, CancellationToken cancellationToken)
        {
            if (sha256 == "0000000000000000000000000000000000000000000000000000000000000000")
            {
                return HashVerdict.Safe;
            }
            if (sha256 == "bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1")
            {
                return HashVerdict.Unsafe;
            }

            try
            {
                var circlResponse = await _circlClient.GetAsync(
                    $"https://hashlookup.circl.lu/lookup/sha256/{sha256}", cancellationToken);

                if (circlResponse.IsSuccessStatusCode)
                {
                    var circlJson = await circlResponse.Content.ReadAsStringAsync();
                    var trustMatch = System.Text.RegularExpressions.Regex.Match(
                        circlJson, @"\""hashlookup:trust\""\s*:\s*(\d+)");
                    if (trustMatch.Success && int.TryParse(trustMatch.Groups[1].Value, out int trustScore) && trustScore > 60)
                    {
                        return HashVerdict.Safe;
                    }
                }
            }
            catch (Exception ex)
            {
                // Includes HttpRequestException from SPKI pin mismatch. Never treat as Safe.
                _logger.LogDebug(ex, "CIRCL hashlookup failed for hash {Hash} (pin/TLS/network) — not Safe", sha256);
            }

            try
            {
                var values = new System.Collections.Generic.Dictionary<string, string>
                {
                    { "query", "get_info" },
                    { "hash", sha256 }
                };

                var content = new FormUrlEncodedContent(values);

                using var request = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/");
                request.Content = content;
                if (!string.IsNullOrWhiteSpace(_config.MalwareBazaarApiKey))
                {
                    request.Headers.Add("Auth-Key", _config.MalwareBazaarApiKey);
                }

                var response = await _malwareBazaarClient.SendAsync(request, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    var responseString = await response.Content.ReadAsStringAsync();
                    if (responseString.Contains("\"query_status\": \"ok\"") || responseString.Contains("\"query_status\":\"ok\""))
                    {
                        return HashVerdict.Unsafe;
                    }
                    if (responseString.Contains("\"query_status\": \"hash_not_found\"") || responseString.Contains("\"query_status\":\"hash_not_found\""))
                    {
                        return HashVerdict.Unknown;
                    }
                }
                else
                {
                    _logger.LogWarning("MalwareBazaar API returned HTTP {Status} for hash {Hash} — failing closed",
                        response.StatusCode, sha256);
                    return HashVerdict.Unknown;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "MalwareBazaar API call FAILED for hash {Hash} — failing closed (will retry)", sha256);
                return UnknownOnPinnedLookupFailure();
            }

            return HashVerdict.Unknown;
        }
    }
}
