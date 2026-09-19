using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>
    /// Process-wide, thread-safe runtime blocklist for enforced domain and IP blocks.
    ///
    /// This is the single place any Sentinel component can add a domain or IP to the enforced
    /// blacklist at runtime. <see cref="HostsFileGuard"/> merges these entries with the
    /// operator-defined <see cref="SentinelConfig.EnforcedDomainBlocks"/> /
    /// <see cref="SentinelConfig.EnforcedIpBlocks"/> on every enforcement pass (startup + every
    /// periodic scan), so anything added here is enforced within one scan cycle via the same
    /// proven hosts-file + wildcard-NRPT path (domains) or inbound/outbound firewall rules (IPs),
    /// and is self-healed on tamper.
    ///
    /// Design notes:
    /// - Additive only by default. Enforced blocks are hardening, not detections; a caller may
    ///   remove an entry it added (<see cref="RemoveDomain"/>/<see cref="RemoveIp"/>), but note
    ///   that hosts/NRPT/firewall artifacts already written are not torn down here - removal just
    ///   stops re-asserting the entry on the next pass.
    /// - Domains are normalized to a bare lowercase host; the wildcard NRPT rule written by the
    ///   guard already covers the apex + every subdomain, so callers pass a bare domain.
    /// - This is intentionally NOT a trust/verdict surface: adding a domain here is an explicit
    ///   block decision by a Sentinel component, never an implicit "this domain is bad" inference
    ///   used to authorize a process kill. It only controls name/IP reachability.
    /// </summary>
    public static class DomainBlocklistStore
    {
        // Using ConcurrentDictionary as a concurrent set (value is ignored). Case-insensitive
        // domain keys; IPs are compared as trimmed strings.
        private static readonly ConcurrentDictionary<string, byte> _domains =
            new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, byte> _ips =
            new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Add a domain to the runtime blocklist. Accepts a URL/host/apex; it is normalized to a
        /// bare lowercase host (scheme/path/port stripped, leading dot removed). Returns true if
        /// the entry was newly added, false if it was already present or could not be normalized.
        /// The block takes effect on the guard's next enforcement pass (startup / periodic scan).
        /// </summary>
        public static bool AddDomain(string? domain)
        {
            var normalized = NormalizeDomain(domain);
            if (normalized == null) return false;
            return _domains.TryAdd(normalized, 0);
        }

        /// <summary>Remove a domain from the runtime blocklist (stops future re-assertion).</summary>
        public static bool RemoveDomain(string? domain)
        {
            var normalized = NormalizeDomain(domain);
            if (normalized == null) return false;
            return _domains.TryRemove(normalized, out _);
        }

        /// <summary>Add a raw IPv4/IPv6 address to the runtime blocklist.</summary>
        public static bool AddIp(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            return _ips.TryAdd(ip!.Trim(), 0);
        }

        /// <summary>Remove an IP from the runtime blocklist (stops future re-assertion).</summary>
        public static bool RemoveIp(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            return _ips.TryRemove(ip!.Trim(), out _);
        }

        /// <summary>True if the (normalized) domain is present in the runtime blocklist.</summary>
        public static bool ContainsDomain(string? domain)
        {
            var normalized = NormalizeDomain(domain);
            return normalized != null && _domains.ContainsKey(normalized);
        }

        /// <summary>Snapshot of all runtime-added domains (normalized, lowercase).</summary>
        public static IReadOnlyList<string> Domains => _domains.Keys.ToList();

        /// <summary>Snapshot of all runtime-added IPs.</summary>
        public static IReadOnlyList<string> Ips => _ips.Keys.ToList();

        /// <summary>
        /// Union of the runtime domains with the supplied config domains (both normalized,
        /// de-duplicated, case-insensitive). This is exactly what the guard enforces each pass.
        /// </summary>
        public static string[] MergeDomains(string[]? configDomains)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (configDomains != null)
            {
                foreach (var d in configDomains)
                {
                    var n = NormalizeDomain(d);
                    if (n != null) set.Add(n);
                }
            }
            foreach (var d in _domains.Keys) set.Add(d);
            return set.ToArray();
        }

        /// <summary>Union of the runtime IPs with the supplied config IPs (trimmed, de-duplicated).</summary>
        public static string[] MergeIps(string[]? configIps)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (configIps != null)
            {
                foreach (var ip in configIps)
                {
                    if (!string.IsNullOrWhiteSpace(ip)) set.Add(ip.Trim());
                }
            }
            foreach (var ip in _ips.Keys) set.Add(ip);
            return set.ToArray();
        }

        /// <summary>
        /// Normalizes a domain to a bare lowercase host (strips scheme/path/port and a leading
        /// dot). Mirrors HostsFileGuard.NormalizeBlockDomain so the two agree byte-for-byte.
        /// </summary>
        public static string? NormalizeDomain(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            var d = raw!.Trim().ToLowerInvariant();
            int scheme = d.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0) d = d.Substring(scheme + 3);
            d = d.Split('/')[0].Split(':')[0].TrimStart('.');
            return string.IsNullOrWhiteSpace(d) ? null : d;
        }

        /// <summary>Clears all runtime entries. Test-only.</summary>
        internal static void ResetForTests()
        {
            _domains.Clear();
            _ips.Clear();
        }
    }
}
