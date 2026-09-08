using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors the Windows IP routing table for unauthorized modifications:
    /// - New /32 host routes (selective traffic redirection for MitM)
    /// - Default gateway hijack (all traffic redirected)
    /// - Route next-hop modification (targeted interception)
    /// - Persistent route registry injection (survives reboot)
    ///
    /// Active response:
    /// - Deletes suspicious /32 host routes via DeleteIpForwardEntry
    /// - Cleans persistent routes from registry on startup and at runtime
    /// - Excludes VPN/Docker/Hyper-V virtual adapter routes
    /// - Excludes multicast (224.0.0.0/4) and broadcast (255.255.255.255)
    ///
    /// Scan interval: 15 seconds.
    /// </summary>
    public sealed class RouteTableMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelConfig _config;
        private readonly ILogger<RouteTableMonitor> _logger;
        private readonly System.Threading.Timer _timer;
        private readonly TimeSpan _scanInterval;

        // Baseline captured at startup
        private readonly ConcurrentDictionary<string, RouteEntry> _baselineRoutes = new();
        private string? _baselineGateway;
        private bool _startupCleanupDone;
        private bool _baselineCaptured;

        // Registry path for persistent routes
        private const string PersistentRoutesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes";

        // Virtual adapter name fragments to exclude (VPN, Docker, Hyper-V, WSL)
        private static readonly string[] VirtualAdapterFragments = new[]
        {
            "hyper-v", "virtual", "vmware", "vmnet", "virtualbox", "vethernet",
            "docker", "wsl", "loopback", "bluetooth", "teredo", "isatap",
            "nordlynx", "wireguard", "tailscale", "cloudflare", "warp",
            "openvpn", "tap-windows", "proton",
        };

        #region P/Invoke

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetIpForwardTable(IntPtr pIpForwardTable, ref int pdwSize, bool bOrder);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int DeleteIpForwardEntry(ref MIB_IPFORWARDROW pRoute);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetIfEntry(ref MIB_IFROW pIfRow);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPFORWARDROW
        {
            public uint dwForwardDest;
            public uint dwForwardMask;
            public int dwForwardPolicy;
            public uint dwForwardNextHop;
            public int dwForwardIfIndex;
            public int dwForwardType;       // 3=local, 4=remote
            public int dwForwardProto;      // 2=local, 3=netmgmt, 4=icmp, 13=ospf
            public int dwForwardAge;
            public int dwForwardNextHopAS;
            public int dwForwardMetric1;
            public int dwForwardMetric2;
            public int dwForwardMetric3;
            public int dwForwardMetric4;
            public int dwForwardMetric5;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct MIB_IFROW
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string wszName;
            public int dwIndex;
            public int dwType;
            public int dwMtu;
            public int dwSpeed;
            public int dwPhysAddrLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] bPhysAddr;
            public int dwAdminStatus;
            public int dwOperStatus;
            public int dwLastChange;
            public int dwInOctets;
            public int dwInUcastPkts;
            public int dwInNUcastPkts;
            public int dwInDiscards;
            public int dwInErrors;
            public int dwInUnknownProtos;
            public int dwOutOctets;
            public int dwOutUcastPkts;
            public int dwOutNUcastPkts;
            public int dwOutDiscards;
            public int dwOutErrors;
            public int dwOutQLen;
            public int dwDescrLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public byte[] bDescr;
        }

        #endregion

        public RouteTableMonitor(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            SentinelConfig config,
            ILogger<RouteTableMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _config = config;
            _logger = logger;
            _scanInterval = TimeSpan.FromSeconds(config.RouteTableScanIntervalSeconds > 0 ? config.RouteTableScanIntervalSeconds : 15);
            _timer = new System.Threading.Timer(CheckRoutes, null, TimeSpan.FromSeconds(30), _scanInterval);
        }

        private void SnapshotBaseline()
        {
            try
            {
                var routes = GetRouteTable();
                var gateway = GetDefaultGateway();

                // If no routes or no gateway, network isn't ready yet — don't mark as captured
                if (routes.Count == 0 || gateway == null)
                {
                    _logger.LogDebug("[RouteTableMonitor] Network not ready ({Count} routes, gw={Gw}), deferring baseline",
                        routes.Count, gateway ?? "null");
                    return;
                }

                foreach (var r in routes)
                    _baselineRoutes[r.Key] = r;
                _baselineGateway = gateway;
                _baselineCaptured = true;
                _logger.LogInformation("[RouteTableMonitor] Baseline: {Count} routes, gateway={Gw}",
                    _baselineRoutes.Count, _baselineGateway);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[RouteTableMonitor] Failed to capture baseline");
            }
        }

        private void CheckRoutes(object? state)
        {
            try
            {
                // Capture baseline if not yet done (network may not have been ready at startup)
                if (!_baselineCaptured)
                {
                    SnapshotBaseline();
                    return; // Don't check on the same tick we baseline — wait for next cycle
                }

                // One-time startup cleanup of persistent route registry
                if (!_startupCleanupDone)
                {
                    _startupCleanupDone = true;
                    CleanupPersistentRouteRegistry();
                }

                var currentRoutes = GetRouteTable();
                var currentGateway = GetDefaultGateway();

                // Detect new routes not in baseline
                foreach (var route in currentRoutes)
                {
                    if (_baselineRoutes.ContainsKey(route.Key)) continue;

                    // New route appeared since baseline
                    if (IsMulticastOrBroadcast(route.Destination)) continue;
                    if (IsVirtualAdapter(route.InterfaceIndex)) continue;

                    // /32 host route from netmgmt protocol = injected by software, not DHCP/kernel
                    bool isHostRoute = route.Mask == 0xFFFFFFFF; // /32
                    bool isNetMgmt = route.Proto == 3; // MIB_IPPROTO_NETMGMT

                    if (isHostRoute && isNetMgmt)
                    {
                        var destIp = UintToIp(route.Destination);
                        var nextHop = UintToIp(route.NextHop);

                        _ = HandleSuspiciousRoute(route, destIp, nextHop);
                    }
                    else if (route.Destination == 0 && route.Mask == 0) // Default route
                    {
                        // New default route — potential full traffic hijack
                        var nextHop = UintToIp(route.NextHop);
                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Network: New Default Route Injected",
                            Evidence = $"New default route via {nextHop} (interface {route.InterfaceIndex}, proto={route.Proto})",
                            Reasoning = "A new default route was added to the system, which redirects all traffic through a potentially attacker-controlled gateway.",
                            Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.NetworkIsolate,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                ["TargetIP"] = nextHop,
                                ["Destination"] = "0.0.0.0/0",
                                ["NextHop"] = nextHop
                            }
                        });
                    }

                    // Update baseline with new route (don't re-alert)
                    _baselineRoutes[route.Key] = route;
                }

                // Detect gateway change
                if (_baselineGateway != null && currentGateway != null && currentGateway != _baselineGateway)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network: Default Gateway Changed",
                        Evidence = $"Default gateway changed from {_baselineGateway} to {currentGateway}",
                        Reasoning = "The default gateway was modified at runtime, which could indicate ARP spoofing, rogue DHCP, or malware redirecting traffic.",
                        Confidence = 0.80, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.NetworkIsolate,
                        ProcessName = "SYSTEM", ProcessId = 0,
                        Metadata = new Dictionary<string, string> { { "TargetIP", currentGateway } }
                    });
                    _baselineGateway = currentGateway;
                }

                // Check persistent routes registry for new injections
                CheckPersistentRouteRegistry();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RouteTableMonitor] Check error");
            }
        }

        private async Task HandleSuspiciousRoute(RouteEntry route, string destIp, string nextHop)
        {
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Network: Suspicious Host Route Injected",
                Evidence = $"/32 host route to {destIp} via {nextHop} (proto=netmgmt, interface={route.InterfaceIndex})",
                Reasoning = "A /32 host route was injected via network management protocol (not DHCP/kernel). This selectively redirects traffic to a specific IP through an attacker-controlled next-hop, enabling targeted MitM interception.",
                Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly, // We handle deletion ourselves
                ProcessName = "SYSTEM", ProcessId = 0,
                Metadata = new Dictionary<string, string>
                {
                    ["Destination"] = destIp,
                    ["NextHop"] = nextHop,
                    ["Action"] = "ROUTE_DELETED"
                }
            });

            // Active response: delete the injected route
            if (ResponsePolicy.MayPerformInlineHostMutation(_config))
            {
                var row = new MIB_IPFORWARDROW
                {
                    dwForwardDest = route.Destination,
                    dwForwardMask = route.Mask,
                    dwForwardNextHop = route.NextHop,
                    dwForwardIfIndex = route.InterfaceIndex,
                    dwForwardPolicy = 0,
                    dwForwardType = route.Type,
                    dwForwardProto = route.Proto,
                    dwForwardAge = 0,
                    dwForwardMetric1 = route.Metric
                };

                int result = DeleteIpForwardEntry(ref row);
                var action = result == 0 ? "ROUTE_DELETED" : $"DELETE_FAILED (error {result})";

                await _eventLogger.LogEventAsync("response", new ResponseEvent
                {
                    ProcessId = 0,
                    ProcessName = "RouteTableMonitor",
                    ActionTaken = action,
                    Reason = $"Deleted injected /32 route: {destIp} via {nextHop}"
                });

                _logger.LogWarning("[RouteTableMonitor] {Action}: /32 route {Dest} via {Hop}",
                    action, destIp, nextHop);
            }
        }

        /// <summary>
        /// Startup cleanup: scan persistent routes registry for pre-existing suspicious entries.
        /// If more than 3 suspicious /32 persistent routes exist, delete them all (attack pattern).
        /// </summary>
        private void CleanupPersistentRouteRegistry()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(PersistentRoutesKey, writable: true);
                if (key == null) return;

                var values = key.GetValueNames();
                var suspiciousRoutes = new List<string>();

                foreach (var valueName in values)
                {
                    if (string.IsNullOrEmpty(valueName)) continue;
                    // Persistent routes format: "dest,mask,gateway,metric"
                    var parts = valueName.Split(',');
                    if (parts.Length < 3) continue;

                    var mask = parts[1].Trim();
                    var gateway = parts[2].Trim();
                    // /32 = 255.255.255.255 — host routes in persistent registry are almost always malicious
                    // Exclude on-link routes (gateway 0.0.0.0) which are used by local sandbox environments like Antigravity
                    if (mask == "255.255.255.255" && gateway != "0.0.0.0")
                    {
                        suspiciousRoutes.Add(valueName);
                    }
                }

                if (suspiciousRoutes.Count >= 3 && ResponsePolicy.MayPerformInlineHostMutation(_config))
                {
                    foreach (var route in suspiciousRoutes)
                    {
                        key.DeleteValue(route, throwOnMissingValue: false);
                    }

                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network: Persistent Route Registry Cleaned",
                        Evidence = $"Removed {suspiciousRoutes.Count} suspicious /32 persistent routes from registry at startup",
                        Reasoning = "Multiple /32 host routes were found in the persistent routes registry key, indicating a prior or ongoing attack that injects routes surviving reboot. All suspicious entries have been removed.",
                        Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            ["RemovedCount"] = suspiciousRoutes.Count.ToString(),
                            ["Routes"] = string.Join("; ", suspiciousRoutes.Take(10))
                        }
                    });

                    _logger.LogWarning("[RouteTableMonitor] Startup cleanup: removed {Count} persistent /32 routes",
                        suspiciousRoutes.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RouteTableMonitor] Persistent route registry check failed");
            }
        }

        /// <summary>
        /// Runtime check: detect new persistent route entries added since startup.
        /// </summary>
        private void CheckPersistentRouteRegistry()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(PersistentRoutesKey);
                if (key == null) return;

                var values = key.GetValueNames();
                foreach (var valueName in values)
                {
                    if (string.IsNullOrEmpty(valueName)) continue;
                    var regKey = $"persistent:{valueName}";
                    if (_baselineRoutes.ContainsKey(regKey)) continue;

                    // New persistent route added at runtime
                    var parts = valueName.Split(',');
                    if (parts.Length < 3) continue;

                    var dest = parts[0].Trim();
                    var mask = parts[1].Trim();
                    var gateway = parts[2].Trim();

                    _baselineRoutes[regKey] = new RouteEntry(); // Mark as seen

                    if (mask == "255.255.255.255" && gateway != "0.0.0.0") // /32 — suspicious (exclude local sandbox/on-link routes)
                    {
                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Network: Persistent Route Registry Modified",
                            Evidence = $"New persistent /32 route added: {dest} mask {mask} via {gateway}",
                            Reasoning = "A new /32 host route was added to the persistent routes registry, ensuring traffic redirection survives reboot. This is a persistence mechanism for network-level MitM.",
                            Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.RemoveRegistryEntry,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                ["Hive"] = "HKLM",
                                ["KeyPath"] = PersistentRoutesKey,
                                ["ValueName"] = valueName,
                                ["Destination"] = dest,
                                ["Gateway"] = gateway
                            }
                        });
                    }
                }
            }
            catch { }
        }

        #region Helpers

        private List<RouteEntry> GetRouteTable()
        {
            var routes = new List<RouteEntry>();
            int size = 0;
            GetIpForwardTable(IntPtr.Zero, ref size, true);
            if (size == 0) return routes;

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetIpForwardTable(buffer, ref size, true) != 0) return routes;

                int numEntries = Marshal.ReadInt32(buffer);
                int entrySize = Marshal.SizeOf<MIB_IPFORWARDROW>();

                for (int i = 0; i < numEntries; i++)
                {
                    var rowPtr = IntPtr.Add(buffer, 4 + i * entrySize);
                    var row = Marshal.PtrToStructure<MIB_IPFORWARDROW>(rowPtr);

                    var entry = new RouteEntry
                    {
                        Destination = row.dwForwardDest,
                        Mask = row.dwForwardMask,
                        NextHop = row.dwForwardNextHop,
                        InterfaceIndex = row.dwForwardIfIndex,
                        Type = row.dwForwardType,
                        Proto = row.dwForwardProto,
                        Metric = row.dwForwardMetric1
                    };
                    routes.Add(entry);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            return routes;
        }

        private static bool IsMulticastOrBroadcast(uint dest)
        {
            byte firstOctet = (byte)(dest & 0xFF); // Little-endian
            return firstOctet >= 224 || dest == 0xFFFFFFFF;
        }

        private bool IsVirtualAdapter(int interfaceIndex)
        {
            try
            {
                var ifRow = new MIB_IFROW
                {
                    dwIndex = interfaceIndex,
                    bPhysAddr = new byte[8],
                    bDescr = new byte[256]
                };
                if (GetIfEntry(ref ifRow) != 0) return false;

                var descr = System.Text.Encoding.ASCII.GetString(ifRow.bDescr, 0, ifRow.dwDescrLen).ToLowerInvariant();
                return VirtualAdapterFragments.Any(f => descr.Contains(f));
            }
            catch { return false; }
        }

        private static string? GetDefaultGateway()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    var gw = ni.GetIPProperties().GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (gw != null) return gw.Address.ToString();
                }
            }
            catch { }
            return null;
        }

        private static string UintToIp(uint addr)
        {
            return new IPAddress(BitConverter.GetBytes(addr)).ToString();
        }

        #endregion

        public void Dispose()
        {
            _timer.Dispose();
        }

        private sealed class RouteEntry
        {
            public uint Destination { get; set; }
            public uint Mask { get; set; }
            public uint NextHop { get; set; }
            public int InterfaceIndex { get; set; }
            public int Type { get; set; }
            public int Proto { get; set; }
            public int Metric { get; set; }
            public string Key => $"{Destination:X8}:{Mask:X8}:{NextHop:X8}:{InterfaceIndex}";
        }
    }
}
