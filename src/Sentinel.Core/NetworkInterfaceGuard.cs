using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors and hardens network interface state:
    /// - Detects and removes network bridges via SetupAPI (DIF_REMOVE)
    /// - Re-enables disabled physical adapters via WMI (MSFT_NetAdapter)
    /// - Locks adapter DNS configuration to baseline registry values
    /// - Enforces global DNS-over-HTTPS (DoH) parameters
    /// </summary>
    public sealed class NetworkInterfaceGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<NetworkInterfaceGuard> _logger;

        private readonly HashSet<int> _baselinePhysicalInterfaceIndices = new();
        private readonly Dictionary<string, string> _baselineDnsServers = new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(15);
        private const string InterfacesKeyPath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

        #region SetupAPI P/Invoke

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid classGuid;
            public int devInst;
            public IntPtr reserved;
        }

        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SetupDiGetClassDevs(
            ref Guid ClassGuid,
            string? Enumerator,
            IntPtr hwndParent,
            int Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(
            IntPtr DeviceInfoSet,
            int MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceRegistryProperty(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            int Property,
            out int PropertyRegDataType,
            byte[]? PropertyBuffer,
            int PropertyBufferSize,
            out int RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiCallClassInstaller(
            int installFunction,
            IntPtr deviceInfoSet,
            ref SP_DEVINFO_DATA deviceInfoData);

        private const int DIGCF_PRESENT = 0x00000002;
        private const int SPDRP_SERVICE = 0x00000004;
        private const int DIF_REMOVE = 0x00000005;

        private static readonly Guid GUID_DEVCLASS_NET = new Guid("{4d36e972-e325-11ce-bfc1-08002be10318}");

        #endregion

        public NetworkInterfaceGuard(
            DetectionEngine detectionEngine,
            SentinelConfig config,
            ILogger<NetworkInterfaceGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _config = config;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[NetworkInterfaceGuard] Started");

            // Baseline current configurations
            BaselinePhysicalAdapters();
            BaselineDnsServers();
            EnforceSecureDoh();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(CheckInterval, ct);

                    // 1. Detect and remove network bridges
                    CheckAndRemoveBridges();

                    // 2. Re-enable disabled physical network adapters
                    await CheckAndRestoreDisabledAdaptersAsync(ct);

                    // 3. Monitor and lock DNS configuration
                    await CheckAndLockDnsAsync(ct);

                    // 4. Ensure DoH remains enabled
                    EnforceSecureDoh();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error in execution loop");
                }
            }
        }

        private void BaselinePhysicalAdapters()
        {
            try
            {
                var scope = new ManagementScope(@"root\StandardCimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT InterfaceIndex, Name, Virtual, InterfaceStatus FROM MSFT_NetAdapter WHERE Virtual = false");
                using var searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    int index = Convert.ToInt32(obj["InterfaceIndex"]);
                    string name = obj["Name"]?.ToString() ?? "";
                    int status = Convert.ToInt32(obj["InterfaceStatus"]);

                    _baselinePhysicalInterfaceIndices.Add(index);
                    _logger.LogInformation("[NetworkInterfaceGuard] Baselined physical network adapter: '{Name}' (Index {Index}, Status {Status})", name, index, status);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[NetworkInterfaceGuard] Failed to baseline physical network adapters");
            }
        }

        private void BaselineDnsServers()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up && 
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var props = ni.GetIPProperties();
                        var dns = props.DnsAddresses
                            .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            .Select(a => a.ToString())
                            .ToList();
                        
                        if (dns.Count > 0)
                        {
                            var dnsStr = string.Join(",", dns);
                            _baselineDnsServers[ni.Id] = dnsStr;
                            _logger.LogInformation("[NetworkInterfaceGuard] Baselined DNS for interface {Name} ({Guid}): {DNS}", ni.Name, ni.Id, dnsStr);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[NetworkInterfaceGuard] Failed to baseline DNS servers");
            }
        }

        private void CheckAndRemoveBridges()
        {
            try
            {
                // Check if any adapter in NetworkInterface list is a bridge
                var bridgeInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.Description.Contains("MAC Bridge") || 
                                 ni.Description.Contains("Multiplexor Driver"))
                    .ToList();

                if (bridgeInterfaces.Count == 0) return;

                foreach (var bridge in bridgeInterfaces)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network: Unauthorized Network Bridge Detected",
                        Evidence = $"Network bridge interface discovered: '{bridge.Name}' ({bridge.Description})",
                        Reasoning = "A network adapter bridge was created on the system. Network bridges allow lateral movement pivoting, bypassing the host firewall, and direct traffic routing into secure network segments.",
                        Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly, // We handle unbridging ourselves
                        ProcessName = "SYSTEM", ProcessId = 0
                    });
                }

                // Active response: remove the bridge device via SetupAPI
                if (ResponsePolicy.MayPerformInlineHostMutation(_config))
                {
                    RemoveNetworkBridge();
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error checking network bridges");
            }
        }

        private void RemoveNetworkBridge()
        {
            Guid netClassGuid = GUID_DEVCLASS_NET;
            IntPtr deviceInfoSet = SetupDiGetClassDevs(ref netClassGuid, null, IntPtr.Zero, DIGCF_PRESENT);
            if (deviceInfoSet == (IntPtr)(-1)) return;

            try
            {
                var deviceInfoData = new SP_DEVINFO_DATA();
                deviceInfoData.cbSize = Marshal.SizeOf(deviceInfoData);
                int index = 0;

                while (SetupDiEnumDeviceInfo(deviceInfoSet, index, ref deviceInfoData))
                {
                    string service = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_SERVICE);
                    if (service.Equals("bridge") || 
                        service.Equals("macbridge"))
                    {
                        _logger.LogWarning("[NetworkInterfaceGuard] Found MAC Bridge device (Service: {Service}). Removing...", service);
                        
                        bool success = SetupDiCallClassInstaller(DIF_REMOVE, deviceInfoSet, ref deviceInfoData);
                        if (success)
                        {
                            _logger.LogInformation("[NetworkInterfaceGuard] Successfully uninstalled MAC Bridge device.");
                        }
                        else
                        {
                            int error = Marshal.GetLastWin32Error();
                            _logger.LogWarning("[NetworkInterfaceGuard] Failed to uninstall MAC Bridge device. SetupAPI Error: {Error}", error);
                        }
                        break;
                    }
                    index++;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error during SetupAPI bridge removal");
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(deviceInfoSet);
            }
        }

        private async Task CheckAndRestoreDisabledAdaptersAsync(CancellationToken ct)
        {
            try
            {
                var scope = new ManagementScope(@"root\StandardCimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT InterfaceIndex, Name, AdminStatus FROM MSFT_NetAdapter WHERE Virtual = false");
                using var searcher = new ManagementObjectSearcher(scope, query);
                
                foreach (ManagementObject obj in searcher.Get())
                {
                    int index = Convert.ToInt32(obj["InterfaceIndex"]);
                    string name = obj["Name"]?.ToString() ?? "";
                    int adminStatus = Convert.ToInt32(obj["AdminStatus"]);

                    if (_baselinePhysicalInterfaceIndices.Contains(index) && adminStatus == 2) // 2 = Down/Disabled
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Network: Primary Adapter Disabled",
                            Evidence = $"Physical network adapter '{name}' (Index {index}) was disabled (AdminStatus changed to Down).",
                            Reasoning = "A physical network adapter that was previously active has been disabled. This could indicate malware attempting to sever network connectivity or execute off-line evasion tactics.",
                            Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });

                        if (ResponsePolicy.MayPerformInlineHostMutation(_config))
                        {
                            _logger.LogWarning("[NetworkInterfaceGuard] Active Response: Re-enabling network adapter '{Name}' (Index {Index})", name, index);
                            obj.InvokeMethod("Enable", null);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error checking/restoring network adapters");
            }
        }

        private async Task CheckAndLockDnsAsync(CancellationToken ct)
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (_baselineDnsServers.TryGetValue(ni.Id, out var baselineDns))
                    {
                        var currentDns = GetRegistryDns(ni.Id);
                        if (!string.IsNullOrEmpty(currentDns) && !currentDns!.Equals(baselineDns))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Network: Unauthorized DNS Change",
                                Evidence = $"DNS NameServer configuration for interface '{ni.Name}' changed from '{baselineDns}' to '{currentDns}' in Registry.",
                                Reasoning = "An unauthorized process modified the network adapter's DNS settings. This is a common hijacking technique to redirect web traffic to malicious servers.",
                                Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });

                            if (ResponsePolicy.MayPerformInlineHostMutation(_config))
                            {
                                SetRegistryDns(ni.Id, baselineDns);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error checking/locking DNS");
            }
        }

        private string? GetRegistryDns(string interfaceGuid)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{InterfacesKeyPath}\{interfaceGuid}");
                return key?.GetValue("NameServer")?.ToString();
            }
            catch { return null; }
        }

        private void SetRegistryDns(string interfaceGuid, string dnsServers)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{InterfacesKeyPath}\{interfaceGuid}", writable: true);
                if (key != null)
                {
                    key.SetValue("NameServer", dnsServers, RegistryValueKind.String);
                    _logger.LogInformation("[NetworkInterfaceGuard] Restored DNS servers on interface {Guid} to secure baseline: {DNS}", interfaceGuid, dnsServers);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[NetworkInterfaceGuard] Failed to set DNS servers on interface {Guid}", interfaceGuid);
            }
        }

        private void EnforceSecureDoh()
        {
            // REMOVED: This conflicts with BrowserDnsPolicyGuard which disables DoH to enforce
            // hosts-file-based blocking. BrowserDnsPolicyGuard is the authoritative policy —
            // the hosts file is the DNS override mechanism for this system.
            // NetworkInterfaceGuard should NOT re-enable DoH.
        }

        private static string GetDeviceProperty(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, int property)
        {
            int requiredSize = 0;
            SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData, property, out _, null, 0, out requiredSize);
            if (requiredSize > 0)
            {
                byte[] buffer = new byte[requiredSize];
                if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData, property, out _, buffer, buffer.Length, out _))
                {
                    return System.Text.Encoding.Unicode.GetString(buffer).TrimEnd('\0');
                }
            }
            return string.Empty;
        }
    }
}
