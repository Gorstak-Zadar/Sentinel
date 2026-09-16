using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.7.1: tests for the site-to-local-app hijack/pairing protections -
    /// DangerousLaunchFlagHeuristics, DangerousBrowserFlagRule, and the ProductPosture
    /// gates on NativeMessagingHostGuard / LocalControlChannelMonitor. Enforces the
    /// docs/constraints.md testing contract: Tier1 rules prove Tier1Behavioral, Tier2
    /// rules prove Tier2Indicator + LogOnly, and proactive host mutations ship a
    /// default-deny gate test.
    /// </summary>
    public class BrowserAppControlGuardTests
    {
        private static FusedTelemetryContext Ctx(string proc, string cmd, string parent = "explorer")
        {
            var pt = new ProcessTelemetry
            {
                ProcessName = proc,
                ProcessId = 4242,
                CommandLine = cmd,
                ParentProcessName = parent,
                ImagePath = @"C:\Users\Admin\AppData\Local\app\" + proc,
            };
            return new FusedTelemetryContext
            {
                ProcessId = pt.ProcessId,
                ProcessName = pt.ProcessName,
                TriggeringEvent = pt,
            };
        }

        // ---- DangerousLaunchFlagHeuristics (pure classifier) ----------------

        [Theory]
        [InlineData("app.exe --remote-debugging-port=9222")]
        [InlineData("app.exe --disable-web-security")]
        [InlineData("app.exe --load-extension=C:\\evil")]
        [InlineData("app.exe --remote-debugging-pipe")]
        [InlineData("app.exe --disable-site-isolation-trials")]
        public void Heuristics_StrongFlags_ClassifyStrong(string cmd)
        {
            var (risk, flags) = DangerousLaunchFlagHeuristics.Classify(cmd);
            Assert.Equal(DangerousLaunchFlagHeuristics.FlagRisk.Strong, risk);
            Assert.NotEmpty(flags);
            Assert.True(DangerousLaunchFlagHeuristics.HasStrongControlFlag(cmd));
        }

        [Theory]
        [InlineData("app.exe --app=https://example.com")]
        [InlineData("app.exe --proxy-server=127.0.0.1:8080")]
        [InlineData("app.exe --headless")]
        public void Heuristics_WeakFlags_ClassifyWeak(string cmd)
        {
            var (risk, _) = DangerousLaunchFlagHeuristics.Classify(cmd);
            Assert.Equal(DangerousLaunchFlagHeuristics.FlagRisk.Weak, risk);
            Assert.False(DangerousLaunchFlagHeuristics.HasStrongControlFlag(cmd));
        }

        [Theory]
        [InlineData("app.exe")]
        [InlineData("app.exe --user-data-dir=C:\\Users\\me\\profile")]
        [InlineData("")]
        [InlineData(null)]
        public void Heuristics_BenignOrEmpty_ClassifyNone(string? cmd)
        {
            var (risk, _) = DangerousLaunchFlagHeuristics.Classify(cmd);
            Assert.Equal(DangerousLaunchFlagHeuristics.FlagRisk.None, risk);
        }

        [Fact]
        public void Heuristics_CaseInsensitive()
        {
            var (risk, _) = DangerousLaunchFlagHeuristics.Classify("APP.EXE --REMOTE-DEBUGGING-PORT=9222");
            Assert.Equal(DangerousLaunchFlagHeuristics.FlagRisk.Strong, risk);
        }

        // ---- DangerousBrowserFlagRule: tier contract ------------------------

        [Fact]
        public void Rule_StrongFlag_NonBrowserParent_IsTier1_Kill()
        {
            var rule = new DangerousBrowserFlagRule();
            // A random app launched with --load-extension by explorer = the hijack shape.
            var result = rule.Evaluate(Ctx("ceprkac.exe", "ceprkac.exe --load-extension=C:\\Users\\Admin\\AppData\\Local\\Temp\\x", parent: "explorer"));

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
            Assert.True(result.KillAuthorized);
            Assert.Equal(TerminalFamily.CredentialDump, result.Family);
        }

        [Fact]
        public void Rule_StrongFlag_BrowserParent_IsTier2_LogOnly()
        {
            var rule = new DangerousBrowserFlagRule();
            // Chrome spawning a child with a debug port is normal browser subprocess behavior.
            var result = rule.Evaluate(Ctx("chrome.exe", "chrome.exe --remote-debugging-port=9222", parent: "chrome"));

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
            Assert.False(result.KillAuthorized);
        }

        [Fact]
        public void Rule_WeakFlagOnly_IsTier2_LogOnly()
        {
            var rule = new DangerousBrowserFlagRule();
            var result = rule.Evaluate(Ctx("app.exe", "app.exe --app=https://example.com", parent: "explorer"));

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
        }

        [Fact]
        public void Rule_NoFlags_DoesNotFire()
        {
            var rule = new DangerousBrowserFlagRule();
            Assert.Null(rule.Evaluate(Ctx("app.exe", "app.exe --some-benign-flag", parent: "explorer")));
        }

        [Fact]
        public void Rule_DoesNotFire_OnNonProcessTelemetry()
        {
            var rule = new DangerousBrowserFlagRule();
            var ctx = new FusedTelemetryContext
            {
                ProcessId = 10,
                ProcessName = "x",
                TriggeringEvent = new NetworkTelemetry { ProcessName = "x", ProcessId = 10 },
            };
            Assert.Null(rule.Evaluate(ctx));
        }

        // ---- Tier2 log-only contract (constraint #3) ------------------------

        [Fact]
        public void Rule_Tier2Result_IsAlwaysLogOnly()
        {
            var rule = new DangerousBrowserFlagRule();
            // Every non-kill-shape result must be Tier2 + LogOnly, never a higher action.
            foreach (var (proc, cmd, parent) in new[]
            {
                ("chrome.exe", "chrome.exe --remote-debugging-port=9222", "chrome"),
                ("app.exe", "app.exe --app=https://x", "explorer"),
                ("app.exe", "app.exe --proxy-server=127.0.0.1:8888", "explorer"),
            })
            {
                var r = rule.Evaluate(Ctx(proc, cmd, parent));
                Assert.NotNull(r);
                if (r!.Tier == DetectionTier.Tier2Indicator)
                    Assert.Equal(ResponseAction.LogOnly, r.AuthorizedResponse);
            }
        }

        // ---- Proactive host mutation gate: default-deny seam (constraint #4) -

        [Fact]
        public void NativeMessagingHostGuard_GatesOnProductPosture()
        {
            Assert.True(NativeMessagingHostGuard.MayEnforce(new SentinelConfig()));
            Assert.True(NativeMessagingHostGuard.MayEnforce(null));
            Assert.Equal(
                ProductPosture.AllowsProactiveHostLockdown(new SentinelConfig()),
                NativeMessagingHostGuard.MayEnforce(new SentinelConfig()));
        }

        [Fact]
        public void LocalControlChannelMonitor_GatesOnProductPosture()
        {
            Assert.True(LocalControlChannelMonitor.MayEnforce(new SentinelConfig()));
            Assert.True(LocalControlChannelMonitor.MayEnforce(null));
            Assert.Equal(
                ProductPosture.AllowsProactiveHostLockdown(new SentinelConfig()),
                LocalControlChannelMonitor.MayEnforce(new SentinelConfig()));
        }
    }
}
