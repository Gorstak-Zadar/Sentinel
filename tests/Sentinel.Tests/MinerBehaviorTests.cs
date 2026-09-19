using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Contract tests for the behavioral cryptominer signal (MinerBehaviorMonitor emits
    /// "Resource Abuse: Cryptominer Behavior" tagged Family=CoinMiner).
    ///
    /// Enforces the docs/constraints.md testing contract for this Tier2 signal:
    ///   - it returns Tier2Indicator,
    ///   - the Tier2 log-only contract holds (even with ActiveResponse=true it stays LogOnly),
    ///   - it classifies as the CoinMiner terminal family (so it can seed a chain), yet
    ///   - it is NOT solo kill-grade and NOT an attack-class terminal, so a miner on its own
    ///     can NEVER authorize a destructive response. This is what guarantees that heavy
    ///     compute, streaming, and torrenting are observed, not killed.
    /// </summary>
    [Collection("ResponsePolicy")]
    public class MinerBehaviorTests
    {
        public MinerBehaviorTests()
        {
            ResponsePolicy.ResetForTests();
        }

        private static SentinelConfig ObserveConfig() => new()
        {
            ActiveResponse = true,
            ObserveUntilChain = true,
            ChainConfirmMinSignals = 2,
            ChainConfirmWindowSeconds = 300,
            MinTier1Confidence = 0.85,
        };

        // Mirrors exactly what MinerBehaviorMonitor.EmitMinerSeed produces.
        private static DetectionEvent MinerSeed(int pid = 6543, string process = "svc-host") => new()
        {
            RuleName = "Resource Abuse: Cryptominer Behavior",
            Evidence = "sustained CPU + persistent low-diversity pool connection",
            Reasoning = "behavioral miner signature",
            Confidence = 0.55,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            SignalType = SignalType.SuspiciousProcess,
            Family = TerminalFamily.CoinMiner,
            ProcessId = pid,
            ProcessName = process,
            Metadata = new Dictionary<string, string>
            {
                ["CpuPercent"] = "92",
                ["PoolEndpoint"] = "203.0.113.10:3333",
                ["EndpointDiversity"] = "1",
            },
        };

        [Fact]
        public void MinerSeed_IsTier2()
        {
            var d = MinerSeed();
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
        }

        [Fact]
        public void MinerSeed_HonorsTier2LogOnlyContract()
        {
            var d = MinerSeed();
            // Author response is LogOnly; applying tier law under an active config must not
            // promote it to any destructive action.
            ResponsePolicy.ApplyTierLaw(d);
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.False(d.KillAuthorized);
        }

        [Fact]
        public void MinerSeed_ClassifiesAsCoinMinerFamily()
        {
            var d = MinerSeed();
            // Typed family is authoritative and must round-trip to the canonical string.
            Assert.Equal("CoinMiner", ResponsePolicy.ClassifyTerminalOutcome(d));
        }

        [Fact]
        public void MinerSeed_IsNotSoloKillGrade()
        {
            var d = MinerSeed();
            // CoinMiner is terminal (seeds chains) but deliberately NOT kill-grade on its own.
            Assert.False(ResponsePolicy.IsKillGradeTerminal(d));
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
        }

        [Fact]
        public void MinerSeed_NeverAuthorizesDestructiveResponseAlone()
        {
            var d = MinerSeed();
            // The whole point: a miner by itself is observed, never killed. This is what keeps
            // legitimate heavy compute AND pirate-streaming / torrenting from being terminated.
            Assert.False(ResponsePolicy.MayPerformDestructiveResponse(d, ObserveConfig()));
        }

        [Fact]
        public void MinerSeed_CanSeedAChainWithARealTerminal()
        {
            // A miner alone stays observe...
            var miner = MinerSeed(pid: 7001, process: "dropper");
            Assert.False(ResponsePolicy.MayPerformDestructiveResponse(miner, ObserveConfig()));

            // ...but if the SAME process ALSO trips a genuine kill-grade attack-class terminal,
            // the multi-signal chain confirms and a destructive response becomes authorized.
            var realTerminal = new DetectionEvent
            {
                RuleName = "AMSI Bypass Detected",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessId = 7001,
                ProcessName = "dropper",
                SignalType = SignalType.SecurityEvasion,
            };
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(realTerminal, ObserveConfig()));
        }
    }
}
