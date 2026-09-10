# Sentinel

Userland endpoint detection and response (EDR) for Windows. Monitors running processes, network activity, file system changes, and kernel driver loads in real time. When a multi-signal chain confirms a kill-grade attack - credential dump, reverse shell, C2 beaconing, process injection, BYOVD - it kills the process tree and writes a sealed evidence pack.

**Platform:** Windows 10/11 x64 - .NET Framework 4.8  
**Version:** 2.6.2

## What it does

- Detects credential theft, reverse shells, C2 beaconing, process injection, BYOVD driver abuse, WSL pivots, covert mesh/webhook C2, and more
- Chain-confirms kills - a single weak signal never authorises a response
- Applies host hardening on startup: IPSec port lockdown, ASR Block rules, RPC/DCOM firewall, credential hardening (LSASS PPL, WDigest off)
- Tray agent with a local web dashboard on `localhost:19845`
- Writes sealed evidence packs for law enforcement reporting

## Install

Run `SentinelSetup-2.6.2.exe` as Administrator. Requires .NET Framework 4.8.

The installer registers `Sentinel` as a Windows service and adds `Sentinel.Agent.exe` to the autorun. Uninstall via **Add or Remove Programs** - the uninstaller stops both processes, removes the service, and cleans up IPSec/firewall rules.

## License

MIT - see [LICENSE](LICENSE).

---

## Legal Disclaimer

**Sentinel is provided for defensive, educational, and research purposes only.**

By installing or using this software you agree to the following:

1. You will only run Sentinel on systems you own or have explicit written authorisation to monitor.
2. You will not use Sentinel to monitor, surveil, or collect data on any person without their knowledge and consent where required by applicable law.
3. The authors and contributors accept no liability for damages, data loss, system instability, false positives, missed detections, or any other harm arising from the use or inability to use this software.
4. Sentinel actively kills processes and modifies host security policy. **Test in a non-production environment before deploying broadly.**
5. This software is provided **"as is"**, without warranty of any kind, express or implied.

Use responsibly and in compliance with all applicable local, national, and international laws.
