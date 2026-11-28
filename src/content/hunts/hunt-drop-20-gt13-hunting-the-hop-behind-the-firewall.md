---
title: "Hunt Drop 20 | GT13: Hunting the Hop Behind the Firewall Manager"
hypothesis: "An exposed file server becomes a tunnel hop: a web-service process runs recon, a key lands in authorized_keys, and Chisel tunnels toward firewall management servers."
attack: [T1190, T1059.004, T1098.004, T1572, T1105, T1574.006]
dataSources: ["Process events", "File events", "Network events"]
languages: [KQL, CQL]
drop: 20
risk: { likelihood: 3, impact: 5 }
status: published
date: 2026-11-25
---

Builds on [Intel Drop 50](/intel/intel-drop-50-gt13-check-point-management-servers/).

Threat Intelligence · Arkknight
https://arkknight.si

HUNT DROP 🧠 20 | GT13: Hunting the Hop Behind the Firewall Manager
Builds on Intel Drop 🧠 50

## The hypothesis
If GT13-style activity touched our estate, an exposed file server was the way in and a compromised Linux host is now the hop: a web-service process runs recon, a key lands in authorized_keys, and Chisel tunnels toward firewall management servers.

## What to hunt
- HFS or Node process spawning shells or recon one-liners (T1190, T1059.004)
- New keys in /root/.ssh/authorized_keys (T1098.004)
- Chisel client or server, scripted nmap, /root/exfil staging (T1572, T1105)
- ld.so.preload entry for a hidden .libproc.so (T1574.006)
ATT&CK IDs are analyst mappings.

## Business risk
Firewall management servers hold policy, the internal CA and credentials. GreyNoise saw policies unloaded and the CA copied. Risk score: Likelihood 3 × Impact 5 = 15/25, CRITICAL (analyst judgement, same as the Intel Drop).

## Tune & triage
Allow-list approved key changes and admin tunnels. On a hit: isolate the host, pull SSH and HFS logs, review management-server audit logs, rotate admin credentials and CA material.

**Risk: 15/25 CRITICAL** (likelihood 3 × impact 5, analyst judgement). Intel confidence: MODERATE. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// =====================================================================
// HUNT DROP #20 - GT13 / Check Point management server campaign
// Builds on Intel Drop #50. Draft for Arthur Thomas. 25 Nov 2026.
// UNTESTED in a live tenant: test and tune before any use.
// Default window: 14 days (Timestamp > ago(14d)). Extend to 30-90d for the IOC sweep.
// Telemetry: Defender for Endpoint P2 (Linux and Windows sensors). Check Point Gaia
// management servers are normally NOT covered by Defender: use Check Point audit logs there.
// ATT&CK IDs are ANALYST MAPPINGS: GreyNoise published none.
// =====================================================================


// ---------------------------------------------------------------------
// HUNT 1 - HFS (Rejetto) / Node worker spawning shells, recon or key plants
// Hypothesis: an internet-facing HFS host was entered with a forged admin session
//   (CVE-2026-61500) and used its command hook for recon (uname -a; df -h / | tail -1; whoami)
//   and to append a key to /root/.ssh/authorized_keys.
// ATT&CK (analyst): T1190, T1059.004, T1098.004
// Expected noise: admins running scripts through a Node-based file server; backup agents.
// Tuning: allow-list known automation by DeviceName and command line.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessCommandLine has "hfs"
    or InitiatingProcessFolderPath has_any ("hfs", "rejetto")
| where FileName in~ ("sh", "bash", "dash", "curl", "wget", "python3", "whoami", "uname", "cmd.exe", "powershell.exe")
    or ProcessCommandLine has_any ("authorized_keys", "uname -a", "whoami")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, FileName, ProcessCommandLine
| order by Timestamp desc


// ---------------------------------------------------------------------
// HUNT 2 - authorized_keys changes under /.ssh by unusual processes
// Hypothesis: the actor planted an SSH public key in /root/.ssh/authorized_keys; each later
//   compromised device held the matching private key (GreyNoise).
// ATT&CK (analyst): T1098.004
// Expected noise: config management, onboarding scripts, ssh-copy-id. Allow-list by initiating process.
// NOTE: ActionType values for DeviceFileEvents are not listed on the Learn table page:
//   confirm "FileCreated" / "FileModified" in your tenant (getschema / distinct ActionType).
// ---------------------------------------------------------------------
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName =~ "authorized_keys" and FolderPath has "/.ssh"
| where ActionType in ("FileCreated", "FileModified")
| where InitiatingProcessFileName !in~ ("sshd", "ssh-copy-id")
| project Timestamp, DeviceName, FolderPath, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc


// ---------------------------------------------------------------------
// HUNT 3 - Hop / relay tooling: Chisel, nmap from scripts, /root/exfil, ld.so.preload
// Hypothesis: a compromised host was turned into a relay (hop): Chisel server/client, nmap,
//   staging in /root/exfil/, and an /etc/ld.so.preload entry referencing /usr/lib/.libproc.so
//   (GreyNoise says the preload error may indicate an implant).
// ATT&CK (analyst): T1572, T1105, T1046, T1574.006
// Expected noise: legitimate pentest or admin use of nmap/chisel; vulnerability scanners.
// ---------------------------------------------------------------------
union DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine matches regex @"(?i)chisel\s+(client|server)"
    or (FileName =~ "nmap" and InitiatingProcessFileName in~ ("sh", "bash", "python", "python3"))
    or FolderPath has "/root/exfil"
    or FileName in~ (".libproc.so", "ld.so.preload")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc


// ---------------------------------------------------------------------
// HUNT 4 (IOC sweep) - GT13 domain and Check Point advisory IPs
// Sources: GreyNoise 23 Nov 2026 (newpayapp[.]com, ZULT download subdomain);
//   Check Point advisory 22 Jul 2026 (background, 6 IPs seen exploiting CVE-2026-16232).
// GT13's own 99 IPs are mostly ExpressVPN egress or compromised devices: shared infrastructure,
//   so they are NOT swept here (load them from the GreyNoise post if you want, and expect noise).
// ATT&CK (analyst): T1105, T1071
// ---------------------------------------------------------------------
let iocIPs = dynamic(["151.241.99.207", "151.241.99.233", "158.62.198.182",
                      "192.142.10.99", "139.28.37.250", "194.213.18.137"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has "newpayapp.com" or RemoteIP in (iocIPs)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================
// HUNT DROP #20 - GT13 / Check Point management server campaign (CrowdStrike Falcon CQL)
// Builds on Intel Drop #50. Draft for Arthur Thomas. 25 Nov 2026.
// UNTESTED in a live tenant: test and tune before any use.
// Time window: set the Falcon time picker to 14 days (extend to 30-90 days for the IOC sweep).
// Telemetry: Falcon Insight / Next-Gen SIEM. Check Point Gaia management servers are normally
// NOT covered by the Falcon sensor: use Check Point audit logs there.
// ATT&CK IDs are ANALYST MAPPINGS: GreyNoise published none.
// UNVERIFIED items are marked [UNVERIFIED]; see the CQL double-check table in the markdown.
// =====================================================================


// ---------------------------------------------------------------------
// HUNT 1 - HFS (Rejetto) / Node worker spawning shells or recon
// Hypothesis: forged-admin-session access to HFS (CVE-2026-61500), then command hook recon
//   (uname -a; df -h / | tail -1; whoami) and key plant.
// ATT&CK (analyst): T1190, T1059.004
// Expected noise: Node-based admin tooling. Allow-list by aid / ComputerName / CommandLine.
// [UNVERIFIED] UserName on Linux ProcessRollup2 not confirmed on a public page this run.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| in(field=ParentBaseFileName, values=["node", "hfs", "hfs.exe"], ignoreCase=true)
| ImageFileName=/(\/|\\)(sh|bash|dash|curl|wget|python3?|whoami|uname|cmd\.exe|powershell\.exe)$/i
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine], limit=1000)


// ---------------------------------------------------------------------
// HUNT 2 - key plant, Chisel, staging dir, ld.so.preload (command-line view)
// Hypothesis: SSH key appended to authorized_keys; host turned into a relay with Chisel;
//   /root/exfil staging; /etc/ld.so.preload entry for /usr/lib/.libproc.so.
// ATT&CK (analyst): T1098.004, T1572, T1105, T1574.006
// Expected noise: admin key management, legitimate Chisel/nmap use.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| CommandLine=/authorized_keys|chisel\s+(client|server)|\/root\/exfil|\.libproc\.so|ld\.so\.preload/i
| groupBy([aid, ComputerName, ParentBaseFileName, ImageFileName], function=collect(CommandLine), limit=max)


// ---------------------------------------------------------------------
// HUNT 3 (IOC sweep, DNS) - GT13 domain (GreyNoise 23 Nov 2026)
// ATT&CK (analyst): T1105, T1071
// ---------------------------------------------------------------------
#event_simpleName=DnsRequest
| DomainName=/(^|\.)newpayapp\.com$/i
| table([@timestamp, aid, ComputerName, DomainName], limit=1000)


// ---------------------------------------------------------------------
// HUNT 4 (IOC sweep, network) - Check Point advisory IPs (22 Jul 2026, background)
// GT13's own 99 IPs are mostly ExpressVPN egress / compromised devices: not swept (shared infrastructure).
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4
| in(field=RemoteAddressIP4, values=["151.241.99.207", "151.241.99.233", "158.62.198.182", "192.142.10.99", "139.28.37.250", "194.213.18.137"])
| table([@timestamp, aid, ComputerName, ImageFileName, RemoteAddressIP4, RemotePort], limit=1000)
```

Queries are untested: tune before use.

## Sources

1. GreyNoise (23 Nov 2026): <https://www.greynoise.io/blog/check-point-security-management-servers-intrusion-campaign>
2. SecurityWeek (24 Nov 2026): <https://www.securityweek.com/check-point-security-management-servers-hacked-in-ai-assisted-campaign/>
