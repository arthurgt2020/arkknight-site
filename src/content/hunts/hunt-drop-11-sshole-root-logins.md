---
title: "Hunt Drop 11 | SSHole: Hunting Root Logins That Skipped the Password"
hypothesis: A password-less SSH login on a musl build without PAM was used to get root.
attack: [T1021.004, T1033, T1082, T1190, T1133, T1548, T1136.001, T1098.004]
dataSources: [Linux EDR process events, Network events, File events]
languages: [KQL, CQL]
drop: 11
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-11-09
---

Builds on [Intel Drop 33](/intel/intel-drop-33-openssh-sshole/).

OpenSSH CVE-2026-123158 lets password logins succeed on accounts that have no password, on musl builds without PAM (think Alpine). Exploitation attempts were reported within nine hours of disclosure, including root on a honeypot.

## The hypothesis

If SSHole was used against us, we expect `sshd` to spawn a short, non-interactive session running `id`, `uname` and `hostname`, followed by `doas`, a new user or an `authorized_keys` change.

## What to hunt

Analyst ATT&CK mapping.

- `sshd` → `id` / `uname` / `hostname` burst in one session (T1021.004, T1033, T1082)
- Inbound SSH to Linux from public IPs, plus the published source IP (T1190, T1133)
- `doas`, `adduser`/`useradd` or `authorized_keys` edits after an SSH login (T1548, T1136.001, T1098.004)

## Business risk

Alpine sits under many containers, appliances and cloud images. Root on one means data access, a pivot point and tampered services. The catch: musl hosts are often outside EDR support, so no hits does not mean no compromise.

**Risk score:** likelihood 3 × impact 4 = **12/25, HIGH** (analyst judgement).

## Tune and triage

Allow-list Ansible, monitoring and jump-host accounts. On a hit, check `/var/log/messages` for "Accepted password for" on password-less accounts, then review `doas` use, new users and `authorized_keys`. Patch to OpenSSH 10.6p2.

## Confidence

| Assessment | Confidence |
|---|---|
| Intel confidence | MODERATE |
| Detection fidelity | LOW |

## Microsoft Defender (KQL)

```kql
// =====================================================================================
// Hunt Drop #11 | SSHole: Hunting Root Logins That Skipped the Password
// Builds on Intel Drop #33 (OpenSSH CVE-2026-123158 "SSHole", fixed in 10.6p2)
// Platform: Microsoft Defender XDR Advanced Hunting (Defender for Endpoint P2, Linux sensor)
// STATUS: UNTESTED in a live tenant. Test and tune in a lab/tenant before any use.
// ATT&CK IDs below are ANALYST MAPPINGS (the sources do not publish ATT&CK IDs).
// COVERAGE WARNING: Alpine/musl is not on the MDE Linux supported-distribution list, so
// the hosts that are actually vulnerable may have no sensor. These hunts cover onboarded
// Linux hosts (and see the same post-exploitation pattern anywhere it occurs).
// Default window: 14 days.
// =====================================================================================


// -------------------------------------------------------------------------------------
// H1 | sshd -> non-interactive recon burst (id / uname / hostname)
// ATT&CK (analyst): T1021.004 Remote Services: SSH, T1033 System Owner/User Discovery,
//                   T1082 System Information Discovery
// Hypothesis: if SSHole (or any illicit SSH login) hit our Linux estate, sshd spawns a
//   short non-interactive session that runs id, uname and hostname within minutes
//   (the post-login pattern Previdian reported on its honeypot).
// Expected noise: MEDIUM-HIGH. Ansible, config management, monitoring and jump-host
//   scripts run exactly these commands over SSH. Allow-list by account and source.
// Note: on BusyBox systems FileName may be "busybox" while the command line starts with
//   the applet name, so the match is on the command line, not only FileName.
// -------------------------------------------------------------------------------------
let lookback = 14d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "sshd" or InitiatingProcessParentFileName =~ "sshd"
| extend Cmd = tolower(ProcessCommandLine)
| extend Tools = extract_all(@"(?:^|[\s;&|/])(id|uname|hostname)(?:[\s;&|]|$)", Cmd)
| where array_length(Tools) > 0
| mv-expand Tool = Tools to typeof(string)
| summarize ReconTools = make_set(Tool),
            Commands = make_set(ProcessCommandLine, 20),
            Accounts = make_set(AccountName, 10),
            Parents = make_set(InitiatingProcessCommandLine, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceId, DeviceName, Window = bin(Timestamp, 5m)
| where array_length(ReconTools) >= 2
// | where not(Accounts has_any ("ansible", "svc_monitor"))   // TUNE: your automation accounts
| order by LastSeen desc


// -------------------------------------------------------------------------------------
// H2a | Inbound SSH to Linux hosts from public IPs (exposure + who is knocking)
// ATT&CK (analyst): T1190 Exploit Public-Facing Application, T1133 External Remote Services
// Hypothesis: SSHole needs reachable sshd with password auth on. Internet-facing Linux
//   SSH listeners are the hunt scope; unusual public sources are the leads.
// Expected noise: HIGH on internet-facing hosts (constant scanning). Use for scoping and
//   pivoting from H1/H3 hits, not as a standalone alert.
// Unverified values: OSPlatform "Linux" and RemoteIPType "Public" are not enumerated on
//   the Microsoft Learn pages; confirm in the in-portal schema reference.
// -------------------------------------------------------------------------------------
let lookback = 14d;
let LinuxDevices = DeviceInfo
    | where Timestamp > ago(lookback)
    | where OSPlatform =~ "Linux"                    // UNVERIFIED value
    | distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where DeviceId in (LinuxDevices)
| where LocalPort == 22
| where RemoteIPType == "Public"                     // UNVERIFIED value
| summarize Connections = count(), DistinctSources = dcount(RemoteIP),
            SampleSources = make_set(RemoteIP, 50), Actions = make_set(ActionType),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceId, DeviceName
| order by DistinctSources desc


// -------------------------------------------------------------------------------------
// H2b | IOC sweep: the single published exploitation source IP
// Source: Help Net Security / The Hacker News (6 Nov 2026), citing Previdian telemetry.
// Defanged in notes as 89.116.89[.]18; real string used below so the query works.
// Expected noise: LOW. A hit = contact with the reported exploitation source.
// -------------------------------------------------------------------------------------
let lookback = 14d;
let ioc = dynamic(["89.116.89.18"]);
union
    (DeviceNetworkEvents
     | where Timestamp > ago(lookback)
     | where RemoteIP in (ioc)
     | project Timestamp, DeviceName, Table = "DeviceNetworkEvents", ActionType, RemoteIP,
               RemotePort, LocalPort, Account = InitiatingProcessAccountName,
               Process = InitiatingProcessFileName),
    (DeviceLogonEvents
     | where Timestamp > ago(lookback)
     | where RemoteIP in (ioc)
     | project Timestamp, DeviceName, Table = "DeviceLogonEvents", ActionType, RemoteIP,
               RemotePort, LocalPort = int(null), Account = AccountName,
               Process = InitiatingProcessFileName)
| order by Timestamp desc


// -------------------------------------------------------------------------------------
// H3a | Privilege / persistence follow-on from an SSH session
// ATT&CK (analyst): T1548 Abuse Elevation Control Mechanism (doas), T1136.001 Create
//   Account: Local Account, T1098.004 Account Manipulation: SSH Authorized Keys
// Hypothesis: after a password-less login (e.g. the Alpine cloud-image "alpine" user with
//   passwordless doas), the attacker escalates with doas, adds a user or plants a key.
//   Ethiack's guidance: review doas use, new users, changed files and authorized_keys.
// Expected noise: MEDIUM. Admins legitimately add users/keys; baseline per host.
// -------------------------------------------------------------------------------------
let lookback = 14d;
let acctTools = dynamic(["doas", "adduser", "useradd", "usermod", "chpasswd", "passwd"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| extend Cmd = tolower(ProcessCommandLine)
| where FileName in~ (acctTools)
     or (FileName =~ "busybox" and Cmd matches regex @"^(\S*/)?(adduser|passwd)\s")
     or Cmd has "authorized_keys"
| extend FromSSH = InitiatingProcessFileName =~ "sshd"
                or InitiatingProcessParentFileName =~ "sshd"
                or InitiatingProcessCommandLine has "sshd"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, FromSSH
| order by FromSSH desc, Timestamp desc


// -------------------------------------------------------------------------------------
// H3b | authorized_keys and doas config file changes
// ATT&CK (analyst): T1098.004, T1548
// Expected noise: LOW-MEDIUM (key rotation, provisioning tools).
// ActionType values for DeviceFileEvents are not listed on the Learn page: they are
//   projected, not filtered.
// -------------------------------------------------------------------------------------
let lookback = 14d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where FileName =~ "authorized_keys" or FolderPath startswith "/etc/doas"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc


// -------------------------------------------------------------------------------------
// H0 | Scoping helper: Linux inventory by distribution (find musl / Alpine gaps)
// Not a hunt: tells you which distributions are onboarded. Alpine hosts missing from this
// list need syslog review (/var/log/messages) and asset scanning outside Defender.
// -------------------------------------------------------------------------------------
DeviceInfo
| where Timestamp > ago(14d)
| where OSPlatform =~ "Linux"                        // UNVERIFIED value
| summarize arg_max(Timestamp, OSDistribution, OSVersionInfo, OnboardingStatus, PublicIP) by DeviceId, DeviceName
| summarize Devices = count(), SampleDevices = make_set(DeviceName, 20) by OSDistribution, OnboardingStatus
| order by Devices desc
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================================
// Hunt Drop #11 | SSHole: Hunting Root Logins That Skipped the Password
// Builds on Intel Drop #33 (OpenSSH CVE-2026-123158 "SSHole", fixed in 10.6p2)
// Platform: CrowdStrike Falcon Next-Gen SIEM / Advanced Event Search (CQL), Falcon Insight
// STATUS: UNTESTED in a live tenant. Test and tune in a lab/tenant before any use.
// ATT&CK IDs below are ANALYST MAPPINGS (the sources do not publish ATT&CK IDs).
// TIME PICKER: set to "Last 14 days" for every query below.
// COVERAGE WARNING: Alpine is not on the published Falcon Linux sensor OS list reviewed
// in this run, so vulnerable musl hosts may have no sensor.
// CQL double-check: cqlsearch.com was NOT reachable from this run (blocked by the sandbox
// allowlist). Fallback checks: library.humio.com function pages + CrowdStrike
// logscale-community-content wiki (mirror) + community query collections.
// Lines marked "UNVERIFIED" use a field or behaviour not confirmed in this run's sources.
// =====================================================================================


// -------------------------------------------------------------------------------------
// H1 | sshd -> non-interactive recon burst (id / uname / hostname)
// ATT&CK (analyst): T1021.004, T1033, T1082
// Hypothesis: an illicit SSH login (SSHole or other) produces a short session where sshd
//   (parent or grandparent) runs id, uname and hostname.
// Expected noise: MEDIUM-HIGH (Ansible, monitoring, jump hosts). Allow-list accounts.
// -------------------------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Lin
| ParentBaseFileName="sshd" OR GrandParentBaseFileName="sshd"
// Named capture group extracts ReconTool (UNVERIFIED: named-group extraction not re-read in this run)
| CommandLine=/(?:^|[\s;&|\/])(?<ReconTool>id|uname|hostname)(?:[\s;&|]|$)/i
| groupBy([aid, ComputerName],
    function=[count(as=Events),
              count(ReconTool, distinct=true, as=ReconTools),   // distinct=true UNVERIFIED in this run
              collect([ReconTool, CommandLine, ParentBaseFileName, UID]),  // UID: UNVERIFIED field name (pwnkit blog uses UID_decimal in legacy search)
              min(@timestamp, as=FirstSeen),
              max(@timestamp, as=LastSeen)],
    limit=max)
| ReconTools >= 2
| sort(LastSeen, order=desc, limit=1000)
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, timezone="UTC")
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, timezone="UTC")


// -------------------------------------------------------------------------------------
// H2a | Inbound/outbound SSH-related network events with public peers + IOC sweep
// ATT&CK (analyst): T1190, T1133
// Expected noise: HIGH on internet-facing hosts (scanning). Use to scope and pivot.
// IOC: 89.116.89[.]18 (Help Net Security / The Hacker News, citing Previdian). Real
// string used below so the query works.
// -------------------------------------------------------------------------------------
#event_simpleName=/^(NetworkReceiveAcceptIP4|NetworkConnectIP4)$/ event_platform=Lin
| RemoteAddressIP4="89.116.89.18" OR LocalPort=22 OR RemotePort=22   // LocalPort: UNVERIFIED field name
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
| case {
    RemoteAddressIP4="89.116.89.18" | Signal := "IOC_HIT";
    * | Signal := "public_ssh_peer";
  }
| groupBy([aid, ComputerName, #event_simpleName, Signal],
    function=[count(as=Events), count(RemoteAddressIP4, distinct=true, as=DistinctPeers),
              collect([RemoteAddressIP4])],
    limit=max)
| sort(DistinctPeers, order=desc, limit=1000)


// -------------------------------------------------------------------------------------
// H2b | SSH client IP per Linux session from SSH_CONNECTION (non-RFC1918 sources)
// ATT&CK (analyst): T1133, T1021.004
// Based on a community Linux SSH-audit pattern using CriticalEnvironmentVariableChanged
// with EnvironmentVariableName SSH_CONNECTION (third-party source, see notes).
// EnvironmentVariableValue: UNVERIFIED field name.
// -------------------------------------------------------------------------------------
#event_simpleName=CriticalEnvironmentVariableChanged event_platform=Lin
| EnvironmentVariableName="SSH_CONNECTION"
| EnvironmentVariableValue=/^(?<ClientIP>\S+)\s+(?<ClientPort>\d+)\s+(?<ServerIP>\S+)\s+(?<ServerPort>\d+)/
| !cidr(ClientIP, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"])
| groupBy([aid, ComputerName, ClientIP], function=[count(as=Sessions)], limit=max)
| sort(Sessions, order=desc, limit=1000)


// -------------------------------------------------------------------------------------
// H3 | Privilege / persistence follow-on (doas, new users, authorized_keys)
// ATT&CK (analyst): T1548, T1136.001, T1098.004
// Expected noise: MEDIUM (admin work, provisioning). Baseline per host and account.
// BusyBox note: applets run as FileName "busybox" with the applet name in CommandLine.
// -------------------------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Lin
| case {
    in(field="FileName", values=["doas", "adduser", "useradd", "usermod", "chpasswd", "passwd"]) | Signal := "account_or_priv_tool";
    FileName="busybox" CommandLine=/^(\S*\/)?(adduser|passwd)\s/i | Signal := "busybox_account_applet";
    CommandLine=/authorized_keys/i | Signal := "ssh_key_change";
  }
| case {
    ParentBaseFileName="sshd" OR GrandParentBaseFileName="sshd" | FromSSH := "yes";
    * | FromSSH := "no";
  }
| groupBy([aid, ComputerName, Signal, FromSSH],
    function=[count(as=Events), collect([FileName, CommandLine, ParentBaseFileName, GrandParentBaseFileName])],
    limit=max)
| sort(FromSSH, order=desc, limit=1000)
```

Queries are untested: tune before use.

## Sources

1. Ethiack: CVE-2026-123158 (sshole): OpenSSH Password Bypass on Alpine Linux (5 Nov 2026) <https://ethiack.com/info-hub/research/sshole-cve-2026-123158>
2. Help Net Security: OpenSSH flaw exploited in the wild just hours after disclosure (6 Nov 2026) <https://www.helpnetsecurity.com/2026/11/06/openssh-sshole-cve-2026-123158-exploitation/>
3. The Hacker News: Hackers Target OpenSSH SSHole Flaw Within Hours of Disclosure, Gain Root on Honeypot (6 Nov 2026) <https://thehackernews.com/2026/11/hackers-exploited-openssh-sshole-flaw.html>
4. Red Hat: CVE-2026-123158 security advisory <https://access.redhat.com/security/cve/cve-2026-123158>
