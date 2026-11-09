---
title: "Hunt Drop 02 | PHP2Shell: hunt PHP workers gone rogue"
hypothesis: "A PHP web worker has been turned into a shell on the host."
attack: [T1059.004, T1059, T1033, T1505.003, T1071, T1053.003]
dataSources: ["Web server and PHP worker process events", "File events", "Network events"]
languages: [KQL, CQL]
drop: 2
risk: { likelihood: 4, impact: 5 }
linkedinUrl: "https://lnkd.in/p/dkmXT9hn"
status: published
date: 2026-10-21
---

Builds on [Intel Drop 5](/intel/intel-drop-05-php2shell/).

## The nine hunts

1. Exposure: PHP runtimes below 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, and EOL branches
2. php-fpm, php-cgi, httpd or apache2 spawning sh, bash, cmd, PowerShell, curl, wget or certutil
3. Reverse-shell and recon command lines (/dev/tcp, mkfifo, fsockopen, whoami, id) from the web account
4. New .php, .phtml or .phar files in web roots, /tmp or /dev/shm
5. Rare outbound connections from PHP workers to public IPs
6. Web-worker parent-child pairs not seen in the previous 28 days
7. Cron, SSH key or user changes by www-data, apache or nginx
8. "PHP Fatal error … tried to allocate … Unknown on line 0" in PHP logs
9. Bursts of Apache AH00052 child exits

No IOCs have been published yet, so these hunts are behavioural. Expect noise from deploy scripts and admin tooling; baseline before escalating. Treat a hit on hunt 2 or 3 as a potential compromise, and preserve the web and PHP logs first.

Once tuned to your estate, hunts 2, 3 and 7 are good candidates for promotion to detection rules.

Full KQL and CQL pack: link in the comments.

**Risk: 20/25 CRITICAL** (likelihood 4 × impact 5, analyst judgement). Hunt logic sourced: HIGH.

## Microsoft Defender (KQL)

```kusto
// ===== H1 Exposure - PHP runtimes and PHP2Shell CVEs (MDVM)
// Part A: devices where Defender Vulnerability Management already maps the CVEs (may be empty while MDVM catches up)
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-109618", "CVE-2026-109619")
| summarize CVEs = make_set(CveId), Software = make_set(strcat(SoftwareName, " ", SoftwareVersion), 20) by DeviceId, DeviceName, OSPlatform
| join kind=leftouter (
    DeviceTvmSoftwareInventory
    | where SoftwareName matches regex @"(?i)^php"
    | summarize PhpPackages = make_set(strcat(SoftwareName, " ", SoftwareVersion), 20) by DeviceId
  ) on DeviceId
| project DeviceName, OSPlatform, CVEs, Software, PhpPackages
// ===== H1b Exposure - PHP versions below the fixed builds (upstream versioning)
// Distro backports keep old version strings: confirm patch status from the package changelog, not this flag alone
DeviceTvmSoftwareInventory
| where SoftwareName matches regex @"(?i)^php([0-9]+(\.[0-9]+)?)?(-(cli|fpm|cgi|common))?(_for_linux)?$"
| extend Ver = extract(@"^(?:\d+:)?(\d+\.\d+\.\d+)", 1, SoftwareVersion)
| extend Major = toint(split(Ver, ".")[0]), Minor = toint(split(Ver, ".")[1]), Patch = toint(split(Ver, ".")[2])
| extend Status = case(
    isempty(Ver), "Unknown version - check manually",
    Major < 8 or (Major == 8 and Minor <= 1), "EOL branch - backport or upgrade",
    Major == 8 and Minor == 2 and Patch < 35, "Below 8.2.35",
    Major == 8 and Minor == 3 and Patch < 36, "Below 8.3.36",
    Major == 8 and Minor == 4 and Patch < 27, "Below 8.4.27",
    Major == 8 and Minor == 5 and Patch < 12, "Below 8.5.12",
    "At or above fixed build")
| where Status != "At or above fixed build"
| summarize Devices = dcount(DeviceId), DeviceList = make_set(DeviceName, 100) by SoftwareName, SoftwareVersion, Status
| order by Devices desc
// ===== H1c Internet-facing Windows/IIS hosts running php-cgi.exe below the PHP2Shell fixed builds (adapted from Sergio Albea)
let InternetFacingDevices = DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, IsInternetFacing, PublicIP) by DeviceId
    | where IsInternetFacing == true          // comment out to see all hosts, with the flag as a column
    | project DeviceId, IsInternetFacing, PublicIP;
let LatestInstalledPHP = DeviceTvmSoftwareInventory
    | where SoftwareName matches regex @"(?i)^php"
    | summarize InstalledPHP = make_set(SoftwareVersion, 10) by DeviceId;
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("php-cgi.exe", "php.exe")
| extend PathVersion = extract(@"(?i)\\v?(\d+\.\d+(?:\.\d+)?)\\php(-cgi)?\.exe$", 1, FolderPath)
| extend PHPVersion = coalesce(extract(@"^(\d+\.\d+\.\d+)", 1, ProcessVersionInfoProductVersion), PathVersion)
| extend Major = toint(split(PHPVersion, ".")[0]), Minor = toint(split(PHPVersion, ".")[1]), Patch = toint(split(PHPVersion, ".")[2])
| extend Status = case(
    isempty(PHPVersion), "Unknown version - check binary",
    Major < 8 or (Major == 8 and Minor <= 1), "EOL branch",
    Major == 8 and Minor == 2 and (isnull(Patch) or Patch < 35), "Below 8.2.35 or patch unknown",
    Major == 8 and Minor == 3 and (isnull(Patch) or Patch < 36), "Below 8.3.36 or patch unknown",
    Major == 8 and Minor == 4 and (isnull(Patch) or Patch < 27), "Below 8.4.27 or patch unknown",
    Major == 8 and Minor == 5 and (isnull(Patch) or Patch < 12), "Below 8.5.12 or patch unknown",
    "At or above fixed build")
| where Status != "At or above fixed build"
| join kind=inner InternetFacingDevices on DeviceId
| join kind=leftouter LatestInstalledPHP on DeviceId
| summarize FirstExecution = min(Timestamp), LastExecution = max(Timestamp), Executions = count(),
    ProcessPaths = make_set(FolderPath, 10), IISCommandLines = make_set(InitiatingProcessCommandLine, 10)
    by DeviceName, PublicIP, PHPVersion, Status, InstalledPHP = tostring(InstalledPHP)
| order by Status asc, Executions desc
// ===== H2 PHP or web worker spawning shells, interpreters or download tools
let lookback = datetime(2026-10-20T00:00:00Z);
let WebParents = @"(?i)^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$";
let Children = dynamic(["sh","bash","dash","zsh","busybox","cmd.exe","powershell.exe","pwsh.exe","python","python3","python.exe","perl","curl","curl.exe","wget","nc","ncat","socat","certutil.exe","bitsadmin.exe"]);
DeviceProcessEvents
| where Timestamp >= lookback
| where InitiatingProcessFileName matches regex WebParents
| where FileName in~ (Children)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
// ===== H3 Reverse-shell and recon command lines run as the web worker
let lookback = datetime(2026-10-20T00:00:00Z);
let WebParents = @"(?i)^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$";
let WebUsers = dynamic(["www-data","apache","nginx","http","wwwrun","nobody","daemon","iusr"]);
DeviceProcessEvents
| where Timestamp >= lookback
| where InitiatingProcessFileName matches regex WebParents
    or InitiatingProcessParentFileName matches regex WebParents
    or AccountName in~ (WebUsers)
| where ProcessCommandLine matches regex @"(?i)(/dev/(tcp|udp)/|mkfifo|fsockopen|n(c|cat)\s+.*-e\s|bash\s+-i|sh\s+-i|socat\s+.*exec)"
    or FileName in~ ("whoami", "whoami.exe", "id", "uname", "hostname", "hostname.exe", "ipconfig.exe", "ifconfig", "systeminfo.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
// ===== H4 PHP or script files written by web workers into web roots or temp paths
let lookback = datetime(2026-10-20T00:00:00Z);
let WebParents = @"(?i)^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe|sh|bash|dash|curl|wget)$";
DeviceFileEvents
| where Timestamp >= lookback
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName matches regex @"(?i)\.(php[0-9]?|phtml|phar)$"
| where FolderPath has_any ("/var/www/", "/srv/www/", "/usr/share/nginx/", "public_html", "wwwroot", "/tmp/", "/var/tmp/", "/dev/shm/")
| where InitiatingProcessFileName matches regex WebParents
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
// ===== H5 Rare outbound connections from PHP workers to public IPs
let lookback = datetime(2026-10-20T00:00:00Z);
let WebParents = @"(?i)^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|lsphp[0-9]*|frankenphp)$";
DeviceNetworkEvents
| where Timestamp >= lookback
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| where InitiatingProcessFileName matches regex WebParents
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Ports = make_set(RemotePort, 20), Urls = make_set(RemoteUrl, 20), Devices = make_set(DeviceName, 20) by RemoteIP, InitiatingProcessFileName
| extend DeviceCount = array_length(Devices)
| where DeviceCount <= 2
| order by Connections asc
// ===== H6 New web-worker parent to child pairs vs a 28-day baseline
let WebParents = @"(?i)^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$";
let Baseline = DeviceProcessEvents
    | where Timestamp between (ago(30d) .. ago(2d))
    | where InitiatingProcessFileName matches regex WebParents
    | distinct DeviceId, InitiatingProcessFileName, FileName;
DeviceProcessEvents
| where Timestamp > ago(2d)
| where InitiatingProcessFileName matches regex WebParents
| join kind=leftanti Baseline on DeviceId, InitiatingProcessFileName, FileName
| summarize Executions = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Commands = make_set(ProcessCommandLine, 10) by DeviceName, InitiatingProcessFileName, FileName
| order by FirstSeen desc
// ===== H7 Persistence by the web account - cron, SSH keys, new users
let lookback = datetime(2026-10-20T00:00:00Z);
let WebUsers = dynamic(["www-data","apache","nginx","http","wwwrun","nobody","daemon"]);
let ProcHits = DeviceProcessEvents
    | where Timestamp >= lookback
    | where AccountName in~ (WebUsers) or InitiatingProcessAccountName in~ (WebUsers)
    | where FileName in~ ("crontab", "useradd", "adduser", "usermod", "passwd", "chpasswd")
        or ProcessCommandLine has_any ("authorized_keys", "/etc/cron", "/var/spool/cron", "/etc/sudoers")
    | project Timestamp, DeviceName, Signal = "process", Account = AccountName, Detail = ProcessCommandLine, Parent = InitiatingProcessFileName;
let FileHits = DeviceFileEvents
    | where Timestamp >= lookback
    | where InitiatingProcessAccountName in~ (WebUsers)
    | where FolderPath has_any ("/.ssh/authorized_keys", "/etc/cron", "/var/spool/cron", "/etc/sudoers", "/etc/systemd/system/")
    | project Timestamp, DeviceName, Signal = "file", Account = InitiatingProcessAccountName, Detail = FolderPath, Parent = InitiatingProcessFileName;
union ProcHits, FileHits
| order by Timestamp desc
// ===== H8 PHP fatal out-of-memory errors in web or PHP logs (Sentinel Syslog; adapt to your log table)
Syslog
| where TimeGenerated >= datetime(2026-10-20T00:00:00Z)
| where SyslogMessage has "PHP Fatal error"
| where SyslogMessage has "tried to allocate" and SyslogMessage has "Unknown on line 0"
| summarize Errors = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Samples = make_set(SyslogMessage, 5) by Computer, ProcessName
| order by Errors desc
// ===== H9 Apache child exits (AH00052) bursts - possible exploit retries (adapt to your log table)
Syslog
| where TimeGenerated >= datetime(2026-10-20T00:00:00Z)
| where SyslogMessage has "AH00052"
| summarize Exits = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Computer, bin(TimeGenerated, 10m)
| where Exits >= 10
| order by Exits desc
```

## CrowdStrike Falcon (CQL)

```
// ===== H1 Where PHP runs - hosts executing PHP workers (pair with Falcon Exposure Management for versions/CVEs)
#event_simpleName=ProcessRollup2
| FileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|lsphp[0-9]*|frankenphp)$/i
| groupBy([ComputerName, event_platform, FileName, ImageFileName], function=[count(as=Executions), max(@timestamp, as=LastSeen)], limit=max)
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen, timezone="UTC")
| sort(Executions, order=desc, limit=1000)
// ===== H1c Windows/IIS hosts running php-cgi.exe below the PHP2Shell fixed builds (version from install path; filter internet-facing hosts with Falcon Exposure Management)
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^php(-cgi)?\.exe$/i
| regex("(?i)\\\\v?(?<Major>\\d+)\\.(?<Minor>\\d+)(?:\\.(?<Patch>\\d+))?\\\\php(-cgi)?\\.exe$", field=ImageFileName, strict=false)
| case {
    Major!=* | Status := "Unknown version - check binary" ;
    test(Major < 8) | Status := "EOL branch" ;
    Major=8 | test(Minor <= 1) | Status := "EOL branch" ;
    Major=8 Minor=2 | Patch!=* | Status := "8.2 - patch unknown" ;
    Major=8 Minor=2 | test(Patch < 35) | Status := "Below 8.2.35" ;
    Major=8 Minor=3 | Patch!=* | Status := "8.3 - patch unknown" ;
    Major=8 Minor=3 | test(Patch < 36) | Status := "Below 8.3.36" ;
    Major=8 Minor=4 | Patch!=* | Status := "8.4 - patch unknown" ;
    Major=8 Minor=4 | test(Patch < 27) | Status := "Below 8.4.27" ;
    Major=8 Minor=5 | Patch!=* | Status := "8.5 - patch unknown" ;
    Major=8 Minor=5 | test(Patch < 12) | Status := "Below 8.5.12" ;
    * | Status := "At or above fixed build" ;
  }
| Status!="At or above fixed build"
| groupBy([ComputerName, ImageFileName, Status], function=[count(as=Executions), min(@timestamp, as=FirstExecution), max(@timestamp, as=LastExecution), collect([ParentBaseFileName], limit=5)], limit=max)
| FirstExecution := formatTime("%Y-%m-%d %H:%M", field=FirstExecution, timezone="UTC")
| LastExecution := formatTime("%Y-%m-%d %H:%M", field=LastExecution, timezone="UTC")
| sort(Executions, order=desc, limit=1000)
// ===== H2 PHP or web worker spawning shells, interpreters or download tools
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$/i
| FileName=/^(sh|bash|dash|zsh|busybox|cmd\.exe|powershell\.exe|pwsh\.exe|python[0-9.]*(\.exe)?|perl|curl(\.exe)?|wget|nc|ncat|socat|certutil\.exe|bitsadmin\.exe)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, ImageFileName, SHA256HashData], limit=1000)
// ===== H3 Reverse-shell and recon command lines from web workers or web accounts
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$/i
    OR UserName=/^(www-data|apache|nginx|http|wwwrun|nobody|daemon|iusr)$/i
| CommandLine=/(\/dev\/(tcp|udp)\/|mkfifo|fsockopen|n(c|cat)\s+.*-e\s|bash\s+-i|sh\s+-i|socat\s+.*exec)/i
    OR FileName=/^(whoami(\.exe)?|id|uname|hostname(\.exe)?|ipconfig\.exe|ifconfig|systeminfo\.exe)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
// ===== H4 PHP or script files written into web roots or temp paths by a PHP or web process
(#event_simpleName=ProcessRollup2 FileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$/i)
  OR (#event_simpleName=/^(WebScriptFileWritten|NewScriptWritten)$/ TargetFileName=/\.(php[0-9]?|phtml|phar)$/i)
| case {
    #event_simpleName=ProcessRollup2 | falconPID := TargetProcessId ;
    * | falconPID := ContextProcessId ;
  }
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=/^(WebScriptFileWritten|NewScriptWritten)$/}])
| groupBy([aid, falconPID], function=[collect([ComputerName, FileName, CommandLine, TargetFileName]), max(@timestamp, as=LastSeen)], limit=max)
| TargetFileName=/(\/var\/www\/|\/srv\/www\/|\/usr\/share\/nginx\/|public_html|wwwroot|\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/i
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen, timezone="UTC")
// ===== H5 Outbound connections from PHP workers to public IPs
(#event_simpleName=ProcessRollup2 FileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|lsphp[0-9]*|frankenphp)$/i)
  OR #event_simpleName=NetworkConnectIP4
| case {
    #event_simpleName=ProcessRollup2 | falconPID := TargetProcessId ;
    #event_simpleName=NetworkConnectIP4 | !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"]) | falconPID := ContextProcessId ;
  }
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=NetworkConnectIP4}])
| groupBy([aid, falconPID], function=[collect([ComputerName, FileName, CommandLine, RemoteAddressIP4, RemotePort]), count(RemoteAddressIP4, distinct=true, as=DistinctPublicIPs), max(@timestamp, as=LastSeen)], limit=max)
| DistinctPublicIPs >= 1
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen, timezone="UTC")
| sort(DistinctPublicIPs, order=asc, limit=1000)
// ===== H6 New web-worker parent to child pairs (first seen in the last 2 days; set the time picker to 30 days)
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$/i
| groupBy([aid, ComputerName, ParentBaseFileName, FileName], function=[count(as=Executions), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen), collect([CommandLine], limit=10)], limit=max)
| test(FirstSeen > (now() - 172800000))
| FirstSeen := formatTime("%Y-%m-%d %H:%M", field=FirstSeen, timezone="UTC")
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen, timezone="UTC")
| sort(Executions, order=asc, limit=1000)
// ===== H7 Persistence by the web account - cron, SSH keys, new users
#event_simpleName=ProcessRollup2
| UserName=/^(www-data|apache|nginx|http|wwwrun|nobody|daemon)$/i
| FileName=/^(crontab|useradd|adduser|usermod|passwd|chpasswd)$/i
    OR CommandLine=/(authorized_keys|\/etc\/cron|\/var\/spool\/cron|\/etc\/sudoers|\/etc\/systemd\/system\/)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
// ===== H8 PHP fatal out-of-memory errors in ingested web/PHP logs (Next-Gen SIEM; set repository/parser for your log source)
"PHP Fatal error" "tried to allocate" "Unknown on line 0"
| groupBy([@host], function=[count(as=Errors), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)], limit=max)
| sort(Errors, order=desc)
// ===== H9 Apache child exits (AH00052) bursts - possible exploit retries
"AH00052"
| bucket(span=10m, field=[@host], function=count(as=Exits))
| Exits >= 10
```

Queries are untested: tune before use.

## Sources

1. Sergio Albea, Detect FYI (21 Oct 2026): <https://detect.fyi/php2shell-two-critical-php-vulnerabilities-cve-2026-109618-and-cve-2026-109619-are-your-3f0a0c08f6ec>
2. Cyb3rMonk KQL hunt: <https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/blob/main/Uncategorized/PHP2Shell.md>
3. Huntress (21 Oct 2026): <https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities>
4. Abstract Security (21 Oct 2026): <https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619>
5. Cybaverse (21 Oct 2026): <https://www.cybaverse.co.uk/en/php2shell-checker>
6. Wiz Research (21 Oct 2026): <https://www.wiz.io/blog/php2shell-php-rce>
7. PHP security release (21 Oct 2026): <https://www.php.net/archive/2026.php#2026-10-21-5>
