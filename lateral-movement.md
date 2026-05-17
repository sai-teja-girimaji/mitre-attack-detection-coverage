# Lateral Movement

> Detection coverage for MITRE ATT&CK Lateral Movement techniques in Microsoft Sentinel

**Tactic ID:** TA0008
**Techniques Documented:** 6
**Covered:** 3 | **Partial:** 2 | **Gap:** 1

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1570 - Lateral Tool Transfer | PsExec | ✅ Covered | SecurityEvent | Windows Security Events |
| T1021 - Remote Services | T1021.001 RDP | ✅ Covered | SecurityEvent | Windows Security Events |
| T1021 - Remote Services | T1021.002 SMB/Admin Shares | ✅ Covered | SecurityEvent | Windows Security Events |
| T1550 - Use Alternate Authentication | T1550.002 Pass the Hash | ⚠️ Partial | SecurityEvent | Windows Security Events |
| T1021 - Remote Services | T1021.006 WinRM | ⚠️ Partial | SecurityEvent / DeviceProcessEvents | Windows Security Events / MDE |
| T1091 - Removable Media | | 🔴 No Source | DeviceEvents | MDE (requires specific config) |

---

## Technique Details

### T1570 - Lateral Tool Transfer (PsExec)

**Status:** ✅ Covered

**Rule:** [T1570-psexec-lateral-movement](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1570-psexec-lateral-movement.md)

---

### T1021.001 - Remote Desktop Protocol

**Status:** ✅ Covered

**What it detects:** Lateral movement using RDP (LogonType 10) from one internal host to another, or from an unexpected external source.

**Event ID:** 4624 with LogonType 10 (RemoteInteractive)

```kql
// Detect RDP lateral movement between internal hosts
// MITRE ATT&CK: T1021.001
let InternalRanges = dynamic(["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."]);
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4624
| where LogonType == 10
| where isnotempty(IpAddress) and IpAddress != "-" and IpAddress != "::1"
| extend IsInternal = iif(
    IpAddress startswith "10." 
    or IpAddress startswith "192.168."
    or IpAddress startswith "172.", true, false
)
| where IsInternal == true
| summarize 
    SessionCount = count(),
    TargetComputers = make_set(Computer),
    SourceIPs = make_set(IpAddress)
    by Account, bin(TimeGenerated, 1h)
| where array_length(TargetComputers) >= 3
| project TimeGenerated, Account, SessionCount, TargetComputers, SourceIPs
| sort by array_length(TargetComputers) desc
```

**Tuning:** Alert when a single account establishes RDP sessions to 3 or more distinct hosts within an hour, which is inconsistent with normal user behavior.

---

### T1021.002 - SMB/Windows Admin Shares

**Status:** ✅ Covered

**What it detects:** Lateral movement using SMB administrative shares (C$, ADMIN$, IPC$) accessed from internal hosts.

**Event IDs:** 5140 (network share accessed), 4624 LogonType 3

```kql
// Detect access to admin shares indicating potential lateral movement
// MITRE ATT&CK: T1021.002
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 5140
| where ShareName has_any ("\\\\*\\C$", "\\\\*\\ADMIN$", "\\\\*\\IPC$")
| where SubjectUserName !endswith "$"
| summarize 
    AccessCount = count(),
    TargetShares = make_set(ShareName),
    TargetHosts = make_set(Computer)
    by SubjectUserName, SubjectDomainName, IpAddress, bin(TimeGenerated, 30m)
| where AccessCount >= 3 or array_length(TargetHosts) >= 2
| project TimeGenerated, SubjectUserName, SubjectDomainName, IpAddress, AccessCount, TargetShares, TargetHosts
| sort by AccessCount desc
```

**Required audit policy:** Audit File Share: Success

---

### T1550.002 - Pass the Hash

**Status:** ⚠️ Partial

**What it detects:** Attackers authenticating using NTLM hashes instead of plaintext passwords, allowing lateral movement without knowing the actual password.

**Why partial:** Pass the Hash leaves a specific footprint: a LogonType 3 (Network) authentication using NtLmSsp where the account name does not match the workstation name, and the authentication package is NTLM rather than Kerberos.

```kql
// Detect potential Pass the Hash via NTLM network logons
// MITRE ATT&CK: T1550.002
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where LogonProcessName == "NtLmSsp"
| where SubjectUserName != "-"
| where WorkstationName != Computer
| where SubjectUserName !endswith "$"
| project 
    TimeGenerated, 
    Computer, 
    SubjectUserName, 
    SubjectDomainName, 
    IpAddress, 
    WorkstationName,
    AuthenticationPackageName
| sort by TimeGenerated desc
```

**Why partial:** Not all NTLM network logons indicate Pass the Hash. Legacy applications and older infrastructure legitimately use NTLM. This rule generates a signal for investigation rather than a high-confidence alert. Enrich with UEBA (BehaviorAnalytics) to increase confidence.

---

### T1021.006 - Windows Remote Management (WinRM)

**Status:** ⚠️ Partial

**What it detects:** Lateral movement using WinRM (PowerShell Remoting, Enter-PSSession, Invoke-Command) which uses port 5985 or 5986.

```kql
// Detect WinRM usage for lateral movement via process events
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where (FileName =~ "wsmprovhost.exe" and InitiatingProcessFileName =~ "svchost.exe")
    or (ProcessCommandLine has_any ("Enter-PSSession", "Invoke-Command", "New-PSSession") 
        and ProcessCommandLine has_any ("-ComputerName", "-cn"))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```
