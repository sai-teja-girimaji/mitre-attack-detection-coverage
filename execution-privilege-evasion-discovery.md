# Execution

> Detection coverage for MITRE ATT&CK Execution techniques in Microsoft Sentinel

**Tactic ID:** TA0002
**Techniques Documented:** 6
**Covered:** 2 | **Partial:** 2 | **Gap:** 2

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1059 - Command and Scripting | T1059.001 PowerShell | ✅ Covered | DeviceProcessEvents | MDE |
| T1047 - WMI | | ✅ Covered | DeviceProcessEvents | MDE |
| T1059 - Command and Scripting | T1059.003 Windows Command Shell | ⚠️ Partial | DeviceProcessEvents | MDE |
| T1053 - Scheduled Task/Job | T1053.005 Scheduled Task | ⚠️ Partial | SecurityEvent | Windows Security Events |
| T1204 - User Execution | T1204.002 Malicious File | ❌ Gap | DeviceProcessEvents / OfficeActivity | MDE / M365 |
| T1072 - Software Deployment Tools | | ❌ Gap | DeviceProcessEvents | MDE |

---

## Technique Details

### T1059.001 - PowerShell

**Status:** ✅ Covered

**Rule:** [T1059-powershell-encoded-command](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1059-powershell-encoded-command.md)

---

### T1047 - Windows Management Instrumentation

**Status:** ✅ Covered

```kql
// Detect WMI being used for remote execution or persistence
// MITRE ATT&CK: T1047
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where (FileName =~ "wmiprvse.exe" and InitiatingProcessFileName !in ("svchost.exe", "WmiPrvSE.exe"))
    or (FileName in ("wmic.exe") and ProcessCommandLine has_any (
        "process call create", "/node:", "shadowcopy delete", "os get", "/format:list"
    ))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

---

### T1059.003 - Windows Command Shell

**Status:** ⚠️ Partial

```kql
// Detect suspicious cmd.exe usage with common attacker patterns
// MITRE ATT&CK: T1059.003
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_any (
    "/c powershell", "/c wscript", "/c cscript", "/c mshta",
    "/c regsvr32", "/c rundll32", "&&ping", "&&timeout",
    "net user", "net localgroup", "whoami /all"
)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

---

# Privilege Escalation

> Detection coverage for MITRE ATT&CK Privilege Escalation techniques in Microsoft Sentinel

**Tactic ID:** TA0004
**Techniques Documented:** 5
**Covered:** 2 | **Partial:** 1 | **Gap:** 2

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1098 - Account Manipulation | T1098.003 Additional Cloud Roles | ✅ Covered | AuditLogs | Azure AD |
| T1136 - Create Account | T1136.001 Local Account | ✅ Covered | SecurityEvent | Windows Security Events |
| T1078 - Valid Accounts | T1078.004 Cloud Accounts | ⚠️ Partial | SigninLogs / AuditLogs | Azure AD |
| T1134 - Access Token Manipulation | | ❌ Gap | DeviceProcessEvents | MDE |
| T1068 - Exploitation for Privilege Escalation | | ❌ Gap | DeviceProcessEvents | MDE |

---

## Technique Details

### T1134 - Access Token Manipulation

**Status:** ❌ Gap

```kql
// Detect token manipulation via suspicious token-related API usage
// MITRE ATT&CK: T1134
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where ProcessCommandLine has_any (
    "ImpersonateLoggedOnUser", "DuplicateTokenEx",
    "CreateProcessWithTokenW", "AdjustTokenPrivileges"
)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName
| sort by TimeGenerated desc
```

---

# Defense Evasion

> Detection coverage for MITRE ATT&CK Defense Evasion techniques in Microsoft Sentinel

**Tactic ID:** TA0005
**Techniques Documented:** 7
**Covered:** 2 | **Partial:** 2 | **Gap:** 3

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1070 - Indicator Removal | T1070.001 Clear Windows Event Logs | ✅ Covered | SecurityEvent | Windows Security Events |
| T1059 - Command and Scripting | T1059.001 PowerShell Obfuscation | ✅ Covered | DeviceProcessEvents | MDE |
| T1562 - Impair Defenses | T1562.001 Disable Security Tools | ⚠️ Partial | DeviceProcessEvents | MDE |
| T1036 - Masquerading | | ⚠️ Partial | DeviceProcessEvents | MDE |
| T1218 - System Binary Proxy Execution | T1218.011 Rundll32 | ❌ Gap | DeviceProcessEvents | MDE |
| T1055 - Process Injection | | ❌ Gap | DeviceProcessEvents | MDE |
| T1027 - Obfuscated Files | T1027.010 Command Obfuscation | ❌ Gap | DeviceProcessEvents | MDE |

---

## Technique Details

### T1070.001 - Clear Windows Event Logs

**Status:** ✅ Covered

```kql
// Detect Windows event log clearing
// MITRE ATT&CK: T1070.001
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 1102
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName
| extend AlertDetail = strcat("Security event log cleared on ", Computer, " by ", SubjectDomainName, "\\", SubjectUserName)
| sort by TimeGenerated desc
```

Also detect via command line:
```kql
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl ", "clear-log"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has "Clear-EventLog")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, FileName
| sort by TimeGenerated desc
```

---

### T1562.001 - Disable Security Tools

**Status:** ⚠️ Partial

```kql
// Detect attempts to disable Windows Defender or other security tools
// MITRE ATT&CK: T1562.001
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
    "DisableRealtimeMonitoring", "Set-MpPreference", "Add-MpPreference",
    "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableScriptScanning"
))
    or (FileName =~ "sc.exe" and ProcessCommandLine has_any (
    "stop", "delete", "config start= disabled"
) and ProcessCommandLine has_any (
    "WinDefend", "MsMpSvc", "Sense", "WdBoot", "WdFilter"
))
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, FileName
| sort by TimeGenerated desc
```

---

# Discovery

> Detection coverage for MITRE ATT&CK Discovery techniques in Microsoft Sentinel

**Tactic ID:** TA0007
**Techniques Documented:** 7
**Covered:** 1 | **Partial:** 3 | **Gap:** 3

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1087 - Account Discovery | T1087.002 Domain Account | ⚠️ Partial | SecurityEvent | Windows Security Events |
| T1069 - Permission Groups Discovery | T1069.001 Local Groups | ⚠️ Partial | SecurityEvent | Windows Security Events |
| T1046 - Network Service Discovery | | ⚠️ Partial | DeviceNetworkEvents | MDE |
| T1482 - Domain Trust Discovery | | ❌ Gap | SecurityEvent | Windows Security Events |
| T1018 - Remote System Discovery | | ❌ Gap | DeviceProcessEvents | MDE |
| T1135 - Network Share Discovery | | ❌ Gap | SecurityEvent | Windows Security Events |
| T1083 - File and Directory Discovery | | ✅ Covered | DeviceProcessEvents | MDE |

---

## Technique Details

### T1083 - File and Directory Discovery

**Status:** ✅ Covered (Detection query)

```kql
// Detect bulk file and directory enumeration
// MITRE ATT&CK: T1083
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where (FileName =~ "cmd.exe" and ProcessCommandLine has_any ("dir /s", "dir /a", "dir /b /s"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
        "Get-ChildItem", "ls -r", "dir -Recurse", "gci -r"
    ) and ProcessCommandLine has_any ("C:\\", "D:\\", "\\\\"))
    or (FileName =~ "tree.exe")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName
| sort by TimeGenerated desc
```

---

### T1046 - Network Service Discovery

**Status:** ⚠️ Partial

```kql
// Detect network port scanning from internal hosts
// MITRE ATT&CK: T1046
DeviceNetworkEvents
| where TimeGenerated >= ago(30m)
| where ActionType == "ConnectionAttempted"
| where RemotePort in (22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5985, 8080, 8443)
| summarize 
    UniqueRemoteHosts = dcount(RemoteIP),
    UniqueRemotePorts = dcount(RemotePort),
    Ports = make_set(RemotePort),
    TargetHosts = make_set(RemoteIP, 10)
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 10m)
| where UniqueRemoteHosts >= 10 or UniqueRemotePorts >= 5
| project TimeGenerated, DeviceName, InitiatingProcessFileName, UniqueRemoteHosts, UniqueRemotePorts, Ports, TargetHosts
| sort by UniqueRemoteHosts desc
```
