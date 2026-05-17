# Persistence

> Detection coverage for MITRE ATT&CK Persistence techniques in Microsoft Sentinel

**Tactic ID:** TA0003
**Techniques Documented:** 7
**Covered:** 3 | **Partial:** 2 | **Gap:** 2

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1136 - Create Account | T1136.001 Local Account | ✅ Covered | SecurityEvent | Windows Security Events |
| T1098 - Account Manipulation | T1098.003 Additional Cloud Roles | ✅ Covered | AuditLogs | Azure AD |
| T1543 - Create/Modify System Process | T1543.003 Windows Service | ✅ Covered | SecurityEvent | Windows Security Events |
| T1053 - Scheduled Task/Job | T1053.005 Scheduled Task | ⚠️ Partial | SecurityEvent | Windows Security Events |
| T1547 - Boot/Logon Autostart Execution | T1547.001 Registry Run Keys | ⚠️ Partial | DeviceRegistryEvents | MDE |
| T1136 - Create Account | T1136.003 Cloud Account | ❌ Gap | AuditLogs | Azure AD |
| T1078 - Valid Accounts | T1078.004 Cloud Account Backdoor | ❌ Gap | AuditLogs / SigninLogs | Azure AD |

---

## Technique Details

### T1136.001 - Create Local Account

**Status:** ✅ Covered

**Rule:** [T1136-new-local-admin-creation](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1136-new-local-admin-creation.md)

---

### T1098.003 - Additional Cloud Roles

**Status:** ✅ Covered

**Rule:** [T1098-privileged-role-assignment](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1098-privileged-role-assignment.md)

---

### T1543.003 - Windows Service

**Status:** ✅ Covered

**What it detects:** Malicious services installed for persistence, including PsExec service installation which doubles as a lateral movement indicator.

**Event ID:** 4697 (A service was installed in the system)

```kql
// Detect suspicious new service installations
// MITRE ATT&CK: T1543.003
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4697
| where ServiceFileName has_any (
    "\\Temp\\", "\\AppData\\", "\\Users\\Public\\",
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32"
)
| project TimeGenerated, Computer, ServiceName, ServiceFileName, SubjectUserName, SubjectDomainName
| sort by TimeGenerated desc
```

---

### T1053.005 - Scheduled Task

**Status:** ⚠️ Partial

**Event ID:** 4698 (A scheduled task was created)
**Required audit policy:** Audit Other Object Access Events: Success

```kql
// Detect scheduled task creation with suspicious execution paths
// MITRE ATT&CK: T1053.005
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4698
| extend TaskContent = tostring(EventData)
| where TaskContent has_any (
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "\\Temp\\",
    "\\AppData\\", "\\Users\\Public\\"
)
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, TaskContent
| sort by TimeGenerated desc
```

**Why partial:** The TaskXml field in Event 4698 contains the full task definition but may require parsing depending on your connector configuration. Validate that the EventData field is populating correctly in your environment.

---

### T1547.001 - Registry Run Keys

**Status:** ⚠️ Partial

```kql
// Detect modifications to common persistence registry run keys
// MITRE ATT&CK: T1547.001
DeviceRegistryEvents
| where TimeGenerated >= ago(1h)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "SYSTEM\\CurrentControlSet\\Services"
)
| where InitiatingProcessFileName !in (
    "regedit.exe", "msiexec.exe", "setup.exe", "install.exe",
    "MicrosoftEdgeUpdate.exe", "GoogleUpdate.exe"
)
| project TimeGenerated, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| sort by TimeGenerated desc
```

---

### T1136.003 - Create Cloud Account

**Status:** ❌ Gap

```kql
// Detect new Azure AD user account creation
// MITRE ATT&CK: T1136.003
AuditLogs
| where TimeGenerated >= ago(1h)
| where OperationName =~ "Add user"
| where Result =~ "success"
| extend 
    NewUser = tostring(TargetResources[0].displayName),
    NewUserUPN = tostring(TargetResources[0].userPrincipalName),
    CreatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, NewUser, NewUserUPN, CreatedBy
| sort by TimeGenerated desc
```
