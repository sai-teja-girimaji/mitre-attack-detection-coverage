# Credential Access

> Detection coverage for MITRE ATT&CK Credential Access techniques in Microsoft Sentinel

**Tactic ID:** TA0006
**Techniques Documented:** 7
**Covered:** 4 | **Partial:** 2 | **Gap:** 1

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1110 - Brute Force | T1110.001/003/004 | ✅ Covered | SigninLogs | Azure AD |
| T1621 - MFA Request Generation | | ✅ Covered | SigninLogs | Azure AD |
| T1558 - Steal/Forge Kerberos Tickets | T1558.003 Kerberoasting | ✅ Covered | SecurityEvent | Windows Security Events |
| T1003 - OS Credential Dumping | T1003.001 LSASS Memory | ✅ Covered | DeviceProcessEvents | MDE |
| T1539 - Steal Web Session Cookie | | ⚠️ Partial | SigninLogs / BehaviorAnalytics | Azure AD / UEBA |
| T1552 - Unsecured Credentials | T1552.001 Credentials in Files | ⚠️ Partial | DeviceFileEvents / DeviceProcessEvents | MDE |
| T1555 - Credentials from Password Stores | | ❌ Gap | DeviceProcessEvents | MDE |

---

## Technique Details

### T1110 - Brute Force

**Status:** ✅ Covered

**What it detects:** High-volume failed authentication attempts against Azure AD accounts, including password spraying, credential stuffing, and traditional brute force.

**Rule:** [T1110-brute-force-signin](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1110-brute-force-signin.md)

**Sub-technique coverage:**
- T1110.001 Password Guessing: Covered (single user, multiple failures)
- T1110.003 Password Spraying: Covered with modification - replace the per-user grouping with a per-password grouping to detect one password attempted across many users
- T1110.004 Credential Stuffing: Covered (high failure count from multiple IPs)
- T1110.002 Password Cracking: Not covered (offline attack, no log source)

**Password spray variant:**
```kql
// Detect password spray: single password attempted against many accounts
let SprayThreshold = 15;
SigninLogs
| where TimeGenerated >= ago(1h)
| where ResultType != "0"
| where isnotempty(ClientAppUsed)
| summarize 
    UniqueUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 10),
    IPAddresses = make_set(IPAddress)
    by bin(TimeGenerated, 30m)
| where UniqueUsers >= SprayThreshold
| project TimeGenerated, UniqueUsers, UserList, IPAddresses
| sort by UniqueUsers desc
```

---

### T1621 - Multi-Factor Authentication Request Generation

**Status:** ✅ Covered

**What it detects:** Repeated MFA push notification requests sent to a user to induce approval through fatigue.

**Rule:** [T1621-mfa-fatigue](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1621-mfa-fatigue.md)

---

### T1558.003 - Kerberoasting

**Status:** ✅ Covered

**What it detects:** Attackers requesting Kerberos service tickets for service accounts and extracting them for offline password cracking. Kerberoasting requests use RC4 encryption (encryption type 0x17) which is weaker than AES and therefore suspicious when used for service ticket requests.

**Sentinel table:** SecurityEvent
**Event ID:** 4769 (Kerberos service ticket was requested)
**Required audit policy:** Audit Kerberos Service Ticket Operations: Success and Failure

```kql
// Detects Kerberoasting via RC4 encryption in Kerberos service ticket requests
// MITRE ATT&CK: T1558.003
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| where ServiceName != "krbtgt"
| summarize 
    RequestCount = count(),
    TargetServices = make_set(ServiceName),
    SourceIPs = make_set(IpAddress)
    by SubjectUserName, SubjectDomainName, bin(TimeGenerated, 10m)
| where RequestCount >= 3
| project TimeGenerated, SubjectUserName, SubjectDomainName, RequestCount, TargetServices, SourceIPs
| sort by RequestCount desc
```

**Tuning:** A single RC4 ticket request may be legitimate for older services that do not support AES. Three or more in a short window from the same source is a strong indicator of Kerberoasting.

---

### T1003.001 - LSASS Memory Credential Dumping

**Status:** ✅ Covered

**What it detects:** Attackers accessing the LSASS process memory to extract credential hashes, typically using tools like Mimikatz, ProcDump, or comsvcs.dll.

**Sentinel table:** DeviceProcessEvents
**Connector required:** Microsoft Defender for Endpoint

```kql
// Detects common LSASS credential dumping techniques
// MITRE ATT&CK: T1003.001
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where (FileName =~ "procdump.exe" and ProcessCommandLine has "lsass")
    or (FileName =~ "comsvcs.dll" and ProcessCommandLine has "MiniDump")
    or (FileName =~ "taskmgr.exe" and ProcessCommandLine has "lsass")
    or (ProcessCommandLine has_all ("sekurlsa", "logonpasswords"))
    or (ProcessCommandLine has_all ("lsass", "minidump"))
| project 
    TimeGenerated, 
    DeviceName, 
    AccountName, 
    FileName, 
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by TimeGenerated desc
```

**Note:** MDE also provides native alerts for LSASS access attempts. This rule supplements those alerts with explicit process command line detection.

---

### T1539 - Steal Web Session Cookie

**Status:** ⚠️ Partial

**What it detects:** Attackers stealing authenticated session cookies to bypass MFA and gain access to cloud services without needing credentials or completing an MFA challenge (adversary-in-the-middle phishing or post-compromise cookie theft).

**Why partial:** Direct detection of cookie theft is not possible from Azure AD logs alone. However, the downstream effect is detectable: a sign-in that bypasses Conditional Access MFA requirements or shows anomalous device or session properties following a prior successful MFA.

**Partial detection:** Detect sign-ins with unusual token issuance or where Conditional Access MFA was satisfied but no MFA event was recorded in SigninLogs (indicates token replay).

```kql
// Detect sign-ins where MFA was not required but the account has MFA registered
// This may indicate session cookie or token replay
SigninLogs
| where TimeGenerated >= ago(1h)
| where ResultType == "0"
| where AuthenticationRequirement == "singleFactorAuthentication"
| where MfaDetail.authMethod == ""
| where ConditionalAccessStatus == "success"
| where UserType != "Guest"
| project 
    TimeGenerated, 
    UserPrincipalName, 
    AppDisplayName, 
    IPAddress, 
    Location,
    DeviceDetail,
    AuthenticationRequirement
| sort by TimeGenerated desc
```

**Gap to close:** Deploy Microsoft Entra ID Protection to detect token replay and anomalous session signals. Enforce Conditional Access policies that require compliant devices to reduce the impact of cookie theft.

---

### T1552.001 - Credentials in Files

**Status:** ⚠️ Partial

**What it detects:** Attackers searching for plaintext credentials stored in files, scripts, configuration files, or documents on compromised endpoints.

**Why partial:** Detection requires monitoring file access patterns and process command lines for credential-seeking behavior. MDE telemetry provides partial coverage through process events.

```kql
// Detect processes searching for credential files or patterns
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where ProcessCommandLine has_any (
    "password", "passwd", "credentials", "secret", ".env",
    "web.config", "appsettings", "connectionstring"
)
| where ProcessCommandLine has_any (
    "findstr", "grep", "type", "cat", "Get-Content", "Select-String"
)
| where FileName !in ("MpCmdRun.exe", "SearchProtocolHost.exe")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName
| sort by TimeGenerated desc
```

---

### T1555 - Credentials from Password Stores

**Status:** ❌ Gap

**What it detects:** Attackers extracting credentials from browser password stores, Windows Credential Manager, or third-party password managers.

**Gap to close:** Detection requires monitoring specific process access patterns to credential store file paths and registry locations. MDE DeviceProcessEvents and DeviceFileEvents can cover this, but dedicated rules for each credential store are needed.

```kql
// Detect access to browser credential database files (Chrome, Edge, Firefox)
DeviceFileEvents
| where TimeGenerated >= ago(1h)
| where FolderPath has_any (
    "\\Google\\Chrome\\User Data\\Default\\Login Data",
    "\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    "\\Mozilla\\Firefox\\Profiles"
)
| where ActionType in ("FileAccessed", "FileRead")
| where InitiatingProcessFileName !in ("chrome.exe", "msedge.exe", "firefox.exe")
| project TimeGenerated, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName
| sort by TimeGenerated desc
```
