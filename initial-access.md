# Initial Access

> Detection coverage for MITRE ATT&CK Initial Access techniques in Microsoft Sentinel

**Tactic ID:** TA0001
**Techniques Documented:** 6
**Covered:** 2 | **Partial:** 2 | **Gap:** 2

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1078 - Valid Accounts | T1078.004 Cloud Accounts | ✅ Covered | SigninLogs | Azure AD |
| T1566 - Phishing | T1566.001 Spearphishing Attachment | ⚠️ Partial | OfficeActivity / EmailEvents | Microsoft 365 / MDO |
| T1566 - Phishing | T1566.002 Spearphishing Link | ⚠️ Partial | OfficeActivity / EmailEvents | Microsoft 365 / MDO |
| T1133 - External Remote Services | | ❌ Gap | SigninLogs / CommonSecurityLog | Azure AD / CEF |
| T1190 - Exploit Public-Facing Application | | ❌ Gap | CommonSecurityLog / AzureActivity | CEF (WAF/IPS) |
| T1199 - Trusted Relationship | | 🔴 No Source | AuditLogs / AzureActivity | Requires CASB or enrichment |

---

## Technique Details

### T1078 - Valid Accounts (T1078.004 Cloud Accounts)

**Status:** ✅ Covered

**What it detects:** Attackers using compromised or stolen Azure AD credentials to authenticate to cloud services, SaaS applications, or Azure resources.

**Detection approach:** Two rules cover this technique:
- Impossible travel detection (sign-ins from geographically separated locations within a short window)
- Brute force sign-in detection (high volume of failed attempts)

**Rules:** [T1078-impossible-travel](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1078-impossible-travel.md) | [T1110-brute-force-signin](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1110-brute-force-signin.md)

**Gap for other sub-techniques:** T1078.001 (Default Accounts) and T1078.002 (Domain Accounts) require SecurityEvent-based logon monitoring, which is documented in the Credential Access and Lateral Movement sections.

---

### T1566 - Phishing (T1566.001 and T1566.002)

**Status:** ⚠️ Partial

**What it detects:** Malicious email attachments or links delivered to users through organizational email systems.

**Detection approach:** Microsoft 365 and Microsoft Defender for Office 365 (MDO) generate events in OfficeActivity and EmailEvents when emails are delivered, clicked, or blocked. Detection at the email delivery layer is available with the Microsoft 365 connector.

**Sentinel tables:**
- `OfficeActivity` - records email delivery, clicks, and sharing events
- `EmailEvents` (via MDO advanced hunting connector) - records email metadata, delivery verdicts, and URL click events

**Why it is partial:** Email delivery detection is available. Detecting successful phishing (user clicked a malicious link, credential entered on a phishing page) requires correlating email events with subsequent sign-in anomalies. This correlation layer is not covered by a single rule in this repository.

**Gap to close:** Deploy Microsoft Defender for Office 365 Plan 2. Enable the MDO advanced hunting connector. Write a correlation rule that joins EmailUrlInfo and SigninLogs to detect users who clicked a flagged URL and subsequently signed in from an unusual location.

```kql
// Partial detection: malicious URLs clicked via email
EmailUrlInfo
| where TimeGenerated >= ago(1h)
| where UrlVerdict has_any ("Malicious", "Phish", "Spam")
| join kind=inner (
    EmailEvents
    | where DeliveryAction != "Blocked"
    | project NetworkMessageId, RecipientEmailAddress
) on NetworkMessageId
| project TimeGenerated, RecipientEmailAddress, Url, UrlVerdict
```

---

### T1133 - External Remote Services

**Status:** ❌ Gap

**What it detects:** Attackers using exposed remote services (VPN, RDP, Citrix, SSH, web application portals) as initial access vectors with valid credentials.

**Detection approach:** Detection depends on the specific service:
- Azure AD Application Proxy or VPN with Azure AD authentication: SigninLogs captures these logons. Apply the same impossible travel and brute force logic.
- RDP exposed directly: SecurityEvent Event ID 4624 with LogonType 10 (RemoteInteractive) from external IPs.
- Third-party VPN or remote access gateway: CommonSecurityLog via CEF connector.

**Gap to close:**

For Azure AD-integrated remote access, the existing SigninLogs rules provide partial coverage. For non-Azure AD integrated services, add the CEF connector for your VPN or remote access appliance and write rules filtering on authentication failures and successes from external IP ranges.

```kql
// Detect RDP logons from external (non-RFC1918) IP addresses
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4624
| where LogonType == 10
| where IpAddress !startswith "10."
    and IpAddress !startswith "192.168."
    and IpAddress !startswith "172."
    and IpAddress != "-"
    and IpAddress != "::1"
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| sort by TimeGenerated desc
```

---

### T1190 - Exploit Public-Facing Application

**Status:** ❌ Gap

**What it detects:** Attackers exploiting vulnerabilities in internet-facing applications (web servers, VPN appliances, API gateways, management interfaces).

**Detection approach:** Detection requires logs from the application layer or a WAF/IPS positioned in front of the application. No native Sentinel table captures this without a network security device connector.

**Gap to close:** Connect your WAF, IPS, or API gateway logs via CEF to the CommonSecurityLog table. The relevant fields are `RequestURL`, `SourceIP`, and `Activity` (blocked/allowed). Alert on high volumes of 4xx/5xx errors from a single source, SQL injection or XSS patterns in request URIs, and scanner signatures.

```kql
// Detect potential exploitation attempts via WAF (CommonSecurityLog)
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where DeviceVendor in ("F5", "Palo Alto Networks", "Fortinet", "Cloudflare", "Akamai")
| where Activity has_any ("SQL Injection", "XSS", "Directory Traversal", "Command Injection", "OWASP")
| summarize 
    HitCount = count(),
    URIs = make_set(RequestURL, 5),
    Actions = make_set(DeviceAction)
    by SourceIP, DestinationHostName, bin(TimeGenerated, 10m)
| where HitCount >= 5
| sort by HitCount desc
```

---

### T1199 - Trusted Relationship

**Status:** 🔴 No Source

**What it detects:** Attackers compromising a trusted third party (MSP, IT vendor, contractor) and using that trust to access the target organization's environment.

**Why no source:** Detection requires correlating sign-in activity from service provider tenants and comparing it against approved maintenance windows and authorized activities. This typically requires a CASB solution or custom enrichment logic that cross-references sign-in data with a maintained list of authorized third-party access.

**Partial mitigation:** Monitor AuditLogs for external user access and guest account activity. Alert on external users accessing sensitive resources outside of defined maintenance windows.

```kql
// Detect external guest user sign-ins to sensitive applications
SigninLogs
| where TimeGenerated >= ago(1h)
| where UserType == "Guest"
| where AppDisplayName has_any ("Azure Portal", "Microsoft Azure Management", "Intune")
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location
| sort by TimeGenerated desc
```
