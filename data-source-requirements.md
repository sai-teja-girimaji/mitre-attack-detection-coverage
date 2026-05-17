# Data Source Requirements

> Connector and audit policy reference for all Sentinel data sources used in this coverage matrix

---

## Connector Reference

| Sentinel Table | Connector | License Required | Cost | Default Enabled |
|---|---|---|---|---|
| SecurityEvent | Windows Security Events via AMA or MMA | None | Log Analytics ingestion | No, requires agent |
| SigninLogs | Azure Active Directory | Azure AD P1 or P2 | Included with P1/P2 | No |
| AuditLogs | Azure Active Directory | Azure AD P1 or P2 | Included with P1/P2 | No |
| AzureActivity | Azure Activity | None | Free (first 5GB/day) | No, manual setup |
| DeviceProcessEvents | Microsoft Defender for Endpoint | MDE Plan 1 or 2 | MDE license | No |
| DeviceFileEvents | Microsoft Defender for Endpoint | MDE Plan 1 or 2 | MDE license | No |
| DeviceNetworkEvents | Microsoft Defender for Endpoint | MDE Plan 1 or 2 | MDE license | No |
| DeviceRegistryEvents | Microsoft Defender for Endpoint | MDE Plan 1 or 2 | MDE license | No |
| DeviceLogonEvents | Microsoft Defender for Endpoint | MDE Plan 1 or 2 | MDE license | No |
| OfficeActivity | Microsoft 365 | Microsoft 365 license | Included with M365 | No |
| CommonSecurityLog | CEF / Syslog (firewall, proxy, WAF) | None | Log Analytics ingestion | No, requires configuration |
| DnsEvents | DNS Analytics solution | None | Log Analytics ingestion | No, requires Windows DNS debug logging |
| ThreatIntelligenceIndicator | Threat Intelligence | None | Free connector | No |
| BehaviorAnalytics | UEBA | Microsoft Sentinel | Sentinel license | No, requires enablement |

---

## Windows Audit Policy Requirements

Many SecurityEvent detections require specific audit policies to be enabled. Default Windows audit settings do not capture all required events.

| Event ID | Description | Audit Policy Required |
|---|---|---|
| 4624 | Successful logon | Audit Logon Events: Success |
| 4625 | Failed logon | Audit Logon Events: Failure |
| 4648 | Logon with explicit credentials | Audit Logon Events: Success |
| 4688 | Process creation | Audit Process Creation: Success |
| 4697 | Service installed | Audit Security System Extension: Success |
| 4698 | Scheduled task created | Audit Other Object Access Events: Success |
| 4720 | User account created | Audit User Account Management: Success |
| 4732 | Member added to local group | Audit Security Group Management: Success |
| 4769 | Kerberos service ticket requested | Audit Kerberos Service Ticket Operations: Success and Failure |
| 1102 | Audit log cleared | Audit System Events: Success |
| 5140 | Network share accessed | Audit File Share: Success |
| 5145 | Network share object access check | Audit Detailed File Share: Success and Failure |

**Command line logging:** Event 4688 only captures the command line in the `ProcessCommandLine` field if **Include command line in process creation events** is enabled via Group Policy:

`Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events`

---

## Connector Priority Order

If you are building out your Sentinel connector coverage from scratch, prioritize in this order based on detection value per connector:

| Priority | Connector | Reason |
|---|---|---|
| 1 | Azure Active Directory (SigninLogs + AuditLogs) | Covers identity-based attacks which are the most common initial access vector |
| 2 | Microsoft Defender for Endpoint | Covers process, file, network, and registry events for endpoint detection |
| 3 | Azure Activity | Free connector, covers cloud infrastructure attacks |
| 4 | Windows Security Events | Covers on-premises Windows events, required for domain controller monitoring |
| 5 | Microsoft 365 (OfficeActivity) | Covers email-based attacks and collaboration platform abuse |
| 6 | CEF / Syslog (CommonSecurityLog) | Covers network perimeter devices, firewalls, proxies, WAF |
| 7 | DNS Analytics (DnsEvents) | Covers DNS tunneling and C2 communication via DNS |
| 8 | Threat Intelligence | Enriches other detections with IOC correlation |
| 9 | UEBA (BehaviorAnalytics) | Covers anomalous behavior patterns requiring a behavioral baseline |
