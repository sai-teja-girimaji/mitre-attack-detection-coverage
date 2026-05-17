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

See [execution-privilege-evasion-discovery.md](./execution-privilege-evasion-discovery.md) for full detection queries.
