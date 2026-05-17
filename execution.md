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

See [execution-privilege-evasion-discovery.md](./execution-privilege-evasion-discovery.md) for full detection queries.
