# Impact

> Detection coverage for MITRE ATT&CK Impact techniques in Microsoft Sentinel

**Tactic ID:** TA0040
**Techniques Documented:** 7
**Covered:** 4 | **Partial:** 1 | **Gap:** 2

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1485 - Data Destruction | | ✅ Covered | DeviceFileEvents | MDE |
| T1578 - Modify Cloud Compute | T1578.003 Delete Cloud Instance | ✅ Covered | AzureActivity | Azure Activity |
| T1490 - Inhibit System Recovery | | ✅ Covered | DeviceProcessEvents | MDE |
| T1486 - Data Encrypted for Impact | | ✅ Covered | DeviceFileEvents | MDE |
| T1489 - Service Stop | | ⚠️ Partial | SecurityEvent / DeviceProcessEvents | Windows Security Events / MDE |
| T1499 - Endpoint Denial of Service | | ❌ Gap | DeviceNetworkEvents | MDE |
| T1491 - Defacement | T1491.002 External Defacement | ❌ Gap | CommonSecurityLog / AppServiceHTTPLogs | CEF / Azure Diagnostics |

See [c2-collection-exfiltration-impact.md](./c2-collection-exfiltration-impact.md) for full detection queries.
