# Collection

> Detection coverage for MITRE ATT&CK Collection techniques in Microsoft Sentinel

**Tactic ID:** TA0009
**Techniques Documented:** 5
**Covered:** 1 | **Partial:** 2 | **Gap:** 2

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1074 - Data Staged | T1074.001 Local Data Staging | ✅ Covered | DeviceFileEvents | MDE |
| T1005 - Data from Local System | | ⚠️ Partial | DeviceFileEvents | MDE |
| T1530 - Data from Cloud Storage | | ⚠️ Partial | AzureActivity / StorageBlobLogs | Azure Activity / Storage diagnostics |
| T1114 - Email Collection | T1114.002 Remote Email Collection | ❌ Gap | OfficeActivity | Microsoft 365 |
| T1056 - Input Capture | T1056.001 Keylogging | ❌ Gap | DeviceProcessEvents | MDE |

See [c2-collection-exfiltration-impact.md](./c2-collection-exfiltration-impact.md) for full detection queries.
