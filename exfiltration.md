# Exfiltration

> Detection coverage for MITRE ATT&CK Exfiltration techniques in Microsoft Sentinel

**Tactic ID:** TA0010
**Techniques Documented:** 5
**Covered:** 1 | **Partial:** 2 | **Gap:** 2

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1048 - Exfiltration Over Alt Protocol | T1048 via DNS | ✅ Covered | DnsEvents | DNS Analytics |
| T1567 - Exfiltration Over Web Service | T1567.002 Cloud Storage | ⚠️ Partial | DeviceNetworkEvents | MDE |
| T1020 - Automated Exfiltration | | ⚠️ Partial | DeviceNetworkEvents / CommonSecurityLog | MDE / CEF |
| T1041 - Exfiltration Over C2 Channel | | ❌ Gap | DeviceNetworkEvents | MDE |
| T1030 - Data Transfer Size Limits | | ❌ Gap | CommonSecurityLog | CEF (DLP/proxy) |

See [c2-collection-exfiltration-impact.md](./c2-collection-exfiltration-impact.md) for full detection queries.
