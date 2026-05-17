# Command and Control

> Detection coverage for MITRE ATT&CK Command and Control techniques in Microsoft Sentinel

**Tactic ID:** TA0011
**Techniques Documented:** 6
**Covered:** 2 | **Partial:** 2 | **Gap:** 2

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1071 - Application Layer Protocol | T1071.004 DNS | ✅ Covered | DnsEvents | DNS Analytics |
| T1219 - Remote Access Software | | ✅ Covered | DeviceProcessEvents / DeviceNetworkEvents | MDE |
| T1071 - Application Layer Protocol | T1071.001 Web Protocols | ⚠️ Partial | DeviceNetworkEvents / CommonSecurityLog | MDE / CEF |
| T1105 - Ingress Tool Transfer | | ⚠️ Partial | DeviceNetworkEvents / DeviceProcessEvents | MDE |
| T1572 - Protocol Tunneling | | ❌ Gap | DeviceNetworkEvents | MDE |
| T1090 - Proxy | T1090.002 External Proxy | ❌ Gap | DeviceNetworkEvents / CommonSecurityLog | MDE / CEF |

See [c2-collection-exfiltration-impact.md](./c2-collection-exfiltration-impact.md) for full detection queries.
