# Discovery

> Detection coverage for MITRE ATT&CK Discovery techniques in Microsoft Sentinel

**Tactic ID:** TA0007
**Techniques Documented:** 7
**Covered:** 1 | **Partial:** 3 | **Gap:** 3

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1083 - File and Directory Discovery | | ✅ Covered | DeviceProcessEvents | MDE |
| T1087 - Account Discovery | T1087.002 Domain Account | ⚠️ Partial | SecurityEvent | Windows Security Events |
| T1069 - Permission Groups Discovery | T1069.001 Local Groups | ⚠️ Partial | SecurityEvent | Windows Security Events |
| T1046 - Network Service Discovery | | ⚠️ Partial | DeviceNetworkEvents | MDE |
| T1482 - Domain Trust Discovery | | ❌ Gap | SecurityEvent | Windows Security Events |
| T1018 - Remote System Discovery | | ❌ Gap | DeviceProcessEvents | MDE |
| T1135 - Network Share Discovery | | ❌ Gap | SecurityEvent | Windows Security Events |

See [execution-privilege-evasion-discovery.md](./execution-privilege-evasion-discovery.md) for full detection queries.
