# Defense Evasion

> Detection coverage for MITRE ATT&CK Defense Evasion techniques in Microsoft Sentinel

**Tactic ID:** TA0005
**Techniques Documented:** 7
**Covered:** 2 | **Partial:** 2 | **Gap:** 3

---

## Coverage Table

| Technique | Sub-Technique | Status | Sentinel Table | Connector Required |
|---|---|---|---|---|
| T1070 - Indicator Removal | T1070.001 Clear Windows Event Logs | ✅ Covered | SecurityEvent | Windows Security Events |
| T1059 - Command and Scripting | T1059.001 PowerShell Obfuscation | ✅ Covered | DeviceProcessEvents | MDE |
| T1562 - Impair Defenses | T1562.001 Disable Security Tools | ⚠️ Partial | DeviceProcessEvents | MDE |
| T1036 - Masquerading | | ⚠️ Partial | DeviceProcessEvents | MDE |
| T1218 - System Binary Proxy Execution | T1218.011 Rundll32 | ❌ Gap | DeviceProcessEvents | MDE |
| T1055 - Process Injection | | ❌ Gap | DeviceProcessEvents | MDE |
| T1027 - Obfuscated Files | T1027.010 Command Obfuscation | ❌ Gap | DeviceProcessEvents | MDE |

See [execution-privilege-evasion-discovery.md](./execution-privilege-evasion-discovery.md) for full detection queries.
