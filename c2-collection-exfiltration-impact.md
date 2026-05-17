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
| T1219 - Remote Access Software | | ✅ Covered | DeviceNetworkEvents / DeviceProcessEvents | MDE |
| T1071 - Application Layer Protocol | T1071.001 Web Protocols | ⚠️ Partial | DeviceNetworkEvents / CommonSecurityLog | MDE / CEF |
| T1105 - Ingress Tool Transfer | | ⚠️ Partial | DeviceNetworkEvents / DeviceProcessEvents | MDE |
| T1572 - Protocol Tunneling | | ❌ Gap | DeviceNetworkEvents | MDE |
| T1090 - Proxy | T1090.002 External Proxy | ❌ Gap | DeviceNetworkEvents / CommonSecurityLog | MDE / CEF |

---

## Technique Details

### T1071.004 - DNS

**Status:** ✅ Covered

**Rule:** [T1071-dns-tunneling](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1071-dns-tunneling.md)

---

### T1219 - Remote Access Software

**Status:** ✅ Covered

**What it detects:** Unauthorized remote access tools (AnyDesk, TeamViewer, ScreenConnect, Ngrok, Cobalt Strike) used for C2 communication.

```kql
// Detect known remote access tool process execution
// MITRE ATT&CK: T1219
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where FileName has_any (
    "anydesk.exe", "teamviewer.exe", "screenconnect.exe",
    "ngrok.exe", "frpc.exe", "frps.exe", "plink.exe",
    "meterpreter", "cobalt_strike", "beacon.exe"
)
    or ProcessCommandLine has_any (
        "ngrok tcp", "ngrok http", "frpc -c", "plink -R",
        "-socks5", "socks5 tunnel"
    )
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

---

### T1105 - Ingress Tool Transfer

**Status:** ⚠️ Partial

```kql
// Detect file downloads via living-off-the-land binaries (LOLBins)
// MITRE ATT&CK: T1105
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-urlcache", "-decode", "-encode"))
    or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has "/transfer")
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
        "Invoke-WebRequest", "wget", "curl", "DownloadFile", "DownloadString",
        "WebClient", "Net.WebClient", "Start-BitsTransfer"
    ) and ProcessCommandLine has_any ("http://", "https://", "ftp://"))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

---

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

---

## Technique Details

### T1074.001 - Local Data Staging

**Status:** ✅ Covered

```kql
// Detect bulk file creation in staging directories (zip, archive preparation)
// MITRE ATT&CK: T1074.001
DeviceFileEvents
| where TimeGenerated >= ago(1h)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\Local\\Temp\\", "\\Users\\Public\\")
| where FileName has_any (".zip", ".rar", ".7z", ".tar", ".gz")
| summarize 
    ArchiveCount = count(),
    Archives = make_set(FileName, 10),
    TotalSizeEstimate = sum(FileSize)
    by DeviceName, AccountName, bin(TimeGenerated, 10m)
| where ArchiveCount >= 3
| project TimeGenerated, DeviceName, AccountName, ArchiveCount, Archives
| sort by ArchiveCount desc
```

---

### T1530 - Data from Cloud Storage

**Status:** ⚠️ Partial

```kql
// Detect bulk download of Azure Storage blob data
// MITRE ATT&CK: T1530
StorageBlobLogs
| where TimeGenerated >= ago(1h)
| where OperationName == "GetBlob"
| where StatusCode == 200
| summarize 
    DownloadCount = count(),
    TotalBytes = sum(ResponseBodySize),
    Containers = make_set(Uri)
    by CallerIpAddress, bin(TimeGenerated, 10m)
| where DownloadCount >= 50 or TotalBytes >= 100000000
| project TimeGenerated, CallerIpAddress, DownloadCount, TotalBytes, Containers
| sort by TotalBytes desc
```

---

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

---

## Technique Details

### T1567.002 - Exfiltration to Cloud Storage

**Status:** ⚠️ Partial

```kql
// Detect large data uploads to cloud storage services
// MITRE ATT&CK: T1567.002
DeviceNetworkEvents
| where TimeGenerated >= ago(1h)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (
    "dropbox.com", "drive.google.com", "onedrive.live.com",
    "box.com", "mega.nz", "wetransfer.com", "sendspace.com",
    "s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com"
)
| where RemotePort in (80, 443)
| summarize 
    ConnectionCount = count(),
    TotalSentBytes = sum(SentBytes),
    Destinations = make_set(RemoteUrl, 5)
    by DeviceName, AccountName, bin(TimeGenerated, 10m)
| where TotalSentBytes >= 10000000
| project TimeGenerated, DeviceName, AccountName, TotalSentBytes, ConnectionCount, Destinations
| sort by TotalSentBytes desc
```

---

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

---

## Technique Details

### T1485 - Data Destruction

**Status:** ✅ Covered

**Rule:** [T1485-mass-file-deletion](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1485-mass-file-deletion.md)

---

### T1578.003 - Delete Cloud Instance

**Status:** ✅ Covered

**Rule:** [T1578-azure-mass-resource-deletion](https://github.com/sai-teja-girimaji/sentinel-kql-detection-rules/blob/main/T1578-azure-mass-resource-deletion.md)

---

### T1490 - Inhibit System Recovery

**Status:** ✅ Covered

**What it detects:** Attackers deleting Volume Shadow Copies (VSS), disabling Windows Backup, or modifying boot configuration to prevent recovery after ransomware deployment.

```kql
// Detect shadow copy deletion and recovery inhibition
// MITRE ATT&CK: T1490
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete shadows", "resize shadowstorage"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no", "bootstatuspolicy ignoreallfailures"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
        "Get-WmiObject Win32_ShadowCopy", "Delete()", "Win32_ShadowCopy"
    ))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

---

### T1486 - Data Encrypted for Impact

**Status:** ✅ Covered

**What it detects:** Ransomware activity characterized by mass file rename operations where files are given new extensions (encryption markers).

```kql
// Detect mass file renaming consistent with ransomware encryption
// MITRE ATT&CK: T1486
let RenameThreshold = 50;
DeviceFileEvents
| where TimeGenerated >= ago(1h)
| where ActionType == "FileRenamed"
| extend OldExtension = tostring(extract(@"\.([^.]+)$", 1, PreviousFileName))
| extend NewExtension = tostring(extract(@"\.([^.]+)$", 1, FileName))
| where OldExtension in ("docx", "xlsx", "pdf", "pptx", "jpg", "png", "sql", "bak", "txt", "csv")
| where NewExtension != OldExtension
| summarize 
    RenameCount = count(),
    NewExtensions = make_set(NewExtension),
    SampleOldFiles = make_set(PreviousFileName, 5),
    FolderPaths = make_set(FolderPath)
    by DeviceName, AccountName, bin(TimeGenerated, 5m)
| where RenameCount >= RenameThreshold
| project TimeGenerated, DeviceName, AccountName, RenameCount, NewExtensions, SampleOldFiles, FolderPaths
| sort by RenameCount desc
```
