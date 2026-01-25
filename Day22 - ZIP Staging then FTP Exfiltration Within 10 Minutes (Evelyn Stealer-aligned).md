# ZIP Staging then FTP Exfiltration Within 10 Minutes (Evelyn Stealer-aligned)

# Description

This threat hunt detects a **high-confidence exfiltration sequence** associated with **Evelyn Stealer** tradecraft: a **ZIP archive created under `\AppData\...\Evelyn\`** followed by an **FTP connection to `server09.mentality.cloud` on port 21** within **10 minutes**.

The hunt correlates **local staging** (ZIP creation) with **network exfiltration activity** to highlight likely data theft workflows.

# References
- https://www.trendmicro.com/en_us/research/26/a/analysis-of-the-evelyn-stealer-campaign.html

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- Evelyn Stealer

# MITRE ATT&CK
- T1074.001 – Data Staged: Local Data Staging
- T1560.001 – Archive Collected Data: Archive via Utility
- T1048.003 – Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceFileEvents
  - DeviceNetworkEvents

# Query

```kql
let window = 10m;

let zip_events =
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"\AppData\"
    | where FolderPath has @"\Evelyn"
    | where FileName endswith ".zip"
    | where ActionType =~ "FileCreated"
    | project DeviceId, DeviceName, ZipTime=Timestamp, ZipFile=FileName, ZipPath=FolderPath,
              ZipInitiatingFile=InitiatingProcessFileName, ZipInitiatingCmd=InitiatingProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "server09.mentality.cloud"
| where RemotePort == 21
| join kind=inner (zip_events) on DeviceId
| where Timestamp between (ZipTime .. ZipTime + window)
| project ZipTime, Timestamp, DeviceName, ZipFile, ZipPath, ZipInitiatingFile, ZipInitiatingCmd,
          InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
