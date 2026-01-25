# ZIP Created then Deleted Under \Evelyn\ (Post-Exfil Cleanup Signal)

# Description

This threat hunt detects **ZIP archives created and subsequently deleted** within `\AppData\...\Evelyn\`, a behaviour consistent with **post-exfiltration cleanup** observed in Evelyn Stealer tradecraft. Creation followed by deletion of staged archives may indicate an attempt to **remove local evidence after data theft**.

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
- T1070.004 – Indicator Removal: File Deletion
- T1560.001 – Archive Collected Data: Archive via Utility

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceFileEvents

# Query

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "\\AppData\\"
| where FolderPath has "\\Evelyn"
| where FileName endswith ".zip"
| where ActionType in~ ("FileCreated", "FileDeleted")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
