# AsyncRAT – Batch Files Dropped in Windows Startup Folder (Persistence)

# Description

This threat hunt detects **persistence mechanisms used by AsyncRAT campaigns**, specifically the **creation of batch files in the Windows Startup folder**. Analysis indicates the campaign drops **`ahke.bat`** or **`olsm.bat`** into the Startup directory—often via **PowerShell**—to ensure execution on user logon.

Monitoring for these artefacts helps identify **early-stage persistence** associated with AsyncRAT delivery chains.

# References
- https://www.trendmicro.com/en_us/research/26/a/analyzing-a-a-multi-stage-asyncrat-campaign-via-mdr.html

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- AsyncRAT

# MITRE ATT&CK
- T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1059.001 – Command and Scripting Interpreter: PowerShell

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceFileEvents

# Query

```kql
DeviceFileEvents
| where FileName in~ ("ahke.bat", "olsm.bat")
| where FolderPath endswith @"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
