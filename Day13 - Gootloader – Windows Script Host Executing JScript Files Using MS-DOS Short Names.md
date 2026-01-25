# Gootloader – Windows Script Host Executing JScript Files Using MS-DOS Short Names

# Description

This threat hunt detects **Windows Script Host (`cscript.exe`) executing JScript files referenced via MS-DOS 8.3 short filenames** (e.g., `~1.js`), a technique commonly associated with **Gootloader** activity.

Gootloader is known to leverage **short-name notation** to evade simplistic detections and obscure malicious JavaScript execution originating from user-writable locations.

# References
- https://redcanary.com/threat-detection-report/threats/gootloader/

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- Gootloader

# MITRE ATT&CK
- T1059.007 – Command and Scripting Interpreter: JavaScript
- T1036.005 – Masquerading: Match Legitimate Name or Location

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where FileName =~ "cscript.exe"
| where ProcessCommandLine has "~1.js"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
