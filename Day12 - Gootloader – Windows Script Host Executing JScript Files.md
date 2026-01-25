# Gootloader – Windows Script Host Executing JScript Files

# Description

This threat hunt detects **Windows Script Host (`wscript.exe`) executing JScript (`.js`) files from user AppData paths**, a behaviour commonly associated with **Gootloader** infections. Gootloader frequently delivers malicious JavaScript disguised as benign files, leveraging WSH to execute payloads from user-writable directories.

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

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where FileName =~ "wscript.exe"
| where ProcessCommandLine has @"\AppData\"
| where ProcessCommandLine matches regex @"(?i)\.js(\s|$)"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
