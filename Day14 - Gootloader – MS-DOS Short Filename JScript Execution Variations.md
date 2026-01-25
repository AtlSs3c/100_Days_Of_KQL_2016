# Gootloader – MS-DOS Short Filename JScript Execution Variations

# Description

This threat hunt detects **Windows Script Host (`cscript.exe`) executing JScript files using MS-DOS 8.3 short filename notation**, a technique frequently observed in **Gootloader** infections. Examples include `POSTPR~1.JS`, `DOCUME~2.js`, and `ABCDEF~9.JS`.

Such patterns are **rare in legitimate environments** and represent a **high-signal indicator** of obfuscated JavaScript execution intended to evade basic filename-based detections.

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
| where ProcessCommandLine matches regex @"(?i)[A-Z0-9]{1,6}~[0-9]\.js(\s|$)"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
