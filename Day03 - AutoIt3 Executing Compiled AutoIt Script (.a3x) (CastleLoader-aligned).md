# AutoIt3 Executing Compiled AutoIt Script (.a3x) (CastleLoader-aligned)

# Description

This threat hunt monitors for **AutoIt3.exe executing compiled AutoIt scripts (`.a3x`)**, a behaviour highlighted in CastleLoader analysis where AutoIt is used to run a compiled script (e.g., `freely.a3x`) as part of a loader chain.

The hunt is designed to surface **script execution via AutoIt** that may indicate staging or execution of follow-on payloads.

# References
- https://any.run/cybersecurity-blog/castleloader-malware-analysis/

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- CastleLoader (loader-style malware)

# MITRE ATT&CK
- T1059.010 – Command and Scripting Interpreter: AutoIt

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where isnotempty(ProcessCommandLine)
| where ProcessCommandLine =~ "AutoIt3.exe"
| where ProcessCommandLine contains ".a3x"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
