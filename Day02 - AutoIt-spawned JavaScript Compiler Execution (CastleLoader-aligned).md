# AutoIt-spawned JavaScript Compiler Execution (CastleLoader-aligned)

# Description

This threat hunt identifies **`jsc.exe` (Microsoft JavaScript Compiler) execution initiated by AutoIt interpreters**, a behaviour aligned with **loader-style malware chains** observed in CastleLoader activity. The hunt focuses on **behavioural correlation** between AutoIt execution and secondary script or compilation stages, which are uncommon in legitimate enterprise environments.

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
- T1059.007 – Command and Scripting Interpreter: JavaScript


# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "jsc.exe"
| where InitiatingProcessFileName in~ ("autoit3.exe", "autoit.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
