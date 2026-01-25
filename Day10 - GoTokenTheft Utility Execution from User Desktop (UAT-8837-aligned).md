# GoTokenTheft Utility Execution from User Desktop (UAT-8837-aligned)

# Description

This threat hunt detects **suspicious execution of `go.exe` from a user Desktop directory**, consistent with reported tradecraft associated with **UAT-8837** activity targeting critical infrastructure sectors in North America.

The **GoTokenTheft utility**, written in Go and commonly deployed as `C:\Users\<user>\Desktop\go.exe`, is used to **steal access tokens** that enable attackers to execute commands with **elevated privileges**. Execution of `go.exe` from user-writable Desktop paths is highly unusual in enterprise environments and should be treated as suspicious.

# References
- UAT-8837 targeting critical infrastructure sectors in North America

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- UAT-8837
- GoTokenTheft utility

# MITRE ATT&CK
- T1550 – Use Alternate Authentication Material
- T1059 – Command and Scripting Interpreter

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| where FileName =~ "go.exe"
| where FolderPath has @"\Users\" and FolderPath has @"\Desktop\"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
