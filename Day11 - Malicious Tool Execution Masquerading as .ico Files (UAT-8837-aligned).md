# Malicious Tool Execution Masquerading as .ico Files (UAT-8837-aligned)

# Description

This threat hunt detects **execution of binaries masquerading as `.ico` files**, a technique used by **UAT-8837** to evade security controls while operating in critical infrastructure environments in North America.

UAT-8837 has been observed renaming multiple tools to use **icon file extensions** and executing them from **user-writable or temporary directories** such as `C:\Windows\Temp\` and `C:\Users\Public\`. These files are not legitimate image icons but **malicious executables** associated with tunnelling, lateral movement, and credential access tooling.

# References
- UAT-8837 targeting critical infrastructure sectors in North America

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- UAT-8837
- Earthworm (tunnelling)
- Impacket / Invoke-WMIExec
- GoExec
- SharpWMI
- Rubeus

# MITRE ATT&CK
- T1036.002 – Masquerading: Right-to-Left Override / File Extension Masquerading
- T1059 – Command and Scripting Interpreter
- T1105 – Ingress Tool Transfer

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where FileName endswith ".ico" or ProcessCommandLine contains ".ico"
| where FolderPath has_any ("Windows\\Temp", "Users\\Public")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath
