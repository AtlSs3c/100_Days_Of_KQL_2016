# SHADOW#REACTOR Staging File Creation (Remcos RAT-aligned)

# Description

This threat hunt detects **creation of known staging artefacts** associated with the **SHADOW#REACTOR campaign** delivering **Remcos RAT**. The campaign uses a **text-only staging pipeline**, writing obfuscated payload fragments to **specific filenames** within **user-writable locations** (e.g., `%TEMP%`, desktop-related paths) prior to in-memory execution.

The hunt monitors for the presence of these artefacts to surface **early-stage infection activity**.

# References
- https://www.securonix.com/blog/shadowreactor-text-only-staging-net-reactor-and-in-memory-remcos-rat-deployment/

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- SHADOW#REACTOR
- Remcos RAT

# MITRE ATT&CK
- T1074.001 – Data Staged: Local Data Staging
- T1059.001 – Command and Scripting Interpreter: PowerShell
- T1059.005 – Command and Scripting Interpreter: Visual Basic

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceFileEvents

# Query

```kql
let Staging_files = dynamic ([
    "qpwoe32.txt",
    "qpwoe64.txt",
    "teste32.txt",
    "teste64.txt",
    "win64.vbs",
    "jdywa.ps1",
    "xx1.ps1",
    "xx2.vbs"
]);

DeviceFileEvents
| where FileName in~ (Staging_files)
| where FolderPath has_any ("Temp", "PublicData", "Desktop")
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
