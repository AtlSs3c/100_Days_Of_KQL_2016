# Suspicious Process Chaining: wscript.exe → powershell.exe → msbuild.exe (SHADOW#REACTOR-aligned)

# Description

This threat hunt detects **suspicious multi-stage process chaining** consistent with the **SHADOW#REACTOR campaign** delivering **Remcos RAT**. The campaign leverages **text-only staging and in-memory execution**, abusing trusted Windows components to evade detection.

The hunt focuses on an execution flow where an **obfuscated VBS script** executed via `wscript.exe` launches a **PowerShell stager**, which subsequently invokes **`msbuild.exe` as a LOLBin** to execute malicious .NET content.

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
- T1059.005 – Command and Scripting Interpreter: Visual Basic
- T1059.001 – Command and Scripting Interpreter: PowerShell
- T1127.001 – Trusted Developer Utilities Proxy Execution: MSBuild

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wscript.exe"
| where FileName =~ "powershell.exe"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| join kind=inner (
    DeviceProcessEvents
    | where InitiatingProcessFileName =~ "powershell.exe"
    | where FileName =~ "msbuild.exe"
) on DeviceName
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
