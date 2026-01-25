# SHADOW#REACTOR PowerShell In-Memory Execution Patterns (Remcos RAT-aligned)

# Description

This threat hunt identifies **PowerShell execution patterns** associated with the **SHADOW#REACTOR campaign** delivering **Remcos RAT**. Analysis indicates the threat actor uses **PowerShell for in-memory payload reconstruction**, leveraging `FromBase64String` and `System.Net.WebClient` while **bypassing execution policies** to evade controls.

The hunt focuses on **behavioural indicators within the PowerShell command line** that are strongly indicative of in-memory staging and delivery activity.

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
- T1059.001 – Command and Scripting Interpreter: PowerShell
- T1027 – Obfuscated Files or Information

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "ExecutionPolicy Bypass"
    and ProcessCommandLine has "FromBase64String"
    and ProcessCommandLine has "WebClient"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessParentFileName
