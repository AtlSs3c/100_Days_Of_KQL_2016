# AsyncRAT – WebDAV Connection via Cloudflare (Initial Access)

# Description

This threat hunt detects **use of `rundll32.exe` to invoke WebDAV functionality** for setting cookies against **`trycloudflare.com`** domains, a technique observed in **multi-stage AsyncRAT campaigns** to establish **initial access** and connectivity to attacker-controlled infrastructure.

The activity leverages `davclnt.dll,DavSetCookie` to prepare WebDAV communication, abusing legitimate Windows components to blend into normal system behaviour.

# References
- https://www.trendmicro.com/en_us/research/26/a/analyzing-a-a-multi-stage-asyncrat-campaign-via-mdr.html

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- AsyncRAT

# MITRE ATT&CK
- T1059.003 – Command and Scripting Interpreter: Windows Command Shell
- T1105 – Ingress Tool Transfer

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where ProcessCommandLine has "rundll32.exe"
| where ProcessCommandLine has "davclnt.dll,DavSetCookie"
| where ProcessCommandLine has "trycloudflare.com"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
