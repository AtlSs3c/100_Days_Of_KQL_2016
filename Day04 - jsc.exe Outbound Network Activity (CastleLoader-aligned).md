# jsc.exe Outbound Network Activity (CastleLoader-aligned)

# Description

This threat hunt detects **outbound network connections initiated by `jsc.exe` (Microsoft JavaScript Compiler)**. While `jsc.exe` is a legitimate compiler, it is **not expected to establish external HTTP connections** in normal environments. CastleLoader analysis indicates the **final payload may execute in-memory within `jsc.exe`**, using it to communicate with external infrastructure.

This hunt highlights **anomalous compiler-driven network activity** that may indicate loader execution or C2 communication.

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
- T1071.001 – Application Layer Protocol: Web Protocols
- T1059.007 – Command and Scripting Interpreter: JavaScript

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceNetworkEvents

# Query

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "jsc.exe"
| where RemoteIP == "94.159.113.32" or RemoteUrl contains "/service"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl
