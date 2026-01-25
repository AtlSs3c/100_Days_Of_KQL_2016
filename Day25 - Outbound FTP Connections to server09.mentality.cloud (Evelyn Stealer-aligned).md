# Outbound FTP Connections to server09.mentality.cloud (Evelyn Stealer-aligned)

# Description

This threat hunt detects **outbound FTP connections to `server09.mentality.cloud` on port 21**, infrastructure associated with **Evelyn Stealer** activity. The use of **FTP for data exfiltration** is consistent with observed campaign tradecraft and is uncommon in modern enterprise environments, making this a **high-signal network indicator** when correlated with suspicious host activity.

# References
- https://www.trendmicro.com/en_us/research/26/a/analysis-of-the-evelyn-stealer-campaign.html

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- Evelyn Stealer

# MITRE ATT&CK
- T1048.003 – Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
- T1071.001 – Application Layer Protocol: Web Protocols

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceNetworkEvents

# Query

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "server09.mentality.cloud"
| where RemotePort == 21
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
