# SHADOW#REACTOR C2 Network Connections (Remcos RAT-aligned)

# Description

This threat hunt monitors for **outbound network connections to known SHADOW#REACTOR command-and-control (C2) infrastructure** identified during analysis of the campaign delivering **Remcos RAT**. The referenced IP addresses have been observed acting as **hosting and C2 endpoints** supporting payload delivery and post-compromise communication.

The hunt is intended to surface **direct network indicators** associated with confirmed SHADOW#REACTOR infrastructure.

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
- T1071.001 – Application Layer Protocol: Web Protocols
- T1041 – Exfiltration Over C2 Channel

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceNetworkEvents

# Query

```kql
DeviceNetworkEvents
| where RemoteIP in ("91.202.233.215","193.24.123.232")
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, LocalPort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
