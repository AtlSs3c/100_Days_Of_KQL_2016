# AsyncRAT – Suspicious WebDAV Mounting via Cloudflare Tunnel

# Description

This threat hunt detects **suspicious WebDAV drive mounting activity** associated with **AsyncRAT campaigns**, where attackers use the Windows `net use` command to mount a **remote WebDAV share** hosted behind **Cloudflare tunnels (`trycloudflare.com`)**.

Observed activity includes mapping a remote WebDAV endpoint (commonly to a drive letter such as `Q:`) using the `@SSL` syntax, enabling attackers to **access and execute malicious content directly from cloud-host2 infrastructure** while evading traditional perimeter controls.

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
- T1105 – Ingress Tool Transfer
- T1021.001 – Remote Services: Remote Desktop Protocol

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has "use"
| where ProcessCommandLine has "@SSL"
| where ProcessCommandLine has "trycloudflare.com"
| project TimeGenerated, DeviceName, ProcessCommandLine

