# AsyncRAT – Dynamic Phishing Attachment and Shortcut File Names

# Description

This threat hunt detects **dynamic, SEO-style phishing file names** associated with **AsyncRAT campaigns**, as described in Trend Micro analysis. Observed attachments and shortcut files use **randomised alphanumeric strings** combined with German business terms such as **“Rechnung”** (invoice) and **“Auftrag”** (order), and are delivered with extensions like **`.pdf.zip`** or **`.url`** to entice execution.

An example pattern includes:
- `Rechnung zu Auftrag W19248960825.pdf.zip`

The hunt focuses on identifying **suspicious file creation events** that match this naming convention, which is uncommon in legitimate environments.

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
- T1566.001 – Phishing: Spearphishing Attachment
- T1036 – Masquerading

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceFileEvents

# Query

```kql
DeviceFileEvents
| where FileName startswith "Rechnung"
| where FileName has "Auftrag"
| where FileName endswith ".zip" or FileName endswith ".url"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
