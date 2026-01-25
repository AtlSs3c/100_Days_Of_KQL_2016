# Gootloader SEO-Style ZIP File Naming Pattern

# Description

This threat hunt detects **SEO-style ZIP archive filenames** commonly associated with **Gootloader** delivery mechanisms. Gootloader frequently distributes payloads inside ZIP files named to resemble legitimate documents, using **multiple underscore-separated words** followed by a **non-date numeric identifier in parentheses**.

Examples observed include:
- `florida_building_code_requirements_for_sheds(9306).zip`
- `can_a_minor_be_an_independent_contractor_in_florida(72777).zip`
- `solanco_school_district_collective_bargaining_agreement(6421).zip`
- `novation_agreement_for_tenancy(56934).zip`

The detection logic is designed to **avoid false positives caused by date-based patterns** (e.g. `15012026`) while maintaining high signal for Gootloader-related artefacts.

# References
- https://redcanary.com/threat-detection-report/threats/gootloader/

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- Gootloader

# MITRE ATT&CK
- T1036 – Masquerading
- T1566.001 – Phishing: Spearphishing Attachment

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceFileEvents

# Query

```kql
DeviceFileEvents
| where FileName matches regex @"(?i)^[a-z]+(_[a-z]+){2,}\(([0-9]{3,7}|[0-9]{9,})\)\.zip$"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
