# AsyncRAT – Malicious Python-Based Shellcode Injection

# Description

This threat hunt detects **malicious Python execution patterns** associated with **AsyncRAT campaigns**, as described in Trend Micro analysis. The observed tradecraft uses a Python script to **decrypt and inject shellcode** into a legitimate process (e.g., `explorer.exe`), leveraging auxiliary files such as a payload (`new.bin`) and a decryption key (`a.txt`).

The hunt focuses on **distinct command-line artefacts** that are uncommon in legitimate Python usage and indicative of **in-memory payload execution**.

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
- T1059.006 – Command and Scripting Interpreter: Python
- T1055 – Process Injection

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where FileName startswith "python"
| where ProcessCommandLine has "ne.py"
| where ProcessCommandLine has_all ("new.bin", "a.txt")
| project TimeGenerated, DeviceName, FolderPath, ProcessCommandLine
