# Renamed or Relocated AutoIt3 Execution (HijackLoader-aligned)

# Description

This threat hunt identifies **renamed or relocated AutoIt3 interpreter executions** running from **user-writable or temporary directories**, a technique commonly associated with **HijackLoader and similar loader families**.

The hunt focuses on processes that **identify as AutoIt via embedded version metadata** while **not executing as `autoit3.exe`**, helping surface attempts to disguise the AutoIt runtime to evade detection. Legitimate AutoIt installations and installers are explicitly excluded.

# References
- https://redcanary.com/threat-detection-report/threats/hijackloader/
- https://redcanary.com/blog/threat-detection/system32-binaries/

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- HijackLoader
- Loader-style malware abusing AutoIt

# MITRE ATT&CK
- T1059.010 – Command and Scripting Interpreter: AutoIt

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (
    tolower(ProcessVersionInfoOriginalFileName) == "autoit3.exe"
    or tolower(ProcessVersionInfoProductName) has "autoit"
    or tolower(ProcessVersionInfoFileDescription) has "autoit"
)
| where tolower(FileName) != "autoit3.exe"
| where tolower(FolderPath) matches regex @"\\users\\|\\programdata\\|\\windows\\temp\\|\\temp\\"
| where not(tolower(FolderPath) has @"\program files\autoit3\")
| where not(tolower(FolderPath) has @"\program files (x86)\autoit3\")
| where not(
    tolower(FileName) has "setup"
    or tolower(FileName) has "install"
    or tolower(ProcessVersionInfoFileDescription) has "setup"
)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          ProcessVersionInfoOriginalFileName, ProcessVersionInfoProductName,
          ProcessVersionInfoFileDescription, InitiatingProcessFileName, InitiatingProcessFolderPath
