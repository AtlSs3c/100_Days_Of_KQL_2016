# DisableRestrictedAdmin Registry Modification for RDP (UAT-8837-aligned)

# Description

This threat hunt detects **registry modifications that disable Restricted Admin mode for Remote Desktop Protocol (RDP)**, a technique used by **UAT-8837** to facilitate **credential exposure and lateral movement** across Windows systems.

By setting the `DisableRestrictedAdmin` registry value, an attacker can bypass protections designed to prevent credential material from being exposed during RDP sessions, enabling further compromise of additional hosts.

# References
- UAT-8837 targeting critical infrastructure sectors in North America

# Author
- AtlSs3c

# Socials
- https://www.linkedin.com/in/aneta-avramova-a757261b8
- @AtlSs3c

# Threats
- UAT-8837

# MITRE ATT&CK
- T1112 – Modify Registry
- T1021.001 – Remote Services: Remote Desktop Protocol

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceRegistryEvents

# Query

```kql
DeviceRegistryEvents
| where RegistryKey == @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
| where RegistryValueName == "DisableRestrictedAdmin"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
