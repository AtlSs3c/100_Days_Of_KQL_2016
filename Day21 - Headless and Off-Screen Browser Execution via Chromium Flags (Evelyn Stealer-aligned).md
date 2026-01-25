# Headless and Off-Screen Browser Execution via Chromium Flags (Evelyn Stealer-aligned)

# Description

This threat hunt detects **Chromium-based browsers (Edge, Chrome, Brave) launched in headless mode with off-screen rendering parameters**, a technique observed in the **Evelyn Stealer campaign**. The campaign abuses browser automation capabilities to perform covert web activity while minimising user visibility by disabling extensions, logging, and sandboxing, and rendering the browser window off-screen with minimal dimensions.

The hunt focuses on a **distinct combination of command-line flags** that is highly unusual in legitimate enterprise usage.

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
- T1059 – Command and Scripting Interpreter
- T1564.003 – Hide Artifacts: Hidden Window

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query


```kql
let CmdStrings = dynamic ([
    "--headless=new",
    "--no-sandbox",
    "--disable-extensions",
    "--disable-logging",
    "--silent-launch",
    "--window-position=-10000,-10000",
    "--window-size=1,1",
    "about:blank"
]);

DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("msedge.exe", "chrome.exe", "brave.exe")
| where ProcessCommandLine has_all (CmdStrings)
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```
# Query – Headless Browser + Evelyn Workspace Correlation (30-minute window)
```kql
let window = 30m;
let evelyn_activity =
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"\AppData\"
    | where FolderPath has @"\Evelyn"
    | where ActionType in~ ("FolderCreated", "FileCreated")
    | project DeviceId, EvelynTime=Timestamp, EvelynFile=FileName, EvelynPath=FolderPath;
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("msedge.exe", "chrome.exe", "brave.exe")
| where ProcessCommandLine has_all ("--headless=new", "--no-sandbox", "--window-position=-10000,-10000", "--window-size=1,1")
| join kind=inner (evelyn_activity) on DeviceId
| where Timestamp between (EvelynTime - window .. EvelynTime + window)
| project EvelynTime, Timestamp, DeviceName, FileName, ProcessCommandLine, EvelynFile, EvelynPath, InitiatingProcessFileName, InitiatingProcessCommandLine
