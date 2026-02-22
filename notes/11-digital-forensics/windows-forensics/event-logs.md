% Filename: 11-digital-forensics/windows-forensics/event-logs.md
% Display name: Windows Event Logs
% Last update: 2026-02-11
% Authors: @TristanInSec

# Windows Event Logs

## Overview

Windows Event Logs (EVTX) are a primary source of forensic evidence on Windows
systems. They record security events, system changes, application activity,
and more. Event logs are stored in binary EVTX format at
`C:\Windows\System32\winevt\Logs\`. Analyzing event logs reveals authentication
activity, process execution, service installations, and many other indicators
of compromise.

## Key Log Files

| Log File | Path | Contents |
|---|---|---|
| Security.evtx | winevt\Logs\ | Authentication, logon/logoff, policy changes |
| System.evtx | winevt\Logs\ | Service changes, driver loads, system events |
| Application.evtx | winevt\Logs\ | Application crashes, errors |
| PowerShell/Operational.evtx | winevt\Logs\ | PowerShell script execution |
| Sysmon/Operational.evtx | winevt\Logs\ | Process creation, network, file (if Sysmon installed) |
| TaskScheduler/Operational.evtx | winevt\Logs\ | Scheduled task creation and execution |
| TerminalServices-*.evtx | winevt\Logs\ | RDP session activity |
| Windows Defender/Operational.evtx | winevt\Logs\ | Antivirus detections |

## Parsing EVTX Files

### python-evtx

```python
# python-evtx
# https://github.com/williballenthin/python-evtx
import Evtx.Evtx as evtx
import Evtx.Views as evtx_views

# Open and parse an EVTX file
with evtx.Evtx("/evidence/Security.evtx") as log:
    for record in log.records():
        print(record.xml())
```

```python
# python-evtx
# https://github.com/williballenthin/python-evtx
import Evtx.Evtx as evtx
from xml.etree import ElementTree

# Filter for specific Event IDs
TARGET_IDS = {4624, 4625, 4672, 4720, 4732}

with evtx.Evtx("/evidence/Security.evtx") as log:
    for record in log.records():
        root = ElementTree.fromstring(record.xml())
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        event_id = int(root.find(".//ns:EventID", ns).text)
        if event_id in TARGET_IDS:
            time_created = root.find(".//ns:TimeCreated", ns).get("SystemTime")
            print(f"[{time_created}] Event ID: {event_id}")
            # Extract event-specific data fields
            for data in root.findall(".//ns:Data", ns):
                name = data.get("Name")
                value = data.text
                if name and value:
                    print(f"  {name}: {value}")
```

## Security Event IDs — Authentication

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logon session ended |
| 4647 | User initiated logoff |
| 4648 | Logon using explicit credentials (runas) |
| 4672 | Special privileges assigned to new logon (admin) |
| 4776 | Credential validation (NTLM) |

**Logon Types (Event ID 4624):**

| Type | Name | Description |
|---|---|---|
| 2 | Interactive | Console logon (keyboard) |
| 3 | Network | SMB, network share access |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth, cleartext password |
| 9 | NewCredentials | RunAs with /netonly |
| 10 | RemoteInteractive | RDP logon |
| 11 | CachedInteractive | Cached domain credential logon |

## Security Event IDs — Account Management

| Event ID | Description |
|---|---|
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempted |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4728 | Member added to security-enabled global group |
| 4732 | Member added to security-enabled local group |
| 4756 | Member added to universal group |

## Security Event IDs — Process and Object Access

| Event ID | Description |
|---|---|
| 4688 | New process created (requires audit policy) |
| 4689 | Process exited |
| 4697 | Service installed |
| 4698 | Scheduled task created |
| 4699 | Scheduled task deleted |
| 4702 | Scheduled task updated |
| 4663 | Object access attempted (file, registry) |

## System Event IDs

| Event ID | Description |
|---|---|
| 7034 | Service crashed unexpectedly |
| 7035 | Service sent a start/stop control |
| 7036 | Service entered running/stopped state |
| 7040 | Service start type changed |
| 7045 | New service installed |
| 1 (Sysmon) | Process creation with full command line |
| 3 (Sysmon) | Network connection |
| 11 (Sysmon) | File created |

## PowerShell Event IDs

| Event ID | Log | Description |
|---|---|---|
| 4103 | PowerShell/Operational | Module logging (command invocation) |
| 4104 | PowerShell/Operational | Script block logging (script content) |
| 400 | Windows PowerShell | Engine lifecycle (start) |
| 800 | Windows PowerShell | Pipeline execution details |

## Forensic Analysis Patterns

### Brute Force / Password Spray Detection

```text
Look for: Multiple Event ID 4625 (failed logon) from same source
  - Same TargetUserName, different source → brute force
  - Different TargetUserName, same source → password spray
  - Event ID 4625 followed by 4624 → successful brute force

Key fields:
  TargetUserName — account targeted
  IpAddress — source of the attempt
  LogonType — 3 (network) or 10 (RDP)
  FailureReason / Status / SubStatus — why it failed
```

### Lateral Movement Detection

```text
Look for: Event ID 4624 with LogonType 3 (network) or 10 (RDP)
  - From internal IP addresses
  - Using admin or service accounts
  - At unusual times or from unusual sources
  - Followed by 4672 (special privileges)

PsExec pattern:
  1. 4624 (LogonType 3) — network authentication
  2. 7045 (System) — service installed (PSEXESVC)
  3. 4688 — process created by the service

WMI pattern:
  1. 4624 (LogonType 3) — network authentication
  2. 4688 — wmiprvse.exe spawning commands
```

### Persistence Detection

```text
Look for:
  7045 (System) — new service installed
    Check: ServiceName, ImagePath for suspicious binaries
  4698 — scheduled task created
    Check: TaskName, Command for malicious commands
  4720 — new user account created
    Check: TargetUserName for suspicious names
  4732 — user added to Administrators group
```

### RDP Activity

```text
Event logs:
  Security.evtx:
    4624 (LogonType 10) — RDP logon
    4625 (LogonType 10) — RDP failed logon
    4634 — logoff

  TerminalServices-LocalSessionManager/Operational.evtx:
    21 — Session logon succeeded
    22 — Shell start notification received
    23 — Session logoff succeeded
    24 — Session disconnected
    25 — Session reconnected

  TerminalServices-RDPClient/Operational.evtx:
    1024 — RDP client attempting connection (outbound)
    1102 — Client connected to server
```

## References

### Tools

- [python-evtx](https://github.com/williballenthin/python-evtx)

### Further Reading

- [Microsoft Event Log Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [SANS Windows Event Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
