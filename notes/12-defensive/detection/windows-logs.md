% Filename: 12-defensive/detection/windows-logs.md
% Display name: Windows Log Analysis
% Last update: 2026-02-11
% Authors: @TristanInSec

# Windows Log Analysis

## Overview

Windows Event Logs are the primary telemetry source for detecting malicious
activity on Windows systems. Key log channels include Security (authentication,
object access), System (services, drivers), and specialized channels like
PowerShell and Sysmon. This file covers the most important event IDs for
detection, recommended audit policies, and analysis techniques.

## Enabling Audit Policies

Many critical events are not logged by default. Enable them via Group Policy
or auditpol.

```text
Recommended audit policy settings (via Group Policy):

Computer Configuration → Windows Settings → Security Settings →
  Advanced Audit Policy Configuration → Audit Policies

Account Logon:
  Audit Credential Validation          → Success, Failure
  Audit Kerberos Authentication Service → Success, Failure

Logon/Logoff:
  Audit Logon                          → Success, Failure
  Audit Logoff                         → Success
  Audit Special Logon                  → Success

Account Management:
  Audit User Account Management        → Success, Failure
  Audit Security Group Management      → Success, Failure

Detailed Tracking:
  Audit Process Creation               → Success
    (also enable: Include command line in process creation events)

Object Access:
  Audit File System                    → Success, Failure (if needed)
  Audit Registry                       → Success, Failure (if needed)

Policy Change:
  Audit Audit Policy Change            → Success, Failure
  Audit Authentication Policy Change   → Success

System:
  Audit Security State Change          → Success
  Audit System Integrity               → Success, Failure
```

## High-Value Security Events

### Authentication Events

| Event ID | Description | Detection Use |
|---|---|---|
| 4624 | Successful logon | Track user access, lateral movement |
| 4625 | Failed logon | Brute force, password spray |
| 4634/4647 | Logoff | Session duration analysis |
| 4648 | Explicit credentials (runas) | Credential misuse |
| 4672 | Special privileges assigned | Admin logon tracking |
| 4768 | Kerberos TGT requested | AS-REP roasting detection |
| 4769 | Kerberos service ticket | Kerberoasting detection |
| 4771 | Kerberos pre-auth failed | Password spray |
| 4776 | NTLM credential validation | Pass-the-hash detection |

### Account Management Events

| Event ID | Description | Detection Use |
|---|---|---|
| 4720 | User account created | Unauthorized account creation |
| 4722 | User account enabled | Re-enabled dormant accounts |
| 4724 | Password reset | Unauthorized password changes |
| 4728/4732 | Added to security group | Privilege escalation |
| 4756 | Added to universal group | Domain-wide privilege changes |

### Process and Service Events

| Event ID | Source | Description |
|---|---|---|
| 4688 | Security | Process creation (with command line if enabled) |
| 4697 | Security | Service installed |
| 7045 | System | New service installed |
| 4698 | Security | Scheduled task created |
| 4104 | PowerShell | Script block logging (script content) |
| 4103 | PowerShell | Module logging (command invocation) |

## Sysmon Events

Sysmon provides granular endpoint telemetry beyond native Windows logging.
Install from the Sysinternals suite.

```text
Key Sysmon Event IDs:

Event ID 1  — Process creation (full command line, parent process, hashes)
Event ID 2  — File creation time changed (timestomping)
Event ID 3  — Network connection (process → destination IP:port)
Event ID 7  — Image loaded (DLL loading)
Event ID 8  — CreateRemoteThread (process injection indicator)
Event ID 10 — Process access (credential dumping indicator)
Event ID 11 — File created
Event ID 12 — Registry object added/deleted
Event ID 13 — Registry value set
Event ID 15 — FileCreateStreamHash (ADS creation)
Event ID 17 — Pipe created (named pipe for C2)
Event ID 18 — Pipe connected
Event ID 22 — DNS query (process-level DNS logging)
Event ID 23 — File delete archived
Event ID 25 — Process tampering (process hollowing/herpaderping)
```

## PowerShell Logging

### Enabling PowerShell Logging

```text
Computer Configuration → Administrative Templates → Windows Components →
  Windows PowerShell:

  Turn on Module Logging         → Enabled (module names: *)
  Turn on Script Block Logging   → Enabled
  Turn on PowerShell Transcription → Enabled
    (set output directory, e.g., \\server\pslogs$\)
```

### Detecting Malicious PowerShell

```text
Suspicious indicators in Event ID 4104 (Script Block Logging):

Encoded commands:
  -EncodedCommand, -enc, [Convert]::FromBase64String

Download cradles:
  Invoke-WebRequest, Invoke-Expression, IEX, Net.WebClient
  DownloadString, DownloadFile, Start-BitsTransfer

AMSI bypass attempts:
  AmsiUtils, amsiInitFailed, AmsiScanBuffer

Credential access:
  Invoke-Mimikatz, Get-Credential, SecureString

Lateral movement:
  Invoke-Command, Enter-PSSession, New-PSSession
  Invoke-WmiMethod, Invoke-CimMethod

Living off the land:
  Add-MpPreference -ExclusionPath (Defender exclusions)
  Set-MpPreference -DisableRealtimeMonitoring
```

## Detection Patterns

### Brute Force / Password Spray

```text
Pattern: Multiple Event ID 4625 from same source in short timeframe

Brute force:   Same TargetUserName, many failures, then 4624 success
Password spray: Many different TargetUserNames, same source, same password
                (LogonType 3 or 10, Status 0xC000006D = bad password)

Key fields:
  TargetUserName, IpAddress, LogonType, Status, SubStatus
```

### Lateral Movement

```text
PsExec pattern:
  1. Event ID 4624 (LogonType 3, network logon)
  2. Event ID 7045 (System, new service "PSEXESVC" installed)
  3. Event ID 4688 (process created by PSEXESVC)

WMI pattern:
  1. Event ID 4624 (LogonType 3)
  2. Event ID 4688 (wmiprvse.exe spawning child processes)

WinRM/PowerShell remoting:
  1. Event ID 4624 (LogonType 3)
  2. Event ID 4688 (wsmprovhost.exe spawning processes)
  3. PowerShell Event ID 4104 (remote script blocks)

RDP:
  1. Event ID 4624 (LogonType 10)
  2. TerminalServices-LocalSessionManager Event ID 21 (session logon)
```

### Persistence

```text
New service:
  Event ID 7045 — check ImagePath for suspicious binaries/scripts

Scheduled task:
  Event ID 4698 — check TaskContent XML for malicious commands

Account creation:
  Event ID 4720 — unexpected user account creation
  Event ID 4732 — added to Administrators or other privileged group

Registry Run key:
  Sysmon Event ID 13 — TargetObject containing
    \CurrentVersion\Run or \CurrentVersion\RunOnce
```

### Credential Access

```text
LSASS access (credential dumping):
  Sysmon Event ID 10 — TargetImage = lsass.exe
    GrantedAccess includes 0x1010 or 0x1410

DCSync:
  Event ID 4662 — Properties containing
    {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes)
    {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes-All)
  From a non-domain-controller source
```

## References

### Tools

- [Sysmon (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### Further Reading

- [SANS Windows Event Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Microsoft Security Auditing Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
