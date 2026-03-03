% Filename: 12-defensive/threat-hunting/hunting-windows.md
% Display name: Windows Threat Hunting
% Last update: 2026-02-19
% Authors: @TristanInSec

# Windows Threat Hunting

## Overview

Windows environments provide rich telemetry for threat hunting through Event
Logs, Sysmon, and endpoint detection tools. This file provides specific hunt
queries and techniques for common attacker behaviors in Windows environments,
organized by ATT&CK tactic.

## Hunting for Initial Access

### Suspicious Office Macro Execution

```text
Hunt hypothesis: Attackers deliver malicious macros via phishing documents

Data source: Sysmon Event ID 1 (Process Creation)

Look for:
  - WINWORD.EXE, EXCEL.EXE, or POWERPNT.EXE spawning child processes
  - Especially: cmd.exe, powershell.exe, mshta.exe, wscript.exe, cscript.exe
  - Parent process should be an Office application
  - Any child process from Office is suspicious in most environments

Filter:
  ParentImage contains "WINWORD.EXE" OR "EXCEL.EXE" OR "POWERPNT.EXE"
  AND Image NOT contains "splwow64.exe" (legitimate print helper)
```

### Suspicious Email Attachment Execution

```text
Hunt hypothesis: Users execute malicious attachments from email

Data source: Sysmon Event ID 1, Event ID 11 (File Create)

Look for:
  - Files created in Outlook temp directory:
    C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\*
  - Executable files (.exe, .scr, .bat, .ps1, .hta, .js, .vbs)
    created in Downloads or Desktop folders
  - Process creation from these paths
```

## Hunting for Execution

### Suspicious PowerShell Activity

```text
Hunt hypothesis: Attackers abuse PowerShell for execution

Data source: PowerShell Event ID 4104 (Script Block), Sysmon Event ID 1

Suspicious patterns:
  - Encoded commands (-enc, -EncodedCommand)
  - Download cradles (Net.WebClient, Invoke-WebRequest, IEX)
  - AMSI bypass strings (AmsiUtils, amsiInitFailed)
  - Reflection ([System.Reflection.Assembly]::Load)
  - Direct .NET access ([System.IO.File], [System.Net.Sockets])
  - Base64 decoded execution ([Convert]::FromBase64String)

Baseline comparison:
  - Which users normally run PowerShell?
  - Which servers normally run PowerShell scripts?
  - Unusual = a user or system that has never run PowerShell before
```

### LOLBin Usage

```text
Hunt hypothesis: Attackers use Living Off the Land Binaries

Data source: Sysmon Event ID 1

Key LOLBins to hunt:

certutil.exe:
  - Download: certutil -urlcache -f http://... file.exe
  - Decode: certutil -decode encoded.b64 decoded.exe

mshta.exe:
  - Execute HTA from URL: mshta http://...
  - Execute inline VBScript: mshta vbscript:Execute(...)

rundll32.exe:
  - Execute DLL: rundll32 malicious.dll,EntryPoint
  - Execute JavaScript: rundll32 javascript:"..."

regsvr32.exe:
  - Squiblydoo: regsvr32 /s /n /u /i:http://... scrobj.dll

bitsadmin.exe:
  - Download: bitsadmin /transfer job http://... file.exe

wmic.exe:
  - Process creation: wmic process call create "cmd /c ..."
  - XSL execution: wmic os get /format:evil.xsl

Hunting approach:
  - List all executions of these binaries
  - Stack count the command-line arguments
  - Investigate rare/unusual argument patterns
```

## Hunting for Persistence

### Scheduled Task Hunting

```text
Hunt hypothesis: Attackers create scheduled tasks for persistence

Data source: Security Event ID 4698, Sysmon Event ID 1

Look for:
  - schtasks.exe /create with suspicious commands
  - Tasks running as SYSTEM that execute from temp directories
  - Tasks with encoded PowerShell commands
  - Recently created tasks on systems that rarely have new tasks

Query approach:
  - List all Event ID 4698 events in the past 30 days
  - Extract the TaskContent XML (contains the command)
  - Look for: PowerShell, cmd, script paths in temp/users directories
  - Compare against known legitimate tasks
```

### Service Installation Hunting

```text
Hunt hypothesis: Attackers install services for persistence

Data source: System Event ID 7045

Look for:
  - Services with ImagePath pointing to temp directories
  - Services with unusual names (random strings, single words)
  - Services running executables from user-writable locations
  - cmd.exe or powershell.exe in the ImagePath
  - Services with Start Type = auto that were recently created

Query approach:
  - List all Event ID 7045 in the past 30 days
  - Stack count by ServiceName — rare names are suspicious
  - Check ImagePath for known-bad patterns
  - Cross-reference with current services to find ones that were
    installed and then removed (possible cleanup attempt)
```

### Registry Run Key Hunting

```text
Hunt hypothesis: Attackers add registry Run keys for persistence

Data source: Sysmon Event ID 13 (Registry Value Set)

Look for:
  - TargetObject containing \CurrentVersion\Run
  - TargetObject containing \CurrentVersion\RunOnce
  - Values pointing to temp directories, user directories, or encoded commands
  - Values pointing to recently created executables

Stack count approach:
  - Aggregate all Run key values across endpoints
  - The most common values are legitimate (Windows Defender, etc.)
  - Investigate values that appear on very few systems
```

## Hunting for Lateral Movement

### PsExec / Remote Service Execution

```text
Hunt hypothesis: Attackers use PsExec or similar tools for lateral movement

Data source: System Event ID 7045, Security Event ID 4624

Look for:
  - Event ID 7045 with ServiceName containing "PSEXE" or random names
  - Event ID 4624 LogonType 3 followed by Event ID 7045 on the same host
  - Services with ImagePath like %SystemRoot%\PSEXESVC.exe
  - Services with ImagePath containing cmd.exe /c (remote command execution)
  - Named pipe creation (Sysmon Event ID 17/18) for \pipe\svcctl
```

### WMI Lateral Movement

```text
Hunt hypothesis: Attackers use WMI for remote execution

Data source: Sysmon Event ID 1

Look for:
  - wmiprvse.exe spawning unexpected child processes
  - Especially: cmd.exe, powershell.exe, or any executable
  - WMI Event Subscriptions (Sysmon Event ID 19/20/21):
    __EventFilter, CommandLineEventConsumer, __FilterToConsumerBinding
  - wmic.exe with /node: argument (remote WMI)
```

### RDP Lateral Movement

```text
Hunt hypothesis: Attackers use RDP for lateral movement

Data source: Security Event ID 4624, TerminalServices logs

Look for:
  - Event ID 4624 LogonType 10 from internal IPs
  - Especially: from workstations to servers (unusual direction)
  - RDP from non-admin users to servers
  - RDP sessions at unusual hours
  - Multiple RDP sessions from the same source to many destinations
  - TerminalServices Event ID 21 (session logon) — correlate with user
```

## Hunting for Credential Access

### LSASS Access

```text
Hunt hypothesis: Attackers dump credentials from LSASS

Data source: Sysmon Event ID 10 (ProcessAccess)

Look for:
  - TargetImage = C:\Windows\System32\lsass.exe
  - GrantedAccess containing:
    0x1010 — minimum for credential dumping
    0x1410 — typical for Mimikatz
    0x1FFFFF — PROCESS_ALL_ACCESS
  - SourceImage that is NOT a known security product:
    - Exclude: MsMpEng.exe, csrss.exe, wininit.exe, lsass.exe itself
  - Process creating a dump file of LSASS:
    Look for procdump.exe, rundll32.exe with comsvcs.dll MiniDump
```

### Kerberoasting

```text
Hunt hypothesis: Attackers request service tickets for offline cracking

Data source: Security Event ID 4769

Look for:
  - Event ID 4769 with Ticket Encryption Type = 0x17 (RC4)
  - Especially when requesting tickets for service accounts with SPNs
  - Many TGS requests from a single source in a short time period
  - Requests from non-service accounts for service account tickets

Baseline:
  - Normal TGS requests use AES (0x12 or 0x11)
  - RC4 requests are increasingly rare in modern environments
  - Any RC4 TGS request from a workstation should be investigated
```

## Hunting for Defense Evasion

### Timestomping

```text
Hunt hypothesis: Attackers modify file timestamps to blend in

Data source: Sysmon Event ID 2 (FileCreateTime Changed)

Look for:
  - Files where CreationUtcTime was changed to a date far in the past
  - Especially: executables in system directories
  - Files with creation timestamps matching legitimate system files
  - Process that modified the timestamp is suspicious
    (legitimate processes rarely change file timestamps)
```

### Log Clearing

```text
Hunt hypothesis: Attackers clear logs to cover tracks

Data source: Security Event ID 1102 (Audit log cleared)

Look for:
  - Event ID 1102 — Security log was cleared
  - Event ID 104 (System log) — System log was cleared
  - wevtutil.exe execution with "cl" argument (Sysmon Event ID 1)
  - Any log clearing outside of documented maintenance windows

Note: If logs are centrally forwarded, the clearing event itself
is still captured even if local logs are wiped
```

## References

### Further Reading

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sysmon (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

> **Note:** Sysmon field names and EventTypes vary by schema version. Queries and rules built against one schema may not work on a different version. Always qualify Sysmon-based detections by schema version and the active config set.
