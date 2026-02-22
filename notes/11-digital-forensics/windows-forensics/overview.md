% Filename: 11-digital-forensics/windows-forensics/overview.md
% Display name: Windows Forensics
% Last update: 2026-02-11
% Authors: @TristanInSec

# Windows Forensics

## Overview

Windows forensics covers the analysis of Windows-specific artifacts including
the Event Log system (EVTX), the Registry, and various filesystem and
application artifacts. These data sources record user activity, program
execution, network connections, persistence mechanisms, and security events.
Understanding Windows artifacts is essential for incident response, intrusion
analysis, and attribution.

## Topics in This Section

- [Windows Event Logs](event-logs.md) — analyzing EVTX logs for security events,
  logon activity, process creation, and service changes
- [Registry Forensics](registry.md) — extracting forensic artifacts from offline
  registry hives using reglookup, regripper, and chntpw
- [Windows Artifacts](artifacts.md) — analyzing prefetch, shimcache, amcache,
  SRUM, jump lists, LNK files, and other execution artifacts

## General Approach

```text
Windows system under investigation
    │
    ├── Collect artifacts
    │   ├── Event logs: C:\Windows\System32\winevt\Logs\
    │   ├── Registry hives: C:\Windows\System32\config\
    │   ├── User hives: C:\Users\<user>\NTUSER.DAT
    │   ├── Prefetch: C:\Windows\Prefetch\
    │   └── Amcache: C:\Windows\appcompat\Programs\Amcache.hve
    │
    ├── Event log analysis
    │   ├── Security.evtx → logon events (4624/4625)
    │   ├── System.evtx → service installs, driver loads
    │   ├── Sysmon/Operational → process creation, network
    │   └── PowerShell/Operational → script execution
    │
    ├── Registry analysis
    │   ├── Run/RunOnce → persistence
    │   ├── Services → installed services
    │   ├── UserAssist → program execution counts
    │   ├── ShimCache → application compatibility
    │   └── SAM → user accounts
    │
    ├── Execution artifacts
    │   ├── Prefetch → program execution times
    │   ├── Amcache → installed applications
    │   ├── SRUM → resource usage
    │   └── Jump lists / LNK files → recent access
    │
    └── Correlate and build timeline
```
