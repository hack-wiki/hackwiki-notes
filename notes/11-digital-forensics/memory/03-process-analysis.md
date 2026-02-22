% Filename: 11-digital-forensics/memory/03-process-analysis.md
% Display name: Step 3 - Process Analysis
% Last update: 2026-02-17
% Authors: @TristanInSec

# Process Analysis

## Overview

Process analysis in memory forensics examines running and terminated processes
to identify malicious activity. By analyzing process trees, loaded modules,
command-line arguments, open handles, and network connections, investigators
can detect anomalous processes, identify their capabilities, and trace attacker
actions. Comparing multiple data sources (PsList vs PsScan vs PsTree) reveals
hidden or unlinked processes that may indicate rootkit activity.

## Process Listing Methods

Volatility 3 provides multiple ways to enumerate processes, each using a
different data source. Discrepancies between them indicate process hiding.

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# PsList — walks the EPROCESS doubly-linked list
# Misses processes that have been unlinked (DKOM)
vol -f memory.raw windows.pslist

# PsTree — same data as PsList, displayed as parent-child tree
vol -f memory.raw windows.pstree

# PsScan — scans physical memory for EPROCESS pool tags
# Finds terminated and hidden (unlinked) processes
vol -f memory.raw windows.psscan

# Cross-reference all methods to find discrepancies
vol -f memory.raw windows.malware.psxview
# Processes visible in PsScan but not PsList = potentially hidden
```

## Identifying Suspicious Processes

### Process Name Anomalies

```text
Normal Windows processes have specific characteristics:

svchost.exe:
  - Parent: services.exe (PID of services.exe)
  - Path: C:\Windows\System32\svchost.exe
  - Always runs with -k flag (e.g., svchost.exe -k netsvcs)
  - Red flags: wrong parent, wrong path, no -k flag, misspelled

lsass.exe:
  - Parent: wininit.exe
  - Path: C:\Windows\System32\lsass.exe
  - Only ONE instance should exist
  - Red flags: multiple instances, wrong parent, wrong path

csrss.exe:
  - Parent: smss.exe (but parent terminates, so shows as orphan)
  - Path: C:\Windows\System32\csrss.exe
  - Typically two instances (Session 0 and Session 1)
  - Red flags: wrong path, more than two instances

explorer.exe:
  - Parent: userinit.exe (but parent terminates)
  - Path: C:\Windows\explorer.exe
  - One per interactive logon session
  - Red flags: wrong path, running as SYSTEM

smss.exe:
  - Parent: System (PID 4)
  - Path: C:\Windows\System32\smss.exe
  - Only one master instance; child instances terminate
  - Red flags: multiple persistent instances, wrong path
```

### Process Tree Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# Display process tree to identify suspicious parent-child relationships
vol -f memory.raw windows.pstree

# What to look for:
#   cmd.exe spawned by Word/Excel/browser → likely macro/exploit
#   powershell.exe spawned by cmd.exe from non-standard parent
#   svchost.exe not under services.exe
#   rundll32.exe with no arguments or suspicious DLL paths
#   Multiple instances of single-instance processes (lsass, services)
```

### Command-Line Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# Show command lines for all processes
vol -f memory.raw windows.cmdline

# Check specific process
vol -f memory.raw windows.cmdline --pid 1234

# Suspicious patterns:
#   powershell -enc <base64>           → encoded command
#   cmd.exe /c <long command>          → command execution
#   rundll32.exe <unusual.dll>,#1      → DLL side-loading
#   certutil -urlcache -split -f       → download and execute
#   mshta.exe http://                  → HTA execution
#   regsvr32.exe /s /n /u /i:<url>     → Squiblydoo
#   svchost.exe without -k             → fake svchost
```

## DLL and Module Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# List DLLs loaded by a specific process
vol -f memory.raw windows.dlllist --pid 1234

# Detect unlinked/hidden DLLs
# LdrModules compares InLoadOrderModuleList, InInitializationOrderModuleList,
# and InMemoryOrderModuleList for each process
vol -f memory.raw windows.malware.ldrmodules

# A DLL that appears False in all three lists but exists in the VAD
# is likely injected or manually mapped

# Key columns to check:
#   InLoad  InInit  InMem  MappedPath
#   True    True    True   \Windows\System32\ntdll.dll      (normal)
#   False   False   False  \Users\...\malicious.dll          (suspicious)
```

## Handle Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# List all handles for a process
vol -f memory.raw windows.handles --pid 1234

# Handle types reveal process capabilities:
#   File handles → files being accessed
#   Key handles → registry keys being accessed
#   Process handles → other processes being manipulated
#   Thread handles → threads in other processes
#   Section handles → shared memory / mapped files
#   Mutant handles → mutexes (malware often creates unique mutexes)
```

## Network Connection Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# List all network connections with owning process
vol -f memory.raw windows.netscan

# Key columns: Owner (process name), PID, LocalAddr, ForeignAddr, State

# What to look for:
#   Unexpected processes with outbound connections
#   Connections to known-bad IPs or unusual ports
#   svchost.exe connecting to non-Microsoft IPs
#   Processes listening on unusual ports
#   ESTABLISHED connections during the incident timeframe
```

## SID and Privilege Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# Show SIDs associated with each process
vol -f memory.raw windows.getsids

# What to look for:
#   Processes running as SYSTEM that shouldn't be
#   User processes with elevated SIDs
#   Processes with S-1-5-18 (SYSTEM) or S-1-5-32-544 (Administrators)
```

## Linux Process Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# List processes
vol -f memory.lime linux.pslist

# Process tree
vol -f memory.lime linux.pstree

# List open files per process
vol -f memory.lime linux.lsof

# Recover bash history per process
vol -f memory.lime linux.bash

# Check environment variables for suspicious content
vol -f memory.lime linux.envars

# List ELF binaries mapped in process memory
vol -f memory.lime linux.elfs

# Suspicious patterns on Linux:
#   Process running from /tmp, /dev/shm, or /var/tmp
#   Deleted binaries (path shows "(deleted)")
#   Processes with LD_PRELOAD set
#   Shell processes spawned from web server (www-data)
#   Crypto miners (high CPU, connections to mining pools)
```

## Process Analysis Checklist

| Check | Description |
|---|---|
| Process tree | Identify unexpected parent-child relationships |
| Process path | Verify executable runs from expected location |
| Command line | Look for encoded commands, downloads, suspicious args |
| DLL list | Check for unexpected or injected DLLs |
| windows.malware.ldrmodules | Find hidden/unlinked modules |
| Network | Identify C2 connections, beacons, exfiltration |
| Handles | Find mutexes, file access, registry manipulation |
| SIDs | Verify process runs under expected user context |
| windows.malware.psxview | Detect hidden/unlinked processes |
| Timestamps | Correlate process start times with incident timeline |

## References

### Tools

- [Volatility 3](https://github.com/volatilityfoundation/volatility3)

### Further Reading

- [SANS Hunt Evil Poster](https://www.sans.org/posters/hunt-evil/)
- [The Art of Memory Forensics](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics-p-9781118825099)
