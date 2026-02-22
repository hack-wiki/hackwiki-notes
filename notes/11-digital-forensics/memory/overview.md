% Filename: 11-digital-forensics/memory/overview.md
% Display name: Memory Forensics
% Last update: 2026-02-11
% Authors: @TristanInSec

# Memory Forensics

## Overview

Memory forensics involves capturing and analyzing the contents of volatile
memory (RAM). Unlike disk forensics, memory analysis reveals runtime state —
running processes, network connections, loaded modules, encryption keys, and
injected code that may never touch disk. Memory forensics is critical for
detecting fileless malware, rootkits, and in-memory-only indicators of
compromise.

## Topics in This Section

- [Memory Acquisition](01-acquisition.md) — capturing RAM from live systems and
  virtual machines while preserving volatile evidence
- [Volatility Framework](02-volatility.md) — using Volatility 3 for comprehensive
  memory analysis on Windows and Linux images
- [Process Analysis](03-process-analysis.md) — examining process trees, loaded
  modules, handles, and command-line arguments
- [Memory-Based Malware Hunting](04-malware-hunting.md) — detecting injected code,
  hollowed processes, rootkits, and suspicious memory regions

## General Approach

```text
Incident detected / live system available
    │
    ├── Acquire memory dump
    │   ├── Linux: /proc/kcore, LiME, AVML
    │   ├── Windows: WinPmem, DumpIt, FTK Imager
    │   └── VMs: snapshot + vmem extraction
    │
    ├── Identify OS profile / symbol tables
    │   └── vol -f dump.raw windows.info / linux.bash
    │
    ├── Process analysis
    │   ├── Process listing (PsList, PsTree, PsScan)
    │   ├── DLL and module enumeration
    │   ├── Command-line arguments
    │   └── Network connections
    │
    ├── Malware hunting
    │   ├── Malfind → injected code detection
    │   ├── LdrModules → hidden DLLs
    │   ├── SSDT / IDT hooks
    │   └── YARA scanning in memory
    │
    └── Extract artifacts (files, registry, credentials)
```
