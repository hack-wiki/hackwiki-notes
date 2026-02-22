% Filename: 11-digital-forensics/memory/02-volatility.md
% Display name: Step 2 - Volatility Framework
% Last update: 2026-02-17
% Authors: @TristanInSec

# Volatility Framework

## Overview

Volatility 3 is the primary open-source framework for memory forensics. It
analyzes memory dumps from Windows, Linux, and macOS systems to extract
running processes, network connections, loaded modules, registry data,
and malware artifacts. Volatility 3 uses symbol tables (ISF files) instead
of the profile system used in Volatility 2.

## Basic Usage

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# Show OS information (also validates the memory dump)
vol -f memory.raw windows.info

# Specify output directory for extracted files
vol -f memory.raw -o /output/ windows.dumpfiles --pid 1234

# Quiet mode (suppress progress output)
vol -q -f memory.raw windows.pslist

# Use a specific renderer (text, json, csv)
vol -r csv -f memory.raw windows.pslist > processes.csv
vol -r json -f memory.raw windows.pslist > processes.json

# Specify custom symbol path
vol -s /path/to/symbols/ -f memory.raw windows.info
```

## Windows Plugins — Process Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# List running processes (from PsActiveProcessHead linked list)
vol -f memory.raw windows.pslist

# Process tree (parent-child relationships)
vol -f memory.raw windows.pstree

# Scan for process objects in memory (finds hidden/unlinked processes)
vol -f memory.raw windows.psscan

# Command-line arguments for each process
vol -f memory.raw windows.cmdline

# Environment variables
vol -f memory.raw windows.envars

# Filter by PID
vol -f memory.raw windows.cmdline --pid 1234
```

## Windows Plugins — DLL and Module Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# List loaded DLLs for all processes
vol -f memory.raw windows.dlllist

# List DLLs for a specific process
vol -f memory.raw windows.dlllist --pid 1234

# Detect hidden/unlinked DLLs (compare three DLL lists)
vol -f memory.raw windows.malware.ldrmodules

# List loaded kernel modules (drivers)
vol -f memory.raw windows.modules

# Scan for driver objects
vol -f memory.raw windows.driverscan

# Scan for loaded modules
vol -f memory.raw windows.modscan
```

## Windows Plugins — Network

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# List network connections and listening ports
vol -f memory.raw windows.netscan

# Show network statistics
vol -f memory.raw windows.netstat
```

## Windows Plugins — Registry

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# List registry hives loaded in memory
vol -f memory.raw windows.registry.hivelist

# Print a specific registry key
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# List UserAssist entries (program execution tracking)
vol -f memory.raw windows.registry.userassist

# Dump cached credentials
vol -f memory.raw windows.registry.cachedump

# Dump password hashes from SAM
vol -f memory.raw windows.registry.hashdump

# Dump LSA secrets
vol -f memory.raw windows.registry.lsadump
```

## Windows Plugins — File and Handle Analysis

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# List open handles for all processes
vol -f memory.raw windows.handles

# Filter handles by type
vol -f memory.raw windows.handles --pid 1234

# Scan for file objects in memory
vol -f memory.raw windows.filescan

# Dump files from memory
vol -f memory.raw -o /output/ windows.dumpfiles --pid 1234

# List services
vol -f memory.raw windows.svcscan
```

## Windows Plugins — Malware Detection

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# Detect injected code (VAD regions with PAGE_EXECUTE_READWRITE)
vol -f memory.raw windows.malware.malfind

# Filter malfind to a specific PID
vol -f memory.raw windows.malware.malfind --pid 1234

# Detect hollowed processes
vol -f memory.raw windows.malware.hollowprocesses

# Check SSDT for hooks
vol -f memory.raw windows.ssdt

# Scan memory with YARA rules
vol -f memory.raw windows.vadyarascan --yara-file /path/to/rules.yar

# Detect process ghosting
vol -f memory.raw windows.malware.processghosting

# Cross-reference process lists to find hidden processes
vol -f memory.raw windows.malware.psxview
```

## Linux Plugins

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# Recover bash command history
vol -f memory.lime linux.bash

# List running processes
vol -f memory.lime linux.pslist

# Process tree
vol -f memory.lime linux.pstree

# List open files for each process
vol -f memory.lime linux.lsof

# List network connections
vol -f memory.lime linux.sockstat

# List loaded kernel modules
vol -f memory.lime linux.lsmod

# Check for hidden kernel modules
vol -f memory.lime linux.hidden_modules

# List ELF files mapped in memory
vol -f memory.lime linux.elfs

# List environment variables
vol -f memory.lime linux.envars

# Process capabilities
vol -f memory.lime linux.capabilities

# Show network interface information
vol -f memory.lime linux.ip.Addr

# Show system boot time
vol -f memory.lime linux.boottime

# Check system call table for hooks
vol -f memory.lime linux.check_syscall
```

## Extracting Artifacts

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# Dump a process executable
vol -f memory.raw -o /output/ windows.dumpfiles --pid 1234

# Dump all files associated with a process
vol -f memory.raw -o /output/ windows.dumpfiles --pid 1234

# Dump a specific file by virtual address (from filescan)
vol -f memory.raw -o /output/ windows.dumpfiles --virtaddr 0xfa80023456

# Write a memory layer to disk (full physical memory)
vol -f memory.raw layerwriter
```

## Symbol Tables

Volatility 3 requires symbol tables (ISF — Intermediate Symbol Format) to
parse kernel structures. For Windows, symbols are downloaded automatically
from Microsoft. For Linux, symbols must be generated from the target kernel.

```bash
# Volatility 3
# https://github.com/volatilityfoundation/volatility3

# Check available symbols
vol -f memory.raw isfinfo

# Linux: generate symbols from a running system
# Install dwarf2json from https://github.com/volatilityfoundation/dwarf2json
# Then generate ISF from the kernel's debug symbols
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > linux_symbols.json

# Place the ISF file in volatility3/symbols/linux/
```

## References

### Tools

- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- [dwarf2json](https://github.com/volatilityfoundation/dwarf2json)

### Further Reading

- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [The Art of Memory Forensics](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics-p-9781118825099)
