% Filename: 11-digital-forensics/windows-forensics/artifacts.md
% Display name: Windows Artifacts
% Last update: 2026-02-11
% Authors: @TristanInSec

# Windows Artifacts

## Overview

Beyond event logs and the registry, Windows systems contain numerous artifacts
that record program execution, file access, user activity, and system state.
These artifacts persist across reboots and often survive attempts at cleanup.
This file covers prefetch, shimcache, amcache, SRUM, jump lists, LNK files,
and other execution and activity artifacts.

## Prefetch

Windows Prefetch stores information about recently executed programs to speed
up subsequent launches. Each executable creates a .pf file in
`C:\Windows\Prefetch\`.

```text
Location: C:\Windows\Prefetch\
Format:   <EXECUTABLE_NAME>-<HASH>.pf
Enabled:  Windows client editions (disabled by default on Server)

Prefetch records:
  - Executable name and path
  - Run count (number of times executed)
  - Last 8 execution timestamps (Windows 8+, 1 on Windows 7)
  - DLLs and files loaded during execution
  - Volumes accessed
```

**Forensic Value:**

| Data | Use |
|---|---|
| Executable name | Confirms a program was executed |
| Last run time | When the program last ran |
| Run count | How many times it ran |
| Referenced files | What DLLs/files the program loaded |
| Volume info | Which drives were accessed |

**Prefetch File Naming:**

The hash in the filename is based on the executable path and command-line
arguments (on some Windows versions). Different paths to the same executable
produce different prefetch files.

## ShimCache (AppCompatCache)

ShimCache records executables that Windows checked for compatibility during
execution. It is stored in the registry and persists across reboots.

```text
Location: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
Written:  On system shutdown (not real-time)

ShimCache records:
  - File path
  - File size
  - Last modified timestamp ($STANDARD_INFORMATION)
  - Execution flag (Windows 7/8 only, not reliable on Windows 10+)
  - Cache entry position (most recent entries at the top)
```

```bash
# RegRipper
# https://github.com/keydet89/RegRipper3.0

# Extract ShimCache from SYSTEM hive
regripper -r /evidence/config/SYSTEM -p shimcache
```

**Forensic Value:**

ShimCache proves a file existed on disk with a specific path and timestamp.
On Windows 7/8, the execution flag indicates whether the file was run.
On Windows 10+, presence in ShimCache only means Windows checked the file,
not necessarily that it executed.

## Amcache

Amcache tracks application installations and execution with rich metadata
including file hashes.

```text
Location: C:\Windows\appcompat\Programs\Amcache.hve
Format:   Registry hive

Amcache records:
  - File path
  - SHA-1 hash of the file
  - File size
  - Compile timestamp (for PE files)
  - Link timestamp
  - Publisher / product information
  - Installation source
```

```bash
# RegRipper
# https://github.com/keydet89/RegRipper3.0

# Extract Amcache data
regripper -r /evidence/Amcache.hve -a

# Volatility (from memory)
vol -f memory.raw windows.amcache
```

**Forensic Value:**

Amcache is especially valuable because it records the SHA-1 hash of executed
files. Even if the original file is deleted, the hash remains in Amcache,
allowing identification via VirusTotal or other hash databases.

## SRUM (System Resource Usage Monitor)

SRUM tracks application resource usage — network bytes sent/received, CPU
time, memory usage — per application and per user.

```text
Location: C:\Windows\System32\sru\SRUDB.dat
Format:   ESE database (Extensible Storage Engine)

SRUM records (per application per hour):
  - Application name / executable path
  - User SID
  - Bytes sent and received (per network interface)
  - Foreground/background CPU cycles
  - Memory usage
  - Timestamp (hourly aggregations)
```

**Forensic Value:**

SRUM reveals network activity per application, including data volumes. This
is critical for detecting data exfiltration — an application that sent
gigabytes of data to the network is clearly visible in SRUM even without
packet captures.

## Jump Lists

Jump Lists record recently and frequently accessed files per application.
They are Windows shortcuts stored in a structured format.

```text
Location:
  Recent: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
  Pinned: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\

Format: OLE Compound Files (AutomaticDestinations-ms)

Jump List records:
  - Target file path
  - Target file timestamps (MAC)
  - Application that accessed the file (encoded in filename)
  - Access count and timestamps
  - Volume name and serial number
```

**Forensic Value:**

Jump Lists persist even after the target file is deleted. If an attacker
accessed sensitive documents using Explorer, Word, or other applications,
Jump Lists record which files were opened and when.

## LNK (Shortcut) Files

Windows creates LNK files when files are opened, providing rich metadata
about the target file and the system that created the shortcut.

```text
Location:
  C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\
  Desktop, Start Menu, and other locations

LNK file metadata:
  - Target file path (local and network)
  - Target file timestamps (MAC)
  - Target file size
  - Volume name, type, and serial number
  - MAC address of the creating machine (in some cases)
  - NetBIOS name (for network targets)
```

**Forensic Value:**

LNK files record access to files — including files on network shares. The
volume serial number and MAC address can be used to identify external USB
drives or network locations where files were accessed.

## Shellbags

Shellbags record Explorer folder browsing activity, including folder paths,
view settings, and timestamps.

```text
Location:
  NTUSER.DAT: HKU\<SID>\Software\Microsoft\Windows\Shell\BagMRU
  UsrClass.dat: HKU\<SID>_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU

Shellbag records:
  - Folder path (including network shares, ZIP files, FTP sites)
  - Folder access timestamps
  - View settings (icon size, sort order)
```

**Forensic Value:**

Shellbags prove a user browsed a specific folder — even if the folder has
since been deleted. This includes network shares, USB drives, and remote
paths. Shellbags persist even after the user clears their recent files.

## Browser Artifacts

```text
Chrome:
  History:    C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History
  Downloads:  Same SQLite database, "downloads" table
  Cookies:    C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies
  Cache:      C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cache\

Firefox:
  History:    C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\places.sqlite
  Downloads:  Same SQLite database
  Cookies:    C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\cookies.sqlite

Edge (Chromium):
  History:    C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\History

All browser databases are SQLite and can be queried with sqlite3.
```

## Recycle Bin

```text
Location: C:\$Recycle.Bin\<SID>\
Files:
  $I<id> — metadata file (original path, deletion time, file size)
  $R<id> — actual file content

The $I file contains:
  - Original file path
  - Deletion timestamp
  - Original file size
```

## Artifact Summary Table

| Artifact | Evidence Type | Persists After Deletion |
|---|---|---|
| Prefetch | Program execution, timestamps, loaded files | Yes (until .pf deleted) |
| ShimCache | File existence, path, timestamp | Yes (in registry) |
| Amcache | Execution, SHA-1 hash, metadata | Yes (in registry hive) |
| SRUM | Network usage per app, CPU/memory | Yes (ESE database) |
| Jump Lists | File access per application | Yes (until cleared) |
| LNK files | File access, target metadata | Yes (until deleted) |
| Shellbags | Folder browsing history | Yes (in registry) |
| Browser history | Web activity, downloads | Until cleared |
| Recycle Bin | Deleted file content and metadata | Until bin emptied |

## References

### Tools

- [RegRipper](https://github.com/keydet89/RegRipper3.0)

### Further Reading

- [SANS Windows Forensic Analysis Poster](https://www.sans.org/posters/windows-forensic-analysis/)
