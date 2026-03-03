% Filename: 02-reconnaissance/enum-network/rsync.md
% Display name: Rsync Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# Rsync Enumeration

## Overview

Rsync runs on TCP 873 when operating as a daemon. Enumeration focuses on listing accessible modules (shared directories), testing for anonymous access, and extracting files. Misconfigured rsync daemons frequently expose sensitive data — backup directories, configuration files, web roots, and credential stores — without authentication.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 873
- `rsync` client installed

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 873 <target>
```

Expected output:
```text
873/tcp open  rsync  (protocol version 31)
```

### Banner Grabbing

```bash
nc -nv <target> 873
```

Expected output:
```text
@RSYNCD: 31.0
```

The protocol version number is returned immediately on connection. Type `#list` followed by Enter to request available modules:

```text
@RSYNCD: 31.0
#list
backups        	Server Backups
www            	Web Root
configs        	Configuration Files
@RSYNCD: EXIT
```

### Module Listing

The primary enumeration step — list all accessible rsync modules:

```bash
rsync --list-only rsync://<target>/
```

Expected output:
```text
backups        	Server Backups
www            	Web Root
configs        	Configuration Files
```

Each module is a shared directory. Modules may be public (no authentication) or require a username and password defined in the rsync daemon configuration.

### Nmap NSE Script

```bash
# Nmap
# https://nmap.org/
nmap -p 873 --script rsync-list-modules <target>
```

Expected output:
```text
| rsync-list-modules:
|   backups       	Server Backups
|   www           	Web Root
|_  configs       	Configuration Files
```

### Anonymous File Listing

Test each discovered module for anonymous read access:

```bash
# List files in a module (recursive)
rsync --list-only rsync://<target>/backups/

# List with full details (permissions, sizes, dates)
rsync -av --list-only rsync://<target>/backups/
```

If the listing succeeds without prompting for a password, the module allows anonymous read access.

### File Download

```bash
# Download entire module contents
rsync -av rsync://<target>/backups/ ./loot/backups/

# Download a specific file
rsync -av rsync://<target>/configs/sshd_config ./loot/

# Download with progress
rsync -av --progress rsync://<target>/www/ ./loot/www/
```

### Authenticated Access

If a module requires authentication, rsync prompts for a password:

```bash
rsync --list-only rsync://admin@<target>/backups/
# Password: 
```

Credentials are defined in the rsync daemon's secrets file (typically `/etc/rsyncd.secrets`). Default or weak credentials are worth testing if the username is known.

### Write Access Testing

Some modules may allow unauthenticated uploads:

```bash
# Test upload capability
echo "test" > test.txt
rsync -av test.txt rsync://<target>/www/
```

Write access to a web root module is a direct path to code execution via webshell upload — the same impact as writable FTP serving a web directory.

### Rsync Daemon Configuration

If you gain filesystem access through another vector, the rsync configuration reveals all modules, their paths, access controls, and credential files:

| File | Contains |
|------|----------|
| `/etc/rsyncd.conf` | Module definitions, paths, auth settings |
| `/etc/rsyncd.secrets` | Username:password pairs in plaintext |

Key directives in `rsyncd.conf`:
- `path` — filesystem path the module exposes
- `read only` — if `false`, uploads are allowed
- `auth users` — if absent, anonymous access is granted
- `secrets file` — path to the credentials file
- `hosts allow` / `hosts deny` — IP-based access control

## Post-Enumeration

With rsync access confirmed, prioritize:
- Downloading all accessible files for credential and configuration review
- Checking for backup archives containing database dumps, SSH keys, or application configs
- Testing write access for webshell placement if the module maps to a web server docroot
- Extracting `/etc/rsyncd.secrets` if filesystem access is obtained through another vector
- Using discovered credentials against other services

## References

### Official Documentation

- [Nmap rsync-list-modules NSE Script](https://nmap.org/nsedoc/scripts/rsync-list-modules.html)
- [rsync(1) Man Page](https://download.samba.org/pub/rsync/rsync.1)
- [rsyncd.conf(5) Man Page](https://download.samba.org/pub/rsync/rsyncd.conf.5)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
