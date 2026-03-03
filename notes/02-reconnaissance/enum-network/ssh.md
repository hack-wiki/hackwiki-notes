% Filename: 02-reconnaissance/enum-network/ssh.md
% Display name: SSH Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# SSH Enumeration

## Overview

SSH runs on TCP 22 by default but is frequently moved to non-standard ports. Enumeration focuses on version detection, supported authentication methods, host key fingerprinting, and algorithm negotiation. SSH itself is rarely vulnerable, but version and configuration details reveal OS, patch level, and potential weaknesses in key exchange or cipher selection.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target SSH port
- `ssh`, `nmap`, or `nc` installed

## Enumeration Techniques

### Banner Grabbing

```bash
nc -nv <target> 22
```

Expected output:
```text
SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
```

The banner format is `SSH-<protocol>-<software> <comments>`. This reveals the SSH implementation (OpenSSH, Dropbear, libssh), version, and often the OS distribution and release.

Common banner patterns and what they reveal:

| Banner | Inference |
|--------|-----------|
| `OpenSSH_9.6p1 Ubuntu-3ubuntu13` | Ubuntu 24.04 (Noble) |
| `OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | Ubuntu 22.04 (Jammy) |
| `OpenSSH_7.4 CentOS` | CentOS 7 |
| `OpenSSH_8.0 FreeBSD-20211221` | FreeBSD |
| `dropbear_2022.83` | Embedded/IoT device |
| `libssh-0.9.6` | Library-based implementation |

OpenSSH version-to-OS mapping is well documented and one of the most reliable ways to fingerprint the target OS.

### Nmap Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 22 <target>
```

Expected output:
```text
22/tcp open  ssh  OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)
```

If SSH is on a non-standard port:

```bash
# Nmap
# https://nmap.org/
nmap -sV -p- --open <target> | grep ssh
```

### Authentication Method Enumeration

Discovering which authentication methods are enabled narrows the attack surface:

```bash
ssh -o PreferredAuthentications=none -o BatchMode=yes <target> 2>&1
```

Expected output:
```text
Permission denied (publickey,password,keyboard-interactive).
```

The parenthesized list shows all enabled authentication methods. Common methods:

| Method | Implication |
|--------|-------------|
| `publickey` | Key-based auth enabled — look for exposed private keys |
| `password` | Password auth enabled — brute-force/spraying viable |
| `keyboard-interactive` | Usually password-based, may include 2FA prompts |
| `gssapi-with-mic` | Kerberos authentication — Active Directory integrated |

If only `publickey` is listed, password attacks are not viable. If `gssapi-with-mic` is present, the host is likely domain-joined.

### Host Key Fingerprinting

```bash
# Retrieve all host key types and fingerprints
ssh-keyscan -t rsa,ecdsa,ed25519 <target> 2>/dev/null
```

Expected output:
```text
10.10.10.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB...
10.10.10.1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYT...
10.10.10.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

Host keys identify the server uniquely. If you see the same host key on multiple IPs, those hosts are either cloned, behind a load balancer, or share configuration — all useful for mapping infrastructure.

```bash
# Get SHA256 fingerprint for comparison
ssh-keyscan -t ed25519 <target> 2>/dev/null | ssh-keygen -lf -
```

### Algorithm Enumeration

```bash
# Nmap
# https://nmap.org/
nmap -p 22 --script ssh2-enum-algos <target>
```

Expected output (truncated):
```text
| ssh2-enum-algos:
|   kex_algorithms:
|     curve25519-sha256
|     diffie-hellman-group14-sha256
|   server_host_key_algorithms:
|     ssh-ed25519
|     ecdsa-sha2-nistp256
|     rsa-sha2-512
|   encryption_algorithms:
|     aes256-gcm@openssh.com
|     chacha20-poly1305@openssh.com
|     aes256-ctr
|   mac_algorithms:
|     hmac-sha2-256-etm@openssh.com
```

Weak algorithms to flag:
- Key exchange: `diffie-hellman-group1-sha1`, `diffie-hellman-group-exchange-sha1`
- Encryption: `3des-cbc`, `arcfour`, `blowfish-cbc`, any CBC mode cipher
- MAC: `hmac-md5`, `hmac-sha1`

The presence of weak algorithms doesn't mean they're in use — the client and server negotiate the strongest mutual algorithm. But their availability indicates outdated configuration.

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Retrieve host keys
nmap -p 22 --script ssh-hostkey <target>

# Retrieve host keys with full fingerprints
nmap -p 22 --script ssh-hostkey --script-args ssh_hostkey=full <target>

# Enumerate supported authentication methods
nmap -p 22 --script ssh-auth-methods <target>

# Brute-force SSH credentials
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt <target>
```

The `ssh-auth-methods` script enumerates allowed auth methods per user, which can differ from the global server setting. Testing with `--script-args ssh.user=root` reveals if root login is enabled.

```bash
# Nmap
# https://nmap.org/
# Check auth methods for specific user
nmap -p 22 --script ssh-auth-methods --script-args ssh.user=root <target>
```

### SSH Configuration Extraction (Post-Access)

If you gain filesystem access through another vector, SSH config files reveal valuable settings:

| File | Contains |
|------|----------|
| `/etc/ssh/sshd_config` | Server configuration — allowed users, auth methods, port |
| `~/.ssh/authorized_keys` | Public keys that can authenticate to this account |
| `~/.ssh/known_hosts` | Hosts this user has connected to (lateral movement targets) |
| `~/.ssh/id_rsa` / `id_ed25519` | Private keys — immediate access to other hosts |
| `~/.ssh/config` | SSH client config — saved hostnames, users, proxy settings |

Key directives to check in `sshd_config`:
- `PermitRootLogin` — if `yes`, root is a valid brute-force target
- `PasswordAuthentication` — if `no`, only key-based auth works
- `AllowUsers` / `AllowGroups` — restricts which users can SSH in
- `AuthorizedKeysFile` — custom location for authorized keys

## Post-Enumeration

With SSH details collected, prioritize:
- OS fingerprinting from banner version for targeted exploitation
- Password spraying if `password` or `keyboard-interactive` auth is enabled
- Searching for exposed private keys in other services (web directories, FTP, NFS, backups)
- Checking `known_hosts` files for lateral movement targets if filesystem access is obtained
- Weak algorithm findings for compliance reporting

## References

### Official Documentation

- [OpenSSH Release Notes](https://www.openssh.com/releasenotes.html)
- [OpenSSH Security](https://www.openssh.com/security.html)
- [Nmap ssh2-enum-algos NSE Script](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html)
- [Nmap ssh-hostkey NSE Script](https://nmap.org/nsedoc/scripts/ssh-hostkey.html)
- [Nmap ssh-auth-methods NSE Script](https://nmap.org/nsedoc/scripts/ssh-auth-methods.html)
- [RFC 4253 - SSH Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
