% Filename: 02-reconnaissance/enum-misc/vnc.md
% Display name: VNC Enumeration
% Last update: 2026-02-19
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# VNC Enumeration

## Overview

VNC (Virtual Network Computing) runs on TCP 5900+ by default (5900 for display :0, 5901 for :1, etc.). Enumeration targets version detection, authentication method identification, and unauthenticated access checks. VNC is frequently deployed with no authentication, weak passwords, or default configurations — especially on development servers, kiosks, and embedded systems.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target port 5900-5910
- Nmap or VNC client installed

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 5900-5910 <target>
```

Expected output:
```text
5900/tcp open  vnc     VNC (protocol 3.8)
5901/tcp open  vnc     VNC (protocol 3.8)
```

The protocol version reveals the RFB (Remote Framebuffer) protocol version, not the server software. Banner grab for more detail:

```bash
nc -nv <target> 5900
```

Expected output:
```text
(UNKNOWN) [10.10.10.50] 5900 (?) open
RFB 003.008
```

### Authentication Detection

```bash
# Nmap
# https://nmap.org/
# Check VNC authentication requirements
nmap -sV -p 5900 --script vnc-info <target>
```

Expected output (no authentication):
```text
| vnc-info:
|   Protocol version: 3.8
|   Security types:
|_    None
```

If security type is `None`, the server accepts connections without any password. Connect directly:

```bash
# TigerVNC (vncviewer)
# https://tigervnc.org/
vncviewer <target>::5900
```

Expected output for password-protected server:
```text
| vnc-info:
|   Protocol version: 3.8
|   Security types:
|     VNC Authentication (2)
|     Tight (16)
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Attempt VNC authentication with blank/default passwords
nmap -p 5900 --script vnc-brute <target>

# Get detailed VNC server title and resolution
nmap -p 5900 --script vnc-title <target>
```

Expected output from `vnc-title`:
```text
| vnc-title:
|   name: server01:1 (user01)
|_  resolution: 1920x1080
```

The window title often reveals the hostname and username of the active session.

### Metasploit Modules

```msf
# Metasploit Framework
# https://www.metasploit.com/
# VNC no-auth scanner (identifies servers with no password)
msf6 > use auxiliary/scanner/vnc/vnc_none_auth
msf6 > set RHOSTS <target>
msf6 > run

# VNC login scanner (brute-force)
msf6 > use auxiliary/scanner/vnc/vnc_login
msf6 > set RHOSTS <target>
msf6 > set PASS_FILE /usr/share/wordlists/metasploit/vnc_passwords.txt
msf6 > run
```

The `vnc_none_auth` scanner is fast and should be run first — it identifies servers accepting connections without any credentials.

### VNC Password File Locations

If you gain filesystem access to the VNC server (via other means), VNC password hashes are stored in predictable locations:

| Implementation | Password File |
|---------------|--------------|
| RealVNC | `~/.vnc/passwd` |
| TightVNC | `~/.vnc/passwd` |
| TigerVNC | `~/.vnc/passwd` |
| x11vnc | `~/.vnc/passwd` or `-passwdfile` argument |
| UltraVNC (Windows) | `C:\Program Files\UltraVNC\ultravnc.ini` |
| TightVNC (Windows) | Registry: `HKLM\Software\TightVNC\Server\Password` |

VNC passwords are DES-encrypted with a fixed key and truncated to 8 characters maximum. They are trivially reversible:

```msf
# Metasploit Framework
# https://www.metasploit.com/
# Decrypt a VNC password file
msf6 > irb
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
>> require 'rex/proto/rfb'
>> Rex::Proto::RFB::Cipher.decrypt(["YOUR_HEX_HERE"].pack('H*'), fixedkey)
```

Or use a dedicated tool:

```bash
# vncpwd
# https://github.com/jeroennijhof/vncpwd
vncpwd /path/to/passwd
```

Note: `vncpwd` is not installed by default on Kali. Install from source:

```bash
git clone https://github.com/jeroennijhof/vncpwd.git
cd vncpwd
make
```

### Common VNC Ports

VNC uses display-based port numbering:

| Display | Port | Notes |
|---------|------|-------|
| :0 | 5900 | Default display |
| :1 | 5901 | Second display |
| :2 | 5902 | Third display |
| HTTP viewer | 5800 | Java-based web VNC client (if enabled) |

Some implementations run on non-standard ports. Service detection handles this:

```bash
# Nmap
# https://nmap.org/
nmap -sV -p- --open <target> 2>/dev/null | grep vnc
```

## Post-Enumeration

With VNC access confirmed, prioritize:
- Unauthenticated VNC servers provide immediate desktop-level access — screenshot and document
- Active sessions may reveal logged-in user credentials, open applications, and sensitive data on screen
- VNC server configuration may reveal the running user's privilege level
- Password reuse — VNC passwords are often reused across services

## References

### Official Documentation

- [Nmap vnc-info NSE Script](https://nmap.org/nsedoc/scripts/vnc-info.html)
- [Nmap vnc-brute NSE Script](https://nmap.org/nsedoc/scripts/vnc-brute.html)
- [RFB Protocol Specification (RFC 6143)](https://datatracker.ietf.org/doc/html/rfc6143)
- [vncpwd - VNC Password Decryptor (GitHub)](https://github.com/jeroennijhof/vncpwd)

### Pentest Guides & Tutorials

- [Hacking Articles - VNC Penetration Testing](https://www.hackingarticles.in/vnc-penetration-testing/)
- [miloserdov.org - VNC Security Audit](https://miloserdov.org/?p=4854)

### Password Recovery References

- [Stored Password Decryption Techniques (frizb GitHub)](https://github.com/frizb/PasswordDecrypts)
- [XenArmor - How to Recover Remote Desktop Password from TightVNC](https://xenarmor.com/how-to-recover-remote-desktop-password-from-tightvnc/)
- [RSM War Room - Retrieving Credentials from Configuration Files](https://web.archive.org/web/20240616191007/https://warroom.rsmus.com/retrieving-credentials-from-configuration-files/)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
