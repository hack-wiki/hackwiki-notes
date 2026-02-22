% Filename: 02-reconnaissance/enum-network/ftp.md
% Display name: FTP Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# FTP Enumeration

## Overview

FTP runs on TCP 21 (control) and TCP 20 (active mode data). Enumeration focuses on version detection, anonymous access, directory listing, and file extraction. FTP transmits credentials in plaintext — even authenticated sessions on unencrypted FTP are valuable for credential capture.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target FTP port
- FTP client or netcat installed
- Nmap for scripted enumeration

## Enumeration Techniques

### Banner Grabbing

```bash
nc -nv <target> 21
```

Expected output:
```text
220 (vsFTPd 3.0.5)
```

The banner typically reveals the FTP server software and version. Common servers: vsFTPd, ProFTPD, Pure-FTPd, FileZilla Server, Microsoft FTPD (IIS).

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 21 <target>
```

If the banner has been customized or stripped, Nmap's service probes can still fingerprint the software through protocol behavior.

### Anonymous Login Check

Anonymous FTP allows login with the username `anonymous` and any password (conventionally an email address):

```bash
ftp <target>
# Username: anonymous
# Password: anything@test.com
```

If login succeeds:

```bash
# List files and directories
ls -la

# Check current directory
pwd

# Switch to binary mode before downloading
binary

# Download a file
get <filename>

# Download all files in current directory
mget *

# Navigate directories
cd <directory>
```

Always check for writable directories — the ability to upload files to an FTP server (especially one serving web content) can lead to direct code execution:

```bash
# Test write access
put test.txt
```

### Recursive Directory Listing

Manually browsing directories is slow. Use `wget` to mirror the entire FTP tree:

```bash
wget -r --no-passive-ftp ftp://anonymous:pass@<target>/
```

Or with `curl`:

```bash
curl -s ftp://anonymous:pass@<target>/ --list-only
```

For a quick recursive listing without downloading files:

```bash
ftp <target>
# After login:
ls -R
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Check for anonymous login
nmap -p 21 --script ftp-anon <target>
```

Expected output when anonymous is enabled:
```text
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 ftp      ftp          4096 Jan 01 12:00 pub
|_-rw-r--r--    1 ftp      ftp           170 Jan 01 12:00 welcome.msg
```

```bash
# Nmap
# https://nmap.org/
# Identify server OS via SYST command
nmap -p 21 --script ftp-syst <target>
```

Expected output:
```text
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.10.1
|      Logged in as ftp
|      TYPE: ASCII
|      Session timeout in seconds is 300
|_End of status
```

```bash
# Nmap
# https://nmap.org/
# Test for FTP bounce attack
nmap -p 21 --script ftp-bounce <target>

# Brute-force FTP credentials
nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt <target>

# Check for known vsFTPd 2.3.4 backdoor
nmap -p 21 --script ftp-vsftpd-backdoor <target>

# Check for ProFTPD mod_copy command execution
nmap -p 21 --script ftp-proftpd-backdoor <target>
```

The vsFTPd 2.3.4 backdoor (CVE-2011-2523) opens a shell on port 6200 when a username containing `:)` is sent. Still found on legacy systems and CTF environments. The ProFTPD `mod_copy` module allows unauthenticated file copy operations on the server.

### FTP Bounce Scanning

FTP bounce attacks use the PORT command to make the FTP server connect to a third-party host. This can be used to port scan internal hosts through the FTP server:

```bash
# Nmap
# https://nmap.org/
nmap -Pn -b anonymous@<ftp-server> <internal-target>
```

This technique is largely mitigated on modern FTP servers, but worth testing on older deployments — if it works, you can pivot scans through the FTP server into networks you cannot reach directly.

### FTPS (FTP over TLS)

Some FTP servers support explicit TLS via the `AUTH TLS` command on port 21, or implicit TLS on port 990:

```bash
# Explicit TLS (STARTTLS on port 21)
openssl s_client -starttls ftp -connect <target>:21

# Implicit TLS (port 990)
openssl s_client -connect <target>:990
```

Certificate inspection can reveal internal hostnames, organization names, and CA hierarchy — the same technique used for SMTP STARTTLS.

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 990 <target>
nmap -p 21 --script ssl-cert,ssl-enum-ciphers <target>
```

### FTP Configuration Files

When you have filesystem access (via anonymous FTP or post-exploitation), check for FTP server configuration files that may contain credentials or reveal directory mappings:

| Server | Config Path |
|--------|-------------|
| vsFTPd | `/etc/vsftpd.conf`, `/etc/vsftpd/vsftpd.conf` |
| ProFTPD | `/etc/proftpd/proftpd.conf`, `/etc/proftpd.conf` |
| Pure-FTPd | `/etc/pure-ftpd/pure-ftpd.conf` |
| FileZilla | `C:\Program Files\FileZilla Server\FileZilla Server.xml` |

Key configuration directives to look for:
- `anonymous_enable` / `anon_upload_enable` (vsFTPd) — anonymous access and write permissions
- `chroot_local_user` (vsFTPd) — if disabled, users can navigate outside their home directory
- `DefaultRoot` (ProFTPD) — equivalent chroot setting
- User lists and password hashes in server-specific user databases

### FTP Response Codes

| Code | Meaning | Enumeration Implication |
|------|---------|------------------------|
| 220  | Service ready | Server is accepting connections |
| 230  | Login successful | Valid credentials or anonymous access confirmed |
| 331  | Username OK, need password | User exists (useful for user enumeration) |
| 332  | Need account for login | Account required — rare |
| 421  | Service not available | Server is rejecting connections |
| 530  | Not logged in | Authentication failed |
| 550  | Action not taken | File not found or permission denied |

Code 331 is significant for user enumeration — the server confirms the username exists before requesting a password. Some servers return 530 immediately for invalid usernames, creating a timing or response differential.

## Post-Enumeration

With FTP access confirmed, prioritize:
- Downloading all accessible files for credential and configuration review
- Testing upload capability for webshell placement if FTP root overlaps with a web server docroot
- Checking for sensitive files: backups (`.bak`, `.old`, `.tar.gz`), credentials (`.htpasswd`, `web.config`), database dumps
- Using discovered credentials against other services (SSH, web applications, databases)
- Investigating FTP bounce for internal network scanning

## References

### Official Documentation

- [Nmap ftp-anon NSE Script](https://nmap.org/nsedoc/scripts/ftp-anon.html)
- [Nmap ftp-bounce NSE Script](https://nmap.org/nsedoc/scripts/ftp-bounce.html)
- [Nmap ftp-syst NSE Script](https://nmap.org/nsedoc/scripts/ftp-syst.html)
- [Nmap ftp-vsftpd-backdoor NSE Script](https://nmap.org/nsedoc/scripts/ftp-vsftpd-backdoor.html)
- [Nmap ftp-brute NSE Script](https://nmap.org/nsedoc/scripts/ftp-brute.html)
- [RFC 959 - File Transfer Protocol](https://datatracker.ietf.org/doc/html/rfc959)

### CVE References

- [CVE-2011-2523 - vsFTPd 2.3.4 Backdoor](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
