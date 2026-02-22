% Filename: 01-fundamentals/linux-basics/filesystem.md
% Display name: Filesystem Hierarchy
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Filesystem Hierarchy

## Overview

Linux follows the Filesystem Hierarchy Standard (FHS). Every file and directory lives under a single root `/`. Understanding the directory structure matters for penetration testing — knowing where credentials are stored, where logs live, where binaries execute from, and where configuration files control service behavior determines how fast you can enumerate and escalate on a compromised system.

## Key Concepts

### Root Directory Structure

| Directory | Purpose | Security Relevance |
|-----------|---------|-------------------|
| `/` | Root of the entire filesystem | Everything starts here |
| `/bin` | Essential user binaries | Basic commands (`ls`, `cat`, `cp`) — often symlinked to `/usr/bin` on modern distros |
| `/sbin` | Essential system binaries | Admin commands (`iptables`, `fdisk`, `mount`) — often symlinked to `/usr/sbin` |
| `/etc` | System configuration files | Credentials, service configs, network settings — primary target for enumeration |
| `/home` | User home directories | Personal files, SSH keys, shell history, application data |
| `/root` | Root user's home directory | Restricted — contains root's SSH keys, history, and configs |
| `/var` | Variable data (logs, spools, caches) | Logs, web roots, databases, mail — rich in intelligence |
| `/tmp` | Temporary files (world-writable) | Writable by all users — common staging area for exploits |
| `/dev` | Device files | Pseudo-devices: `/dev/null`, `/dev/urandom`, `/dev/tcp` (Bash) |
| `/proc` | Process and kernel info (virtual) | Live kernel data, process details, system configuration |
| `/sys` | Kernel and hardware info (virtual) | Device and driver information |
| `/opt` | Optional/third-party software | Custom installations, security tools |
| `/usr` | User programs and data | Binaries, libraries, documentation, shared data |
| `/mnt` | Temporary mount points | Manually mounted filesystems |
| `/media` | Removable media mount points | USB drives, CD-ROMs |
| `/boot` | Boot loader files | Kernel images, GRUB configuration |
| `/lib` | Essential shared libraries | Libraries for `/bin` and `/sbin` — often symlinked to `/usr/lib` |
| `/run` | Runtime data since last boot | PID files, sockets, transient state |
| `/srv` | Service data | Data served by services (web, FTP) |

### Security-Critical Paths

### Credentials and Authentication

```bash
/etc/passwd          # User accounts (readable by all)
/etc/shadow          # Password hashes (root-only)
/etc/group           # Group definitions
/etc/gshadow         # Group passwords (root-only)
/etc/sudoers         # Sudo configuration
/etc/sudoers.d/      # Additional sudo rules (drop-in directory)
/etc/login.defs      # Login defaults (password aging, UID ranges)
```

`/etc/passwd` is world-readable and contains usernames, UIDs, GIDs, home directories, and login shells. Password hashes have been moved to `/etc/shadow` (readable only by root) on all modern systems. The password field in `/etc/passwd` shows `x` when shadow passwords are in use.

```bash
# Format: username:x:UID:GID:comment:home:shell
root:x:0:0:root:/root:/bin/bash
```

```bash
# /etc/shadow format: username:hash:last_changed:min:max:warn:inactive:expire:reserved
root:$6$salt$hash...:19000:0:99999:7:::
```

The hash prefix identifies the algorithm: `$1$` is MD5, `$5$` is SHA-256, `$6$` is SHA-512, `$y$` is yescrypt (default on recent Debian/Ubuntu), `$2b$`/`$2y$` is bcrypt (OpenBSD default, appears in web application database dumps).

### SSH

```bash
~/.ssh/               # User SSH directory
~/.ssh/authorized_keys  # Public keys allowed to log in as this user
~/.ssh/id_rsa         # Private key (RSA)
~/.ssh/id_ed25519     # Private key (Ed25519)
~/.ssh/known_hosts    # Previously connected hosts
~/.ssh/config         # Client configuration (aliases, proxy settings)
/etc/ssh/sshd_config  # SSH server configuration
/etc/ssh/ssh_host_*   # Server host keys
```

Finding a readable private key (`id_rsa`, `id_ed25519`) is often an immediate path to lateral movement. Check every user's `~/.ssh/` directory during post-exploitation.

### Network Configuration

```bash
/etc/hostname         # System hostname
/etc/hosts            # Static hostname-to-IP mappings
/etc/resolv.conf      # DNS resolver configuration
/etc/network/         # Network interface config (Debian/Ubuntu)
/etc/netplan/         # Network config (Ubuntu 18.04+)
/etc/sysconfig/network-scripts/  # Network config (RHEL/CentOS)
```

### Service Configuration

```bash
/etc/apache2/         # Apache configuration (Debian/Ubuntu)
/etc/httpd/           # Apache configuration (RHEL/CentOS)
/etc/nginx/           # Nginx configuration
/etc/mysql/           # MySQL/MariaDB configuration
/etc/postgresql/      # PostgreSQL configuration
/etc/crontab          # System-wide cron jobs
/etc/cron.d/          # Cron job drop-in directory
/etc/cron.daily/      # Daily cron scripts
/etc/systemd/system/  # Custom systemd unit files
```

Web server configs reveal document roots, virtual hosts, proxy rules, and sometimes credentials in plain text. Database configs may contain authentication credentials.

### Logs

```bash
/var/log/syslog       # System log (Debian/Ubuntu)
/var/log/messages     # System log (RHEL/CentOS)
/var/log/auth.log     # Authentication log (Debian/Ubuntu)
/var/log/secure       # Authentication log (RHEL/CentOS)
/var/log/apache2/     # Apache logs (Debian/Ubuntu)
/var/log/httpd/       # Apache logs (RHEL/CentOS)
/var/log/nginx/       # Nginx logs
/var/log/mysql/       # MySQL logs
/var/log/lastlog      # Last login for all users (binary, read with lastlog)
/var/log/wtmp         # Login history (binary, read with last)
/var/log/btmp         # Failed login attempts (binary, read with lastb)
```

`auth.log` / `secure` is the first file to check when investigating brute-force attempts or unauthorized access.

### Web Application Paths

```bash
/var/www/html/        # Default Apache document root (Debian/Ubuntu)
/var/www/             # Common web root
/srv/www/             # Alternative web root
/opt/lampp/htdocs/    # XAMPP document root
```

### The /proc Filesystem

`/proc` is a virtual filesystem that exposes kernel and process information as files. Nothing is written to disk — it is generated dynamically by the kernel.

```bash
/proc/version         # Kernel version string
/proc/cmdline         # Kernel boot parameters
/proc/cpuinfo         # CPU details
/proc/meminfo         # Memory statistics
/proc/net/tcp         # Active TCP connections (hex-encoded)
/proc/net/udp         # Active UDP connections
/proc/mounts          # Mounted filesystems
/proc/self/           # Symlink to current process's /proc entry
/proc/[PID]/          # Per-process directory
/proc/[PID]/cmdline   # Command that started the process
/proc/[PID]/environ   # Environment variables (may contain secrets)
/proc/[PID]/fd/       # Open file descriptors
/proc/[PID]/maps      # Memory mappings
/proc/[PID]/status    # Process status (UID, GID, state)
```

`/proc/[PID]/environ` can contain credentials passed as environment variables — database passwords, API keys, tokens. Readable only by the process owner or root.

### Temporary Directories

```bash
/tmp                  # World-writable, cleared on reboot (most distros)
/var/tmp              # World-writable, survives reboots
/dev/shm              # Shared memory (tmpfs, world-writable, RAM-backed)
```

All three are world-writable. Attackers use them to stage payloads, compile exploits, and store tools. `/dev/shm` is RAM-based, so nothing touches disk — useful for avoiding disk-based detection. Note that some systems mount `/tmp` and `/dev/shm` with `noexec`, which prevents direct execution of binaries placed there.

## Practical Examples

### Quick Enumeration After Initial Access

```bash
# What system am I on?
cat /etc/os-release
uname -a

# Who am I?
id
cat /etc/passwd | grep -v nologin | grep -v false

# What's listening?
ss -tlnp

# Any credentials in configs?
grep -r "password" /etc/ 2>/dev/null | grep -v "^#"

# Readable SSH keys?
find /home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null

# Cron jobs running as root?
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/

# SUID binaries?
find / -perm -4000 -type f 2>/dev/null

# World-writable files owned by root?
find / -writable -type f -user root 2>/dev/null
```

## References

### Official Documentation

- [Filesystem Hierarchy Standard (FHS) Specification](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html)
- [The Linux man-pages Project — proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)
