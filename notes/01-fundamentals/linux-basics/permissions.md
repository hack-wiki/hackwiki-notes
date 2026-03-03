% Filename: 01-fundamentals/linux-basics/permissions.md
% Display name: Permissions
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Permissions

## Overview

Linux file permissions control who can read, write, and execute files and directories. The permissions model is the foundation of Linux security — and its misconfigurations are one of the most common paths to privilege escalation. SUID binaries, world-writable scripts executed by root, and misconfigured sudoers entries are staples of Linux privilege escalation.

## Key Concepts

### Permission Basics

Every file and directory has three permission sets applied to three categories of users:

| Category | Symbol | Description |
|----------|--------|-------------|
| Owner (user) | `u` | The user who owns the file |
| Group | `g` | Members of the file's group |
| Others | `o` | Everyone else |

Each category has three permission types:

| Permission | Symbol | On Files | On Directories |
|------------|--------|----------|----------------|
| Read | `r` (4) | View contents | List contents |
| Write | `w` (2) | Modify contents | Create/delete files inside |
| Execute | `x` (1) | Run as program | Enter directory (`cd`) |

### Reading Permissions

```bash
ls -la /etc/passwd
```

Output:
```text
-rw-r--r-- 1 root root 2847 Jan 15 10:30 /etc/passwd
```

Breaking down `-rw-r--r--`:

| Position | Characters | Meaning |
|----------|-----------|---------|
| 1 | `-` | File type: `-` regular, `d` directory, `l` symlink, `c` char device, `b` block device |
| 2-4 | `rw-` | Owner: read + write, no execute |
| 5-7 | `r--` | Group: read only |
| 8-10 | `r--` | Others: read only |

The two fields after the permission string are owner (`root`) and group (`root`).

### Numeric (Octal) Notation

Permissions map to numbers: read = 4, write = 2, execute = 1. Add them per category.

| Octal | Binary | Permission |
|-------|--------|------------|
| 0 | `---` | None |
| 1 | `--x` | Execute only |
| 2 | `-w-` | Write only |
| 3 | `-wx` | Write + execute |
| 4 | `r--` | Read only |
| 5 | `r-x` | Read + execute |
| 6 | `rw-` | Read + write |
| 7 | `rwx` | Read + write + execute |

Common permission sets:

| Octal | Symbolic | Typical Use |
|-------|----------|-------------|
| 644 | `rw-r--r--` | Regular files (owner writes, everyone reads) |
| 755 | `rwxr-xr-x` | Executables and directories |
| 600 | `rw-------` | Private files (SSH keys, configs with credentials) |
| 700 | `rwx------` | Private directories |
| 777 | `rwxrwxrwx` | World-writable (security risk) |
| 4755 | `rwsr-xr-x` | SUID executable |

### Changing Permissions

```bash
# chmod — change file mode
chmod 644 file.txt                  # Set exact permissions (octal)
chmod 755 script.sh                 # Owner rwx, group/others rx

# Symbolic mode
chmod u+x script.sh                # Add execute for owner
chmod g-w file.txt                 # Remove write for group
chmod o-rwx file.txt               # Remove all permissions for others
chmod a+r file.txt                 # Add read for all (a = all)
chmod u+x,g-w,o-rwx file.txt      # Multiple changes

# Recursive
chmod -R 755 directory/            # Apply to directory and all contents
```

### Changing Ownership

```bash
# chown — change owner and group
chown user file.txt                # Change owner
chown user:group file.txt          # Change owner and group
chown :group file.txt              # Change group only
chown -R user:group directory/     # Recursive

# chgrp — change group only
chgrp developers project/
```

### Special Permissions

### SUID (Set User ID) — Octal 4000

When set on an executable, it runs with the file owner's effective UID (EUID) regardless of who executes it. The real UID (RUID) remains the calling user's. If a SUID binary is owned by root, it runs as root. Note: the Linux kernel ignores the SUID bit on interpreted scripts (shebangs) — only compiled binaries honour it.

```bash
# Identify SUID files
find / -perm -4000 -type f 2>/dev/null

# Example: /usr/bin/passwd has SUID set
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root 68208 ... /usr/bin/passwd
```

The `s` in the owner execute position indicates SUID. `/usr/bin/passwd` needs SUID to modify `/etc/shadow`, which is only writable by root.

SUID binaries are the first thing to check during privilege escalation. Resources like GTFOBins document which SUID binaries can be abused to gain root access.

```bash
# Set SUID
chmod 4755 binary
chmod u+s binary

# Remove SUID
chmod 0755 binary
chmod u-s binary
```

### SGID (Set Group ID) — Octal 2000

On executables: runs with the file's group privileges. On directories: new files created inside inherit the directory's group (instead of the creator's primary group).

```bash
# Identify SGID files
find / -perm -2000 -type f 2>/dev/null

# SGID on directory — new files inherit group
ls -la /opt/shared/
# drwxrwsr-x 2 root developers 4096 ... /opt/shared/
```

The `s` in the group execute position indicates SGID.

```bash
# Set SGID
chmod 2755 directory/
chmod g+s directory/
```

### Sticky Bit — Octal 1000

On directories: only the file owner (or root) can delete files inside, even if the directory is world-writable. `/tmp` uses this to prevent users from deleting each other's files.

```bash
ls -la / | grep tmp
# drwxrwxrwt  15 root root  ... tmp
```

The `t` in the others execute position indicates the sticky bit.

```bash
# Set sticky bit
chmod 1777 directory/
chmod +t directory/
```

### Linux Capabilities

Capabilities fragment root privileges into granular units, allowing binaries to perform specific privileged operations without full root. A binary with elevated capabilities is a privilege escalation vector just like SUID root.

```bash
# List capabilities on all binaries (primary privesc check)
getcap -r / 2>/dev/null

# View capabilities on a specific binary
getcap /usr/bin/python3

# Set a capability
sudo setcap cap_net_bind_service+ep /usr/bin/python3

# Remove all capabilities
sudo setcap -r /usr/bin/python3
```

**High-value capabilities for privilege escalation:**

| Capability | Abuse Potential |
|------------|----------------|
| `cap_setuid+ep` | Call `setuid(0)` → root shell |
| `cap_sys_ptrace+ep` | Inject into any process |
| `cap_dac_read_search+ep` | Read any file (bypass ACLs) |
| `cap_net_raw+ep` | Craft raw packets, sniff traffic |

### umask

`umask` defines the default permission mask for newly created files and directories. It works by bitwise AND with the complement of the mask: `effective_perms = default_mode & (~umask)`. For common values the result is the same as subtraction, but they are not equivalent for arbitrary masks.

```bash
# View current umask
umask          # Octal format (e.g., 0022)
umask -S       # Symbolic format (e.g., u=rwx,g=rx,o=rx)
```

| umask | File result (from 0666) | Directory result (from 0777) |
|-------|--------------------------|-------------------------------|
| 0022 | 644 (`rw-r--r--`) | 755 (`rwxr-xr-x`) |
| 0077 | 600 (`rw-------`) | 700 (`rwx------`) |
| 0002 | 664 (`rw-rw-r--`) | 775 (`rwxrwxr-x`) |

```bash
# Set umask for current session
umask 0077     # Restrictive — new files 600, new directories 700
```

### Sudoers

`/etc/sudoers` controls which users can run commands as other users via `sudo`. Misconfigurations in sudoers are a primary privilege escalation vector.

```bash
# View current sudo privileges
sudo -l
```

`sudo -l` shows what the current user can run with `sudo`. Output format:

```text
User kali may run the following commands on host:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/vim
```

The first line allows all commands as any user (with password). The second allows `/usr/bin/vim` as root without a password — a direct path to root shell via `:!/bin/bash` inside vim.

Common dangerous sudoers entries:

| Entry | Risk |
|-------|------|
| `(ALL) NOPASSWD: ALL` | Full root without password |
| `(root) NOPASSWD: /usr/bin/vim` | Shell escape via `:!/bin/bash` |
| `(root) NOPASSWD: /usr/bin/find` | Command execution via `-exec` |
| `(root) NOPASSWD: /usr/bin/python3` | Direct code execution |
| `(root) NOPASSWD: /usr/bin/less` | Shell escape via `!sh` |
| `(root) NOPASSWD: /usr/bin/env` | Run arbitrary commands |

```bash
# Sudoers file editing (always use visudo to prevent syntax errors)
sudo visudo
```

`visudo` validates syntax before saving — a broken sudoers file can lock all users out of `sudo`.

## Practical Examples

### Privilege Escalation Enumeration

```bash
# 1. Check sudo permissions
sudo -l

# 2. Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# 3. Find SGID binaries
find / -perm -2000 -type f 2>/dev/null

# 4. Find files writable by current user (includes owned, group-writable, world-writable)
find / -writable -type f 2>/dev/null

# 5. Find directories writable by current user
find / -writable -type d 2>/dev/null

# 6. Check cron jobs for scripts you can modify
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/

# 7. Check for misconfigured file permissions
ls -la /etc/shadow      # Should be 640 or 600, owned by root:shadow
ls -la /etc/passwd       # Should be 644, owned by root:root
ls -la /etc/sudoers      # Should be 440, owned by root:root
```

If `/etc/shadow` is readable by your user, extract the hashes and crack them offline. If `/etc/passwd` is writable, add a new root-level user directly.

## References

### Official Documentation

- [GNU Coreutils — File Permissions](https://www.gnu.org/software/coreutils/manual/html_node/File-permissions.html)
- [The Linux man-pages Project — chmod(1)](https://man7.org/linux/man-pages/man1/chmod.1.html)
- [GTFOBins — Unix Binaries Privilege Escalation](https://gtfobins.github.io/)
