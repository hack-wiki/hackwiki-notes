% Filename: 02-reconnaissance/enum-misc/nfs.md
% Display name: NFS Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance), TA0007 (Discovery)
% ATT&CK Techniques: T1595 (Active Scanning), T1135 (Network Share Discovery)
% Authors: @TristanInSec

# NFS Enumeration

## Overview

NFS (Network File System) runs on TCP/UDP 2049, with portmapper (rpcbind) on TCP/UDP 111. Enumeration focuses on discovering exported shares, checking access restrictions, and identifying misconfigurations that allow unauthorized file access. NFS is extremely common on internal networks — misconfigured exports with no host restrictions or `no_root_squash` set are frequent findings in enterprise environments.

## ATT&CK Mapping

- **Tactics:** TA0043 - Reconnaissance, TA0007 - Discovery
- **Technique:** T1595 - Active Scanning
- **Technique:** T1135 - Network Share Discovery

## Prerequisites

- Network access to target ports 111 and 2049
- `nfs-common` package installed (provides `showmount` and mount helpers)
- Root or sudo for mounting NFS shares

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 111,2049 <target>
```

Expected output:
```text
111/tcp  open  rpcbind  2-4 (RPC #100000)
2049/tcp open  nfs      3-4 (RPC #100003)
```

### RPC Service Enumeration

Identify all registered RPC services. NFS depends on several RPC programs (mountd, nlockmgr, status) that may run on dynamic ports:

```bash
# Query all registered RPC programs
rpcinfo -p <target>
```

Expected output (truncated):
```text
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100005    3   tcp  20048  mountd
    100021    4   tcp  43219  nlockmgr
    100024    1   tcp  57869  status
```

The `mountd` port is important — this is the service that handles mount requests.

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 111 --script rpcinfo <target>
```

### Export Enumeration

```bash
# List all exported shares and allowed hosts
showmount -e <target>
```

Expected output:
```text
Export list for 10.10.10.50:
/home          *
/var/backups   10.10.10.0/24
/srv/nfs       (everyone)
```

An asterisk (`*`) or `(everyone)` means no host restriction — any client can mount the share.

```bash
# Show all mount points (who has mounted what)
showmount -a <target>

# Show directories only
showmount -d <target>
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# List NFS exports (equivalent to showmount -e)
nmap -p 111 --script nfs-showmount <target>

# List files in NFS exports (requires access)
nmap -p 111 --script nfs-ls <target>

# Show filesystem statistics (disk usage)
nmap -p 111 --script nfs-statfs <target>

# Run all NFS scripts
nmap -p 111 --script nfs-ls,nfs-showmount,nfs-statfs <target>
```

Expected output from `nfs-ls` (truncated):
```text
| nfs-ls: Volume /home
|   access/uid  gid   size     time               filename
|   rwxr-xr-x  1001  1001  4096     2024-03-15T14:22:05  .
|   rwxr-xr-x  0     0     4096     2024-03-15T10:00:01  ..
|   rwx------  1001  1001  12288    2024-03-15T14:22:05  .bash_history
|   rw-r--r--  1001  1001  220      2024-01-01T00:00:00  .bash_logout
|   rw-------  1001  1001  1679     2024-03-10T09:30:00  .ssh/id_rsa
```

Private SSH keys in NFS exports are a common finding.

### Metasploit Modules

```msf
# Metasploit Framework
# https://www.metasploit.com/
# Scan for NFS exports
msf6 > use auxiliary/scanner/nfs/nfsmount
msf6 > set RHOSTS <target>
msf6 > run
```

### Mounting NFS Shares

```bash
# Create mount point
mkdir -p /mnt/nfs

# Mount an NFS share
mount -t nfs <target>:/home /mnt/nfs

# Mount with specific NFS version if default fails
mount -t nfs -o vers=3 <target>:/home /mnt/nfs
mount -t nfs -o vers=2 <target>:/home /mnt/nfs

# Mount with nolock (if lockd is unavailable)
mount -t nfs -o nolock <target>:/home /mnt/nfs
```

After mounting, enumerate the contents:

```bash
# List all files recursively
find /mnt/nfs -type f -ls 2>/dev/null

# Search for interesting files
find /mnt/nfs -name "*.conf" -o -name "*.txt" -o -name "*.bak" -o -name "*.sql" 2>/dev/null
find /mnt/nfs -name "id_rsa" -o -name "*.key" -o -name "*.pem" 2>/dev/null
find /mnt/nfs -name ".bash_history" -o -name ".mysql_history" 2>/dev/null

# Check for SUID binaries (relevant if no_root_squash is set)
find /mnt/nfs -perm -4000 -type f -ls 2>/dev/null
```

### Export Configuration Analysis

If you can read `/etc/exports` on the target (via NFS itself, LFI, or other access):

```text
/home          *(rw,no_root_squash)
/var/backups   10.10.10.0/24(ro,root_squash)
/srv/nfs       *(rw,sync,no_subtree_check)
```

Key options to look for:

- `no_root_squash` — root on the client maps to root on the server. This allows creating SUID binaries on the share that execute as root on the NFS server. Critical escalation vector.
- `rw` — read-write access. Combined with `no_root_squash`, allows writing SUID binaries.
- `root_squash` — default setting. Root on client maps to `nfsnobody`. Safer, but non-root file access still works.
- `*` or no host restriction — any host can mount.
- `anonuid`/`anongid` — maps anonymous users to a specific UID/GID.

### no_root_squash Exploitation Check

If `no_root_squash` is set and the share is writable:

```bash
# Mount the share
mount -t nfs <target>:/home /mnt/nfs

# Confirm root access (should show root ownership)
touch /mnt/nfs/testfile
ls -la /mnt/nfs/testfile
```

If the file is owned by `root:root` (not `nfsnobody`), `no_root_squash` is active. This confirms the escalation path — SUID binary creation is possible. The actual exploitation is post-exploitation scope.

Clean up the test:

```bash
rm /mnt/nfs/testfile
umount /mnt/nfs
```

### UID Spoofing for File Access

NFS v3 trusts the client's UID claims. If files are owned by a specific UID and you cannot access them as your current user:

```bash
# Check file ownership on the mounted share
ls -ln /mnt/nfs/
```

Output:
```text
drwx------ 2 1001 1001 4096 Mar 15 14:22 user
```

Create a local user with matching UID:

```bash
useradd -u 1001 tempuser
su - tempuser
cat /mnt/nfs/user/.ssh/id_rsa
```

This works because NFSv3 authenticates based on UID alone — no Kerberos or host verification.

## Post-Enumeration

With NFS access confirmed, prioritize:
- SSH keys and credential files in home directories
- Configuration files with passwords (database configs, `.env` files)
- Backup files that may contain sensitive data
- Writable exports with `no_root_squash` for privilege escalation
- `/etc/shadow` or `/etc/passwd` if system directories are exported

## References

### Official Documentation

- [Nmap nfs-showmount NSE Script](https://nmap.org/nsedoc/scripts/nfs-showmount.html)
- [Nmap nfs-ls NSE Script](https://nmap.org/nsedoc/scripts/nfs-ls.html)
- [Nmap nfs-statfs NSE Script](https://nmap.org/nsedoc/scripts/nfs-statfs.html)
- [RFC 7530 - NFS Version 4 Protocol](https://datatracker.ietf.org/doc/html/rfc7530)

### Pentest Guides & Tutorials

- [Infosec Institute - Exploiting NFS Share (archived)](https://web.archive.org/web/2024/https://resources.infosecinstitute.com/topic/exploiting-nfs-share/)
- [MCSI Library - NFS Enumeration for Low Privilege Access](https://library.mosse-institute.com/articles/2022/07/nfs-enumeration-for-low-privilege-access/nfs-enumeration-for-low-privilege-access.html)
- [InfoSecWarrior - Offensive NFS Enumeration (GitHub)](https://github.com/InfoSecWarrior/Offensive-Pentesting-Host/blob/main/NFS/README.md)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1135 - Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
