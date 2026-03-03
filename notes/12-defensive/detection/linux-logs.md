% Filename: 12-defensive/detection/linux-logs.md
% Display name: Linux Log Analysis
% Last update: 2026-02-11
% Authors: @TristanInSec

# Linux Log Analysis

## Overview

Linux provides multiple logging subsystems for security monitoring: traditional
syslog (rsyslog/syslog-ng), systemd journal (journald), and the Linux Audit
Framework (auditd). Together they provide visibility into authentication events,
process execution, file access, and system changes. This file covers key log
sources, detection-focused queries, and auditd configuration.

## Syslog and Journald

### Key Log Files

| Log File | Contents |
|---|---|
| /var/log/auth.log (Debian) | Authentication events, sudo, SSH |
| /var/log/secure (RHEL) | Authentication events, sudo, SSH |
| /var/log/syslog (Debian) | General system messages |
| /var/log/messages (RHEL) | General system messages |
| /var/log/kern.log | Kernel messages |
| /var/log/cron.log | Cron job execution |
| /var/log/daemon.log | Daemon messages |

### Journald Analysis

```bash
# journalctl
# https://www.freedesktop.org/software/systemd/man/journalctl.html

# Show all logs since last boot
journalctl -b

# Show logs for a specific time range
journalctl --since "2026-01-15 08:00:00" --until "2026-01-15 18:00:00"

# Show logs for a specific service
journalctl -u sshd --no-pager

# Show only authentication-related messages
journalctl _COMM=sshd --no-pager
journalctl _COMM=sudo --no-pager

# Show kernel messages
journalctl -k

# Show error-level and above
journalctl -p err

# Output as JSON for parsing
journalctl -o json --no-pager | head -5

# Follow logs in real time
journalctl -f -u sshd
```

## Authentication Log Analysis

```bash
# Detect brute force — failed SSH logins
grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Successful SSH logins
grep "Accepted" /var/log/auth.log | \
  awk '{print $1, $2, $3, $9, $11}' | sort

# Detect password spray — many users, same source
grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-3), $(NF-5)}' | sort | uniq -c | sort -rn

# Sudo usage (who ran what as root)
grep "sudo:" /var/log/auth.log | grep "COMMAND=" | \
  awk -F'COMMAND=' '{print $2}' | sort | uniq -c | sort -rn

# User account changes
grep -E "useradd|usermod|userdel|groupadd|passwd" /var/log/auth.log

# SSH key authentication
grep "Accepted publickey" /var/log/auth.log

# Failed sudo attempts
grep "authentication failure" /var/log/auth.log | grep sudo
```

## Linux Audit Framework (auditd)

### Auditd Configuration

```bash
# auditd
# https://people.redhat.com/sgrubb/audit/

# Check auditd status
sudo systemctl status auditd

# View current audit rules
sudo auditctl -l

# Key auditd configuration files:
#   /etc/audit/auditd.conf — daemon configuration
#   /etc/audit/rules.d/*.rules — persistent audit rules
#   /var/log/audit/audit.log — audit log output
```

### Essential Audit Rules

```bash
# /etc/audit/rules.d/security.rules
# Load with: sudo augenrules --load

# Monitor authentication files
# -w <path> -p <permissions> -k <key>
# permissions: r=read, w=write, x=execute, a=attribute change

# Identity and authentication
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k ssh_keys

# Cron and scheduled tasks
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Persistence mechanisms
-w /etc/systemd/system/ -p wa -k systemd_persist
-w /etc/init.d/ -p wa -k init_persist
-w /etc/rc.local -p wa -k rc_local
-w /etc/ld.so.preload -p wa -k ld_preload

# Kernel module loading
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules

# Network configuration
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/network/ -p wa -k network_config

# Log tampering
-w /var/log/auth.log -p wa -k log_tamper
-w /var/log/syslog -p wa -k log_tamper
-w /var/log/audit/ -p wa -k log_tamper
```

### Searching Audit Logs

```bash
# ausearch — search audit logs
# https://people.redhat.com/sgrubb/audit/

# Search by key
sudo ausearch -k identity

# Search by time range
sudo ausearch --start 01/15/2026 08:00:00 --end 01/15/2026 18:00:00

# Search for specific syscall (e.g., execve = process execution)
sudo ausearch -sc execve

# Search for events from a specific user
sudo ausearch -ua 1000

# Search for file access
sudo ausearch -f /etc/shadow

# Generate summary report
sudo aureport --summary

# Authentication report
sudo aureport --auth

# Failed events report
sudo aureport --failed
```

## Detection Patterns

### Unauthorized Access

```bash
# SSH logins from unexpected sources
grep "Accepted" /var/log/auth.log | \
  grep -v "from 10\.\|from 192\.168\.\|from 172\.1[6-9]\.\|from 172\.2[0-9]\.\|from 172\.3[01]\."

# Logins outside business hours (before 8 AM or after 6 PM)
grep "Accepted" /var/log/auth.log | \
  awk '{split($3,t,":"); if (t[1]<8 || t[1]>=18) print}'

# Root login attempts (should be disabled)
grep "Failed password for root" /var/log/auth.log
```

### Privilege Escalation

```bash
# Sudo to root
grep "sudo:.*COMMAND=" /var/log/auth.log | grep "USER=root"

# Setuid/setgid execution (via auditd)
sudo ausearch -sc execve -k setuid 2>/dev/null

# su usage
grep "su:" /var/log/auth.log | grep "Successful"

# Suspicious sudo commands
grep "COMMAND=" /var/log/auth.log | \
  grep -iE "chmod.*777|chown.*root|passwd|useradd|visudo|/bin/bash|/bin/sh"
```

### Persistence Indicators

```bash
# Crontab modifications
grep -E "crontab|CRON" /var/log/auth.log /var/log/syslog 2>/dev/null

# New systemd services
journalctl -u "*.service" | grep -i "Started\|Loaded"

# Shell profile modifications (via auditd)
sudo ausearch -f .bashrc 2>/dev/null
sudo ausearch -f .profile 2>/dev/null

# SSH authorized_keys changes (via auditd)
sudo ausearch -k ssh_keys 2>/dev/null
```

## References

### Tools

- [auditd (Linux Audit)](https://people.redhat.com/sgrubb/audit/)

### Further Reading

- [SANS Linux Log Analysis](https://www.sans.org/posters/sift-cheat-sheet)
