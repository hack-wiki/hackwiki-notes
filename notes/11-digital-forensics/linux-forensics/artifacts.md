% Filename: 11-digital-forensics/linux-forensics/artifacts.md
% Display name: Linux Artifacts
% Last update: 2026-02-11
% Authors: @TristanInSec

# Linux Artifacts

## Overview

Linux forensic artifacts include log files, shell history, user configuration
files, scheduled tasks, filesystem metadata, and various system state files.
Most Linux artifacts are stored as plaintext, making them accessible with
standard command-line tools. This file covers the key locations and analysis
techniques for forensic investigation of Linux systems.

## Log Files

### Authentication Logs

```bash
# Authentication events (Debian/Ubuntu)
# /var/log/auth.log

# Authentication events (RHEL/CentOS)
# /var/log/secure

# Key events to look for:
#   Accepted password/publickey — successful logins
#   Failed password — brute force attempts
#   session opened/closed — login/logout activity
#   sudo: <user> — privilege escalation
#   useradd/usermod/userdel — account changes
#   COMMAND= — sudo commands executed

# Extract successful SSH logins
grep "Accepted" /evidence/var/log/auth.log

# Extract failed login attempts
grep "Failed password" /evidence/var/log/auth.log

# Extract sudo commands
grep "COMMAND=" /evidence/var/log/auth.log

# Extract user creation events
grep -E "useradd|adduser" /evidence/var/log/auth.log
```

### System Logs

```bash
# Syslog (general system events)
# /var/log/syslog (Debian/Ubuntu)
# /var/log/messages (RHEL/CentOS)

# Kernel messages
# /var/log/kern.log

# systemd journal (binary format)
# /var/log/journal/<machine-id>/

# Read systemd journal from a forensic image
journalctl --directory=/evidence/var/log/journal/ --no-pager

# Filter journal by time range
journalctl --directory=/evidence/var/log/journal/ \
  --since="2026-01-15 00:00:00" --until="2026-01-16 00:00:00"

# Filter journal by unit (service)
journalctl --directory=/evidence/var/log/journal/ -u sshd

# Show only error-level messages
journalctl --directory=/evidence/var/log/journal/ -p err
```

### Package Management Logs

```bash
# APT (Debian/Ubuntu)
# /var/log/apt/history.log — packages installed/removed/upgraded
# /var/log/dpkg.log — low-level package operations

# Extract recently installed packages
grep " install " /evidence/var/log/dpkg.log

# YUM/DNF (RHEL/CentOS)
# /var/log/yum.log or /var/log/dnf.log

# Check for attacker-installed packages
grep "Installed:" /evidence/var/log/apt/history.log
```

### Web Server Logs

```bash
# Apache
# /var/log/apache2/access.log
# /var/log/apache2/error.log

# Nginx
# /var/log/nginx/access.log
# /var/log/nginx/error.log

# Look for web shell access
grep -E "\.php\?cmd=|\.php\?c=|eval\(|system\(|passthru" /evidence/var/log/apache2/access.log

# Look for SQL injection attempts
grep -iE "union.*select|or.*1=1|drop.*table" /evidence/var/log/apache2/access.log

# Look for suspicious POST requests
grep "POST" /evidence/var/log/apache2/access.log | grep -v "wp-login\|login\|api"
```

## Shell History

```bash
# Bash history
# /home/<user>/.bash_history
# /root/.bash_history

# Zsh history
# /home/<user>/.zsh_history

# Fish history
# /home/<user>/.local/share/fish/fish_history

# MySQL history
# /home/<user>/.mysql_history

# Python history
# /home/<user>/.python_history

# Look for suspicious commands in bash history
grep -iE 'wget|curl.*-o|nc.*-e|/dev/tcp|base64|python.*-c|perl.*-e|chmod.*777|nohup' \
  /evidence/home/*/.bash_history /evidence/root/.bash_history

# Look for credential access
grep -iE 'shadow|passwd|id_rsa|\.pem|ssh-keygen|authorized_keys' \
  /evidence/home/*/.bash_history /evidence/root/.bash_history

# Look for data exfiltration indicators
grep -iE 'scp|rsync|tar.*czf|zip.*-r|curl.*POST|nc.*<' \
  /evidence/home/*/.bash_history /evidence/root/.bash_history
```

## Login Records

```bash
# Binary login records (requires utmpdump or last with the file)

# /var/log/wtmp — successful login/logout records
last -f /evidence/var/log/wtmp

# /var/log/btmp — failed login attempts
lastb -f /evidence/var/log/btmp

# /var/log/lastlog — last login time per user
lastlog

# /var/run/utmp — currently logged-in users (volatile)
who /evidence/var/run/utmp
```

## Scheduled Tasks

```bash
# User crontabs
# /var/spool/cron/crontabs/<user> (Debian/Ubuntu)
# /var/spool/cron/<user> (RHEL/CentOS)

# System crontabs
# /etc/crontab
# /etc/cron.d/*
# /etc/cron.daily/*
# /etc/cron.hourly/*
# /etc/cron.weekly/*
# /etc/cron.monthly/*

# Check all crontabs for suspicious entries
for f in /evidence/var/spool/cron/crontabs/*; do
  echo "=== $(basename "$f") ==="
  cat "$f"
done

cat /evidence/etc/crontab
ls -la /evidence/etc/cron.d/

# systemd timers (modern replacement for cron)
# /etc/systemd/system/*.timer
# /home/<user>/.config/systemd/user/*.timer
ls -la /evidence/etc/systemd/system/*.timer 2>/dev/null
```

## Persistence Mechanisms

```bash
# systemd services (persistent services)
# /etc/systemd/system/ — system services
# /home/<user>/.config/systemd/user/ — user services
# Look for suspicious .service files

# Check enabled services
ls -la /evidence/etc/systemd/system/multi-user.target.wants/

# Init scripts
# /etc/init.d/ — SysV init scripts
# /etc/rc.local — runs at boot (if enabled)

# Shell profile persistence
# /etc/profile, /etc/profile.d/*.sh — all users
# /home/<user>/.bashrc, .bash_profile, .profile — per user
# /home/<user>/.zshrc — zsh users

# Look for malicious additions to shell profiles
grep -rn "curl\|wget\|nc\|/dev/tcp\|base64\|eval" \
  /evidence/home/*/.bashrc /evidence/home/*/.profile \
  /evidence/etc/profile /evidence/etc/profile.d/ 2>/dev/null

# LD_PRELOAD persistence
cat /evidence/etc/ld.so.preload 2>/dev/null
grep "LD_PRELOAD" /evidence/etc/environment 2>/dev/null

# SSH authorized_keys persistence
find /evidence/home/ -name "authorized_keys" -exec echo "=== {} ===" \; -exec cat {} \;
cat /evidence/root/.ssh/authorized_keys 2>/dev/null
```

## User and Account Analysis

```bash
# User accounts
# /etc/passwd — user accounts (check for new/suspicious users)
# /etc/shadow — password hashes (check for recently changed passwords)
# /etc/group — group memberships (check sudo/wheel/admin groups)

# Find accounts with UID 0 (root-equivalent)
awk -F: '$3 == 0 {print $0}' /evidence/etc/passwd

# Find accounts with shell access
grep -v "nologin\|/false" /evidence/etc/passwd

# Check sudo group membership
grep -E "^(sudo|wheel):" /evidence/etc/group

# Check sudoers configuration
cat /evidence/etc/sudoers
ls -la /evidence/etc/sudoers.d/

# SSH keys
# /home/<user>/.ssh/id_rsa — private keys
# /home/<user>/.ssh/known_hosts — connected hosts
# /home/<user>/.ssh/authorized_keys — allowed keys
```

## Filesystem Artifacts

```bash
# Recently modified files (from a mounted forensic image)
find /evidence/ -type f -mtime -7 -ls 2>/dev/null | sort -k11

# Files in common attacker staging locations
ls -laR /evidence/tmp/
ls -laR /evidence/dev/shm/
ls -laR /evidence/var/tmp/
ls -laR /evidence/run/

# SUID/SGID binaries (potential privesc)
find /evidence/ -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# World-writable directories
find /evidence/ -type d -perm -0002 -ls 2>/dev/null

# Hidden files and directories (dot-prefixed)
find /evidence/home/ -name ".*" -ls 2>/dev/null
find /evidence/tmp/ -name ".*" -ls 2>/dev/null

# Deleted but open files (on live system)
# ls -la /proc/*/fd/ | grep deleted
```

## Network Configuration

```bash
# Network interfaces
cat /evidence/etc/network/interfaces
cat /evidence/etc/netplan/*.yaml 2>/dev/null

# DNS configuration
cat /evidence/etc/resolv.conf
cat /evidence/etc/hosts

# Firewall rules
cat /evidence/etc/iptables/rules.v4 2>/dev/null
cat /evidence/etc/nftables.conf 2>/dev/null

# Listening services configuration
ls -la /evidence/etc/systemd/system/
grep -rn "Listen\|Port" /evidence/etc/ssh/sshd_config

# Hosts file (check for DNS hijacking)
cat /evidence/etc/hosts
```

## References

### Further Reading

- [SANS SIFT Cheat Sheet](https://www.sans.org/posters/sift-cheat-sheet)
