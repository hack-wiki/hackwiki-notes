% Filename: 11-digital-forensics/linux-forensics/overview.md
% Display name: Linux Forensics
% Last update: 2026-02-11
% Authors: @TristanInSec

# Linux Forensics

## Overview

Linux forensics involves analyzing log files, filesystem artifacts, user
activity traces, and system configuration to reconstruct events on Linux
systems. Linux stores most forensic evidence in plaintext logs and well-defined
filesystem locations, making analysis accessible with standard command-line
tools. Key evidence sources include systemd journals, authentication logs,
shell history, cron jobs, and filesystem timestamps.

## Topics in This Section

- [Linux Artifacts](artifacts.md) — analyzing logs, shell history, user activity,
  scheduled tasks, persistence mechanisms, and filesystem metadata on Linux

## General Approach

```text
Linux system under investigation
    │
    ├── Collect artifacts (from forensic image or live system)
    │   ├── /var/log/ → system and application logs
    │   ├── /home/<user>/ → shell history, SSH keys, configs
    │   ├── /etc/ → system configuration, cron, passwd/shadow
    │   └── /tmp/, /dev/shm/ → attacker staging areas
    │
    ├── Log analysis
    │   ├── auth.log / secure → authentication events
    │   ├── syslog / journal → system events
    │   ├── apt/dpkg logs → package installation
    │   └── Application logs (Apache, MySQL, etc.)
    │
    ├── User activity
    │   ├── .bash_history / .zsh_history → command history
    │   ├── .ssh/ → authorized_keys, known_hosts
    │   ├── .local/share/recently-used.xbel → recent files
    │   └── last / lastlog / wtmp → login records
    │
    ├── Persistence and backdoors
    │   ├── crontab -l, /etc/cron.* → scheduled tasks
    │   ├── systemd service files → malicious services
    │   ├── /etc/rc.local, init.d → startup scripts
    │   └── LD_PRELOAD, /etc/ld.so.preload → library injection
    │
    └── Filesystem timeline and correlation
```
