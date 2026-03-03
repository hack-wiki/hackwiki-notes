% Filename: 12-defensive/hardening/linux.md
% Display name: Linux Hardening
% Last update: 2026-02-11
% Authors: @TristanInSec

# Linux Hardening

## Overview

Linux hardening involves reducing the attack surface by configuring secure
defaults, applying kernel protections, restricting user access, enabling
mandatory access controls, and auditing system activity. This file covers
practical hardening steps that can be applied to Debian/Ubuntu and RHEL-based
systems.

## Kernel Hardening

### Sysctl Security Parameters

```bash
# sysctl
# https://man7.org/linux/man-pages/man8/sysctl.8.html

# Apply settings persistently in /etc/sysctl.d/99-hardening.conf

# Disable IP forwarding (unless this is a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Prevent source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg access to root
kernel.dmesg_restrict = 1

# Disable kernel module loading after boot (extreme hardening)
# kernel.modules_disabled = 1

# Restrict ptrace (prevent process debugging)
kernel.yama.ptrace_scope = 2

# Restrict unprivileged BPF
kernel.unprivileged_bpf_disabled = 1

# Restrict unprivileged user namespaces (mitigates some container escapes)
kernel.unprivileged_userns_clone = 0
```

```bash
# Apply sysctl changes immediately
sudo sysctl --system
```

## Service Management

```bash
# List all enabled services
systemctl list-unit-files --type=service --state=enabled

# Disable unnecessary services
sudo systemctl disable --now avahi-daemon    # mDNS (usually not needed on servers)
sudo systemctl disable --now cups            # printing
sudo systemctl disable --now bluetooth       # Bluetooth
sudo systemctl disable --now rpcbind         # NFS (if not used)

# Mask services to prevent them from starting
sudo systemctl mask rpcbind

# Check for listening services
ss -tlnp

# Remove unnecessary packages
sudo apt purge telnetd rsh-server xinetd 2>/dev/null
```

## SSH Hardening

```bash
# /etc/ssh/sshd_config hardening settings

# Disable root login
PermitRootLogin no

# Disable password authentication (use keys only)
PasswordAuthentication no
KbdInteractiveAuthentication no

# Restrict key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Restrict ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

# Restrict MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Restrict host key algorithms
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Limit concurrent sessions
MaxSessions 3
MaxStartups 10:30:60

# Set idle timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Restrict users/groups allowed to SSH
AllowGroups ssh-users

# Enable logging
LogLevel VERBOSE

# Disable X11 forwarding
X11Forwarding no

# Disable TCP forwarding (if not needed)
AllowTcpForwarding no
```

## User and Access Controls

```bash
# Set password policy
# /etc/login.defs
PASS_MAX_DAYS 90
PASS_MIN_DAYS 7
PASS_MIN_LEN  14
PASS_WARN_AGE 14

# Lock unused accounts
sudo usermod -L <unused_user>

# Set account expiration
sudo chage -E 2026-12-31 <user>

# View password aging information
sudo chage -l <user>

# Restrict su to wheel/sudo group
# /etc/pam.d/su
# auth required pam_wheel.so use_uid

# Set umask to 027 (owner=rwx, group=rx, other=none)
# /etc/profile or /etc/bash.bashrc
umask 027
```

## Filesystem Hardening

```bash
# Mount options in /etc/fstab for security

# /tmp — noexec, nosuid, nodev
tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0

# /var/tmp — noexec, nosuid, nodev
# /dev/shm — noexec, nosuid, nodev

# Set sticky bit on world-writable directories
chmod +t /tmp /var/tmp

# Remove SUID/SGID from unnecessary binaries
# Audit current SUID binaries
find / -type f -perm -4000 -ls 2>/dev/null

# Remove SUID if not needed
sudo chmod u-s /path/to/unnecessary/binary

# Restrict cron access
# /etc/cron.allow — only listed users can use cron
# /etc/cron.deny — listed users cannot use cron
# If cron.allow exists, only users in it can use cron
echo root | sudo tee /etc/cron.allow
```

## AppArmor

```bash
# apparmor
# https://apparmor.net/

# Check AppArmor status
sudo aa-status

# Profiles are in /etc/apparmor.d/
# Modes:
#   enforce — deny and log policy violations
#   complain — log but allow violations (for testing)

# Set a profile to enforce mode
sudo aa-enforce /etc/apparmor.d/usr.sbin.sshd

# Set a profile to complain mode (for testing)
sudo aa-complain /etc/apparmor.d/usr.sbin.sshd

# Reload all profiles
sudo systemctl reload apparmor
```

## Auditing with Lynis

```bash
# Lynis
# https://cisofy.com/lynis/

# Run a full system audit
sudo lynis audit system

# Run audit and save report
sudo lynis audit system --report-file /tmp/lynis-report.dat

# Show only warnings from the report
grep "warning" /tmp/lynis-report.dat

# Show suggestions from the report
grep "suggestion" /tmp/lynis-report.dat

# Lynis produces a hardening index (0-100) and lists
# specific recommendations for improvement
```

## Integrity Monitoring with AIDE

```bash
# AIDE (Advanced Intrusion Detection Environment)
# https://aide.github.io/

# Initialize the AIDE database (baseline)
sudo aide --init

# Copy the new database to the active location
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run an integrity check against the baseline
sudo aide --check

# Update the database after approved changes
sudo aide --update

# Configuration: /etc/aide/aide.conf
# Define which directories to monitor and what attributes to check
```

## Rootkit Detection

```bash
# rkhunter
# https://rkhunter.sourceforge.net/

# Update rkhunter database
sudo rkhunter --update

# Run rootkit scan
sudo rkhunter --check --sk

# View warnings only
sudo rkhunter --check --sk --rwo
```

```bash
# chkrootkit
# http://www.chkrootkit.org/

# Run rootkit scan
sudo chkrootkit

# Quiet mode (only show infections)
sudo chkrootkit -q
```

## References

### Tools

- [Lynis](https://cisofy.com/lynis/)
- [AIDE](https://aide.github.io/)
- [rkhunter](https://rkhunter.sourceforge.net/)
- [chkrootkit](http://www.chkrootkit.org/)
- [AppArmor](https://apparmor.net/)

### Further Reading

- [CIS Benchmarks (Linux)](https://www.cisecurity.org/cis-benchmarks)
- [NIST SP 800-123: Guide to General Server Security](https://csrc.nist.gov/pubs/sp/800/123/final)
