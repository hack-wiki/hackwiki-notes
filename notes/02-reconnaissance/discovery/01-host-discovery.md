% Filename: 02-reconnaissance/discovery/01-host-discovery.md
% Display name: Step 1 - Host Discovery
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance), TA0007 (Discovery)
% ATT&CK Techniques: T1595 (Active Scanning), T1018 (Remote System Discovery)
% Authors: @TristanInSec

# Host Discovery

## Overview

Host discovery identifies live systems in a target range before port scanning. Scanning every port on every IP in a /24 wastes time — discovering which hosts are alive first reduces scan scope dramatically. Different probe types work in different network positions: ARP on local segments, ICMP and TCP through routers.

## ATT&CK Mapping

- **Tactics:** TA0043 - Reconnaissance, TA0007 - Discovery
- **Techniques:** T1595 - Active Scanning, T1018 - Remote System Discovery

## Prerequisites

- Network access to target range (local or remote)
- Nmap installed (host discovery probes)
- Root/sudo for raw socket scans (SYN, ARP, ICMP)

## Techniques

### ARP Discovery (Local Subnet)

ARP operates at Layer 2 and cannot be blocked by host firewalls. It is the most reliable discovery method on local network segments.

```bash
# Nmap
# https://nmap.org/
# ARP scan — local subnet only, no port scan
nmap -sn -PR 192.168.1.0/24
```

Nmap uses ARP automatically when scanning a local subnet with `-sn`. The `-PR` flag makes ARP-only explicit.

```bash
# netdiscover
# https://github.com/alexxy/netdiscover
# Active ARP scan
sudo netdiscover -r 192.168.1.0/24

# Passive mode — listen for ARP traffic without sending probes
sudo netdiscover -p
```

```bash
# arp-scan
# https://github.com/royhills/arp-scan
sudo arp-scan --localnet
sudo arp-scan 192.168.1.0/24
```

`arp-scan` includes an OUI database and resolves MAC addresses to manufacturer names, which helps identify device types (printers, switches, IoT).

### ICMP Discovery (Remote Networks)

ICMP echo (ping) is the classic host discovery method. Many firewalls block ICMP, so Nmap combines multiple probe types by default.

```bash
# Nmap
# https://nmap.org/
# ICMP echo request only
nmap -sn -PE 10.10.0.0/16

# ICMP timestamp request (bypasses some echo-blocking filters)
nmap -sn -PP 10.10.0.0/16

# ICMP address mask request (less commonly filtered)
nmap -sn -PM 10.10.0.0/16
```

```bash
# fping — parallel ICMP sweep, faster than serial ping
# https://fping.org/
fping -a -g 10.10.10.0/24 2>/dev/null
```

The `-a` flag shows only alive hosts, `-g` generates the target list from CIDR. Redirect stderr to suppress unreachable messages.

```bash
# Native ping sweep (no tools needed)
for i in $(seq 1 254); do (ping -c 1 -W 1 10.10.10.$i &>/dev/null && echo "10.10.10.$i is alive") & done; wait
```

This bash one-liner runs pings in parallel using background processes. Useful when Nmap is not available.

### TCP Discovery

TCP probes bypass ICMP-blocking firewalls by targeting ports likely to be open.

```bash
# Nmap
# https://nmap.org/
# TCP SYN probe to port 443 (requires root)
nmap -sn -PS443 10.10.10.0/24

# TCP SYN probe to multiple ports
nmap -sn -PS22,80,443,445,3389 10.10.10.0/24

# TCP ACK probe (root required) — bypasses stateless (packet-filter) firewalls
nmap -sn -PA80,443 10.10.10.0/24
```

SYN probes (`-PS`) send a SYN packet. If the port is open, the host replies with SYN-ACK — confirming the host is alive. ACK probes (`-PA`) expect RST responses, which also confirm the host exists. ACK probes can sometimes pass through stateless (packet-filter) firewalls that block incoming SYN packets but allow ACK through. Against stateful firewalls, unexpected ACK packets are recognized as invalid and dropped — in that case, SYN probes are more effective.

When unprivileged (no root), Nmap falls back to a full TCP connect probe.

### UDP Discovery

UDP probes can discover hosts where TCP and ICMP are filtered.

```bash
# Nmap
# https://nmap.org/
# UDP probe to common service ports
nmap -sn -PU53,161,137 10.10.10.0/24
```

A closed UDP port returns ICMP port unreachable — confirming the host is alive. Open UDP ports that respond to the probe also confirm the host.

### Combined Probes (Default Nmap Behavior)

When run as root, Nmap's default `-sn` sends four probe types simultaneously:

```bash
# Nmap
# https://nmap.org/
# Default discovery — ICMP echo + TCP SYN 443 + TCP ACK 80 + ICMP timestamp
sudo nmap -sn 10.10.10.0/24
```

This combination maximizes host detection. On local subnets, Nmap substitutes all probes with ARP automatically.

### Disabling Host Discovery

When you already know hosts are alive (e.g., from a previous sweep), skip discovery to go straight to port scanning:

```bash
# Nmap
# https://nmap.org/
# Skip host discovery — treat all IPs as alive
nmap -Pn -p- 10.10.10.5
```

Use `-Pn` deliberately — applying it to an entire range scans every IP including dead ones, which is slow.

## Handling Firewall Evasion

Some techniques to improve host discovery against firewalled targets:

```bash
# Nmap
# https://nmap.org/
# Fragment packets to bypass simple packet inspection
nmap -sn -f 10.10.10.0/24

# Use a specific source port (firewalls may whitelist DNS/HTTP source ports)
nmap -sn -g 53 10.10.10.0/24

# Slow down to avoid rate-based detection
nmap -sn -T2 10.10.10.0/24
```

Fragmentation (`-f`) splits probes into smaller packets. Source port manipulation (`-g`) can bypass rules that allow traffic from DNS (53) or HTTP (80) source ports. Timing templates (`-T0` through `-T5`) control scan speed — lower values are stealthier but slower.

## Output and Documentation

Save discovery results for use in subsequent port scanning:

```bash
# Nmap
# https://nmap.org/
# Save results in all formats
nmap -sn 10.10.10.0/24 -oA discovery_sweep

# Extract live IPs from grepable output for feeding into port scans
grep "Up" discovery_sweep.gnmap | awk '{print $2}' > live_hosts.txt

# Use the list for targeted port scanning
nmap -iL live_hosts.txt -p-
```

The `-oA` flag produces normal (`.nmap`), grepable (`.gnmap`), and XML (`.xml`) output simultaneously. Grepable output is easiest to parse programmatically.

## References

### Official Documentation

- [Nmap Host Discovery](https://nmap.org/book/host-discovery.html)
- [Nmap Host Discovery Techniques](https://nmap.org/book/host-discovery-techniques.html)
- [arp-scan GitHub Repository](https://github.com/royhills/arp-scan)
- [fping Official Site](https://fping.org/)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
