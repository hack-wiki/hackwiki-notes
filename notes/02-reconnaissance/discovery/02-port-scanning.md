% Filename: 02-reconnaissance/discovery/02-port-scanning.md
% Display name: Step 2 - Port Scanning
% Last update: 2026-02-19
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# Port Scanning

## Overview

Port scanning detects open TCP and UDP ports on discovered hosts. Open ports reveal running services — each one is a potential entry point. The primary tools are Nmap (feature-rich, accurate), Masscan (speed-optimized for large ranges), and RustScan (fast port discovery that feeds into Nmap).

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Live host list from host discovery phase
- Root/sudo for SYN scans and raw packet techniques
- Nmap installed (default on Kali)
- Masscan installed (default on Kali)
- RustScan installed (requires manual install on most distros)

## TCP Scan Types

### SYN Scan (Half-Open)

The default Nmap scan when run as root. Sends SYN, receives SYN-ACK for open ports, sends RST to tear down — never completes the TCP handshake. Faster and stealthier than full connect scans.

```bash
# Nmap
# https://nmap.org/
nmap -sS -p- <target>
```

### Connect Scan

Full TCP handshake. Used when running without root privileges. More detectable because the connection completes and may be logged by the target application.

```bash
# Nmap
# https://nmap.org/
nmap -sT -p- <target>
```

### NULL, FIN, and Xmas Scans

These scans send TCP packets with unusual flag combinations. RFC 793 states that closed ports should respond with RST while open ports should drop the packet silently. Useful for probing through some stateless firewalls, but unreliable against Windows hosts (which send RST regardless).

```bash
# Nmap
# https://nmap.org/
# NULL scan — no flags set
nmap -sN -p 1-1000 <target>

# FIN scan — FIN flag only
nmap -sF -p 1-1000 <target>

# Xmas scan — FIN, PSH, URG flags set
nmap -sX -p 1-1000 <target>
```

These return "open|filtered" when a port is open because the absence of RST is ambiguous — the probe may have been dropped by a firewall.

### Window Scan

Similar to ACK scan but examines the TCP window size field in RST responses to differentiate open from closed ports. Implementation-dependent and unreliable across modern systems.

```bash
# Nmap
# https://nmap.org/
nmap -sW -p 1-1000 <target>
```

### ACK Scan

Does not determine if ports are open — it maps firewall rules. Sends ACK packets and examines whether they receive RST (unfiltered) or no response (filtered).

```bash
# Nmap
# https://nmap.org/
nmap -sA -p 1-1000 <target>
```

Use ACK scans to understand firewall behavior before choosing your primary scan technique.

## UDP Scanning

### Standard UDP Scan

UDP scanning is slow because open ports often do not respond, and Nmap must wait for ICMP port unreachable (closed) or timeout (open/filtered). Scan selectively.

```bash
# Nmap
# https://nmap.org/
# Top 100 UDP ports
nmap -sU --top-ports 100 <target>

# Specific high-value UDP ports
nmap -sU -p 53,67,68,69,123,137,138,161,162,500,514,1900 <target>

# Combined TCP SYN + UDP scan
nmap -sS -sU --top-ports 200 <target>
```

UDP port 161 (SNMP), 53 (DNS), 69 (TFTP), and 137 (NetBIOS) are frequent targets for enumeration.

## Speed and Scope Control

### Port Range Selection

```bash
# Nmap
# https://nmap.org/
# All 65535 TCP ports
nmap -sS -p- <target>

# Top 1000 ports (Nmap default)
nmap -sS <target>

# Top N ports by frequency
nmap -sS --top-ports 100 <target>

# Specific ports
nmap -sS -p 22,80,443,445,3389 <target>

# Port ranges
nmap -sS -p 1-1024 <target>
```

### Timing Templates

```bash
# Nmap
# https://nmap.org/
nmap -sS -T0 <target>   # Paranoid  — 5 min between probes (IDS evasion)
nmap -sS -T1 <target>   # Sneaky   — 15 sec between probes
nmap -sS -T2 <target>   # Polite   — 0.4 sec between probes
nmap -sS -T3 <target>   # Normal   — default
nmap -sS -T4 <target>   # Aggressive — common for CTF and lab environments
nmap -sS -T5 <target>   # Insane   — max speed, may miss ports on lossy networks
```

For engagements, `-T3` or `-T4` is typical. Use `-T1`/`-T2` when stealth is required. Avoid `-T5` on production networks — packet loss causes false negatives.

### Fine-Grained Rate Control

```bash
# Nmap
# https://nmap.org/
# Limit packets per second
nmap -sS --max-rate 500 <target>

# Set minimum rate (prevent Nmap from throttling itself)
nmap -sS --min-rate 1000 -p- <target>

# Control parallel host scanning
nmap -sS --min-hostgroup 64 --max-hostgroup 256 10.10.10.0/24
```

`--min-rate` is useful for full-port scans against a single host — prevents Nmap from slowing down after timeouts.

## Masscan (High-Speed Scanning)

Masscan is purpose-built for scanning large IP ranges at extreme speed. It uses its own TCP stack (bypasses the OS kernel), enabling millions of packets per second. It does not perform service detection — use it for port discovery, then pass results to Nmap.

```bash
# Masscan
# https://github.com/robertdavidgraham/masscan
# Scan all ports on a /24 at 10,000 packets per second
sudo masscan 10.10.10.0/24 -p 0-65535 --rate 10000 -oG masscan_results.gnmap

# Scan specific ports
sudo masscan 10.10.10.0/24 -p 22,80,443,445,3389,8080 --rate 5000

# Scan top ports on a large range
sudo masscan 10.0.0.0/8 -p 80,443 --rate 100000

# Output in list format for Nmap input
sudo masscan 10.10.10.0/24 -p 0-65535 --rate 10000 -oL masscan_list.txt
```

### Masscan to Nmap Pipeline

```bash
# Masscan
# https://github.com/robertdavidgraham/masscan
# Step 1: Fast port discovery with Masscan (-oL produces stable line-based output)
sudo masscan 10.10.10.0/24 -p 0-65535 --rate 10000 -oL masscan_list.txt

# Step 2: Extract IP:port pairs from -oL output
# Each open line looks like: open tcp <port> <ip> <timestamp>
awk '$1=="open"{print $4 ":" $3}' masscan_list.txt | sort -t: -k1,1 -k2,2n

# Step 3: Targeted Nmap scan on discovered ports
# Nmap
# https://nmap.org/
nmap -sV -sC -p 22,80,443 -iL live_hosts.txt -oA nmap_targeted
```

### Masscan Considerations

Masscan does not resolve hostnames, does not detect service versions, and produces false positives on lossy networks. Always validate Masscan results with Nmap. On shared networks, rates above 10,000 pps can cause congestion — coordinate with the client.

## RustScan (Fast Discovery + Nmap Integration)

RustScan performs rapid port discovery using async I/O, then automatically passes open ports to Nmap for service detection. It combines the speed of Masscan with the depth of Nmap in a single workflow.

```bash
# RustScan
# https://github.com/RustScan/RustScan
# Basic scan — discovers open ports then runs Nmap
rustscan -a <target> -- -sV -sC

# Scan with specific port range
rustscan -a <target> -r 1-65535 -- -sV

# Multiple targets
rustscan -a 10.10.10.5,10.10.10.10,10.10.10.15 -- -sV -sC

# Control batch size (concurrent connections)
rustscan -a <target> -b 1000 -- -sV

# Save Nmap output (pass -oA to Nmap via the -- separator)
rustscan -a <target> -- -oA rustscan_results
```

The `--` separator passes everything after it as Nmap arguments. The `-b` flag controls batch size (concurrent port connections) — lower values are quieter, higher values are faster.

### RustScan Considerations

Default batch size is 4500, which can overwhelm targets or trigger rate limiting. Reduce to 500-1000 for production environments. RustScan is not installed by default on Kali — install via the project's GitHub releases or using Docker:

```bash
# Docker method
docker run -it --rm --name rustscan rustscan/rustscan:latest -a <target> -- -sV
```

## Nmap Output Formats

```bash
# Nmap
# https://nmap.org/
# Normal text output
nmap -sS <target> -oN scan.txt

# Grepable output (easy to parse with grep/awk)
nmap -sS <target> -oG scan.gnmap

# XML output (for import into tools like Metasploit, Faraday)
nmap -sS <target> -oX scan.xml

# All three formats simultaneously
nmap -sS <target> -oA scan_results
```

Always use `-oA` to save in all formats. XML output can be imported into Metasploit with `db_import`.

## Firewall Evasion Techniques

```bash
# Nmap
# https://nmap.org/
# Fragment packets into 8-byte chunks
nmap -sS -f <target>

# Set custom MTU (must be multiple of 8)
nmap -sS --mtu 24 <target>

# Spoof source port as DNS
nmap -sS -g 53 <target>

# Add decoy IPs to mask scanner origin
nmap -sS -D RND:5 <target>

# Idle scan — use a zombie host to scan (no packets from your IP)
nmap -sI <zombie_ip> <target>

# Randomize target port order
nmap -sS --randomize-hosts -p- 10.10.10.0/24
```

Idle scan (`-sI`) is the stealthiest technique — it uses predictable IP ID sequences on a third-party host to infer port states without sending any packet from the scanner's IP. Requires a suitable zombie host with an incremental IP ID and low traffic.

## Practical Workflow

A typical engagement port scanning workflow:

```bash
# Nmap
# https://nmap.org/
# Phase 1: Quick top-port scan across all live hosts
nmap -sS --top-ports 1000 -T4 -iL live_hosts.txt -oA phase1_quick

# Phase 2: Full port scan on high-priority targets
nmap -sS -p- --min-rate 1000 -T4 <priority_target> -oA phase2_full

# Phase 3: Service version detection on open ports
nmap -sV -sC -p <open_ports> <priority_target> -oA phase3_services

# Phase 4: UDP scan on high-value ports
nmap -sU --top-ports 50 <priority_target> -oA phase4_udp
```

## References

### Official Documentation

- [Nmap Reference Guide — Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
- [Nmap Reference Guide — Timing and Performance](https://nmap.org/book/performance.html)
- [Nmap Reference Guide — Firewall/IDS Evasion](https://nmap.org/book/firewall-subversion.html)
- [Masscan GitHub Repository](https://github.com/robertdavidgraham/masscan)
- [RustScan GitHub Repository](https://github.com/RustScan/RustScan)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
