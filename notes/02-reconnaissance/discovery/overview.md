% Filename: 02-reconnaissance/discovery/overview.md
% Display name: Discovery Overview
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Discovery

## Overview

Network discovery is the first active contact with target infrastructure. The goal is to map what exists — live hosts, open ports, running services, and operating systems — before moving into deep service enumeration. Discovery answers "what's there?" while enumeration answers "what can I do with it?"

This phase bridges passive reconnaissance (no target contact) and service enumeration (protocol-specific deep dives). Keep discovery scans broad and fast, then narrow down for deeper inspection.

## Topics in This Section

- [Host Discovery](01-host-discovery.md) — Identify live hosts on a network using ICMP, ARP, TCP, and UDP probes
- [Port Scanning](02-port-scanning.md) — Detect open ports with Nmap, Masscan, and RustScan
- [Fingerprinting](03-fingerprinting.md) — Determine OS versions, service versions, and technology stacks
- [Vulnerability Scanning](04-vuln-scanning.md) — Automated vulnerability identification with Nmap NSE and dedicated scanners

## General Approach

A typical discovery workflow follows this sequence:

1. **Host discovery** — Sweep the target range to identify live systems. ARP for local subnets, ICMP/TCP for remote. Eliminates dead IPs before port scanning.
2. **Port scanning** — Scan live hosts for open TCP/UDP ports. Start with top ports for speed, expand to full range on priority targets.
3. **Service fingerprinting** — Probe open ports to identify exact service versions and underlying OS. This feeds directly into vulnerability research and enumeration.
4. **Vulnerability scanning** — Run targeted NSE scripts or dedicated scanners against identified services to flag known weaknesses.

Each step narrows the scope and increases depth. Resist the urge to scan everything at once — a staged approach is faster, quieter, and produces cleaner results.
