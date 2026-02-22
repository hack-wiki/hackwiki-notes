% Filename: 01-fundamentals/networking/overview.md
% Display name: Networking Overview
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Networking

## Overview

Networking fundamentals underpin every area of cybersecurity — from scanning and enumeration to exploit delivery, lateral movement, and forensic analysis. This section covers the conceptual foundations: how data moves across networks, how systems are addressed and segmented, what protocols are in use, and how to diagnose connectivity problems. These topics are prerequisites for all offensive and defensive techniques in later sections.

## Topics in This Section

- [OSI Model](osi-model.md) — The seven-layer reference model for network communication, with security relevance at each layer
- [TCP/IP Fundamentals](tcp-ip.md) — The four-layer protocol suite that runs the internet: IP, ICMP, ARP, TCP, UDP, and packet capture
- [Network Protocols](protocols.md) — Major application and service protocols (DNS, HTTP, SSH, SMB, LDAP, SNMP, and more) with security implications
- [Subnetting](subnetting.md) — CIDR notation, subnet calculation, private ranges, VLSM, and scope definition for engagements
- [Ports](ports.md) — Comprehensive port reference tables, port states, scanning techniques, and service identification
- [Network Troubleshooting](troubleshooting.md) — Bottom-up diagnostic methodology, connectivity checklists, firewall analysis, DNS debugging, and packet capture

## General Approach

Start with the models (OSI and TCP/IP) to understand how layers interact, then study protocols and ports to know what services look like on the wire. Subnetting knowledge is essential before any scanning — understanding scope boundaries prevents testing out-of-scope targets. Troubleshooting skills tie everything together and are used constantly during engagements when tools fail to connect, scans return unexpected results, or tunnels drop.

**Recommended reading order:**

1. OSI Model → TCP/IP Fundamentals (conceptual foundation)
2. Protocols → Ports (service identification)
3. Subnetting (scope and addressing)
4. Troubleshooting (applied diagnostics)
