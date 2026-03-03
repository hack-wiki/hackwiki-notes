% Filename: 11-digital-forensics/network/overview.md
% Display name: Network Forensics
% Last update: 2026-02-11
% Authors: @TristanInSec

# Network Forensics

## Overview

Network forensics involves capturing, recording, and analyzing network traffic
to detect intrusions, reconstruct attack timelines, and extract evidence. It
spans full packet capture (PCAP), flow-level metadata (NetFlow/IPFIX), and
protocol-specific analysis. Network evidence complements host-based forensics
by revealing lateral movement, data exfiltration, and C2 communication.

## Topics in This Section

- [Packet Capture](packet-capture.md) — capturing network traffic with tcpdump,
  dumpcap, and Wireshark for forensic analysis
- [PCAP Analysis](pcap-analysis.md) — analyzing captured packets with tshark,
  Wireshark, and automated extraction tools
- [Network Flow Analysis](flow-analysis.md) — working with NetFlow, IPFIX, and
  flow data using nfdump and nfpcapd

## General Approach

```text
Network incident detected
    │
    ├── Capture / collect evidence
    │   ├── Full packet capture (tcpdump, dumpcap)
    │   ├── Flow records (nfpcapd, router exports)
    │   └── Existing PCAP from IDS/NSM sensors
    │
    ├── Initial triage
    │   ├── Protocol distribution (capinfos, tshark stats)
    │   ├── Top talkers / conversation analysis
    │   └── Time range identification
    │
    ├── Deep analysis
    │   ├── DNS queries → C2, tunneling, DGA
    │   ├── HTTP/HTTPS → downloads, exfiltration, beacons
    │   ├── TLS analysis → certificate anomalies, JA3/JA4
    │   └── SMB/RDP/SSH → lateral movement
    │
    ├── Extract artifacts
    │   ├── Files from HTTP/SMB streams
    │   ├── Credentials from cleartext protocols
    │   └── IOCs (IPs, domains, user agents, hashes)
    │
    └── Correlate with host-based evidence and timeline
```
