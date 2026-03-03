% Filename: 11-digital-forensics/network/flow-analysis.md
% Display name: Network Flow Analysis
% Last update: 2026-02-11
% Authors: @TristanInSec

# Network Flow Analysis

## Overview

Network flow analysis works with metadata about network connections rather
than full packet content. Flow records (NetFlow, IPFIX, sFlow) capture
source/destination IPs, ports, protocols, byte counts, and timestamps for
each connection. While flows lack payload data, they are more scalable for
long-term storage and provide an excellent view of communication patterns,
data volumes, and network behavior over time.

## Flow Data Concepts

| Field | Description |
|---|---|
| Source IP | Origin IP address |
| Destination IP | Target IP address |
| Source Port | Origin port number |
| Destination Port | Target port number |
| Protocol | TCP, UDP, ICMP, etc. |
| Packets | Number of packets in the flow |
| Bytes | Total bytes transferred |
| Start Time | Flow start timestamp |
| End Time | Flow end timestamp |
| Duration | Flow duration |
| TCP Flags | OR of all TCP flags seen in the flow |

**Flow Protocols:**

| Protocol | Description |
|---|---|
| NetFlow v5 | Cisco proprietary, fixed format, IPv4 only |
| NetFlow v9 | Cisco, template-based, supports IPv6 |
| IPFIX | IETF standard (based on NetFlow v9), extensible |
| sFlow | Sampled flow data, packet headers + counters |

## Collecting Flows with nfpcapd

nfpcapd reads PCAP files and converts them to NetFlow/IPFIX format for
analysis with nfdump.

```bash
# nfdump (nfpcapd)
# https://github.com/phaag/nfdump

# Convert a PCAP file to nfdump flow format
nfpcapd -r /evidence/capture.pcap -w /evidence/flows/

# Process multiple PCAP files
for f in /evidence/pcaps/*.pcap; do
  nfpcapd -r "$f" -w /evidence/flows/
done

# nfcapd as a live collector (listening for NetFlow exports)
nfcapd -p 2055 -w /evidence/flows/ -D
# -p: listen port
# -w: output directory
# -D: daemon mode
```

## Flow Analysis with nfdump

```bash
# nfdump
# https://github.com/phaag/nfdump

# Read and display all flows
nfdump -r /evidence/flows/nfcapd.202601150000

# Read all flow files in a directory
nfdump -R /evidence/flows/

# Read flows within a time range
nfdump -R /evidence/flows/ -t 2026/01/15.14:00:00-2026/01/15.16:00:00
```

### Filtering Flows

```bash
# nfdump
# https://github.com/phaag/nfdump

# Filter by source IP
nfdump -R /evidence/flows/ 'src ip 192.168.1.100'

# Filter by destination IP
nfdump -R /evidence/flows/ 'dst ip 10.0.0.1'

# Filter by port
nfdump -R /evidence/flows/ 'dst port 443'
nfdump -R /evidence/flows/ 'src port 4444 or dst port 4444'

# Filter by protocol
nfdump -R /evidence/flows/ 'proto tcp'
nfdump -R /evidence/flows/ 'proto udp'

# Filter by network
nfdump -R /evidence/flows/ 'src net 192.168.1.0/24'

# Combined filters
nfdump -R /evidence/flows/ 'src ip 192.168.1.100 and dst port 53'
nfdump -R /evidence/flows/ 'src net 10.0.0.0/8 and not dst port 80 and not dst port 443'
```

### Statistical Analysis

```bash
# nfdump
# https://github.com/phaag/nfdump

# Top 10 source IPs by byte count
nfdump -R /evidence/flows/ -s srcip/bytes -n 10

# Top 10 destination IPs by flow count
nfdump -R /evidence/flows/ -s dstip/flows -n 10

# Top 10 destination ports
nfdump -R /evidence/flows/ -s dstport/bytes -n 10

# Top 10 conversations (source-destination pairs)
nfdump -R /evidence/flows/ -s record/bytes -n 10

# Aggregate by source IP
nfdump -R /evidence/flows/ -A srcip -s srcip/bytes -n 20

# Bidirectional flow aggregation
nfdump -R /evidence/flows/ -b -A srcip,dstip

# Output in CSV format
nfdump -R /evidence/flows/ -o csv 'dst port 443' > /evidence/https_flows.csv
```

## Forensic Flow Analysis Techniques

### Beaconing Detection

C2 beacons create regular, periodic connections. Flow data makes these
patterns visible.

```bash
# nfdump
# https://github.com/phaag/nfdump

# Find flows from a suspect IP and analyze timing
nfdump -R /evidence/flows/ -o 'fmt:%ts %td %sa %da %dp %pkt %byt' \
  'src ip 192.168.1.100 and dst port 443'

# Look for:
#   Regular intervals (e.g., every 60s, 300s)
#   Consistent byte counts per flow
#   Same destination IP over extended periods
#   Small, uniform packet counts
```

### Data Exfiltration Detection

Large outbound data transfers may indicate exfiltration.

```bash
# nfdump
# https://github.com/phaag/nfdump

# Find large outbound flows (> 100MB)
nfdump -R /evidence/flows/ 'src net 192.168.0.0/16 and bytes > 104857600' \
  -s record/bytes -n 20

# Find flows to unusual ports
nfdump -R /evidence/flows/ \
  'src net 192.168.0.0/16 and not dst port in [80 443 53 25 587 993 22]' \
  -s dstport/bytes -n 20

# DNS exfiltration — large number of DNS flows
nfdump -R /evidence/flows/ 'dst port 53' -A srcip -s srcip/flows -n 20
# Unusually high DNS query counts from a single host = suspicious
```

### Lateral Movement Detection

```bash
# nfdump
# https://github.com/phaag/nfdump

# Find internal-to-internal connections on management ports
nfdump -R /evidence/flows/ \
  'src net 192.168.0.0/16 and dst net 192.168.0.0/16 and dst port in [445 3389 5985 22 135]' \
  -s record/flows -n 20

# Find new connections from a compromised host
nfdump -R /evidence/flows/ \
  -t 2026/01/15.14:00:00-2026/01/15.18:00:00 \
  'src ip 192.168.1.100 and dst net 192.168.0.0/16' \
  -s dstip/flows -n 20
```

### Scanning Detection

```bash
# nfdump
# https://github.com/phaag/nfdump

# Find hosts with many unique destination IPs (port scanning)
nfdump -R /evidence/flows/ -A srcip -s srcip/flows -n 20
# Host with unusually high flow count = potential scanner

# Find hosts hitting many ports on a single target
nfdump -R /evidence/flows/ 'dst ip 192.168.1.50' \
  -A srcip,dstport -s record/flows -n 30
```

## Flow Visualization Timeline

```bash
# nfdump
# https://github.com/phaag/nfdump

# Output flows sorted by time for timeline analysis
nfdump -R /evidence/flows/ -O tstart \
  'src ip 192.168.1.100' \
  -o 'fmt:%ts %te %td %sa %da %sp %dp %pr %pkt %byt %fl'

# Columns: start_time end_time duration src_ip dst_ip src_port dst_port
#          protocol packets bytes flags
```

## References

### Tools

- [nfdump](https://github.com/phaag/nfdump)

### Further Reading

- [IPFIX RFC 7011](https://www.rfc-editor.org/rfc/rfc7011)
- [NetFlow v9 RFC 3954](https://www.rfc-editor.org/rfc/rfc3954)
