% Filename: 11-digital-forensics/network/packet-capture.md
% Display name: Packet Capture
% Last update: 2026-02-11
% Authors: @TristanInSec

# Packet Capture

## Overview

Packet capture records network traffic at the full packet level, preserving
headers, payloads, and timing information. Forensic packet capture provides
the most complete view of network activity during an incident — revealing
protocol details, transferred data, and communication patterns that flow-level
data cannot. The standard format is PCAP/PCAPNG.

## Capture with tcpdump

```bash
# tcpdump
# https://www.tcpdump.org/

# Capture all traffic on an interface, write to PCAP file
tcpdump -i eth0 -w /evidence/capture.pcap

# Capture with packet count limit
tcpdump -i eth0 -c 10000 -w /evidence/capture.pcap

# Capture with time limit (using timeout)
timeout 3600 tcpdump -i eth0 -w /evidence/capture.pcap

# Capture with full packet snaplen (default is 262144 bytes in modern tcpdump)
tcpdump -i eth0 -s 0 -w /evidence/capture.pcap

# Capture with rotation (new file every 100MB)
tcpdump -i eth0 -w /evidence/capture.pcap -C 100

# Capture with rotation and keep last 10 files
tcpdump -i eth0 -w /evidence/capture.pcap -C 100 -W 10

# Capture with timestamp precision (nanoseconds)
tcpdump -i eth0 --time-stamp-precision=nano -w /evidence/capture.pcap

# Capture on all interfaces
tcpdump -i any -w /evidence/capture.pcap
```

### tcpdump Capture Filters (BPF)

Capture filters use Berkeley Packet Filter (BPF) syntax to reduce the volume
of captured data at the kernel level.

```bash
# tcpdump
# https://www.tcpdump.org/

# Filter by host
tcpdump -i eth0 host 192.168.1.100 -w /evidence/capture.pcap

# Filter by source or destination
tcpdump -i eth0 src host 192.168.1.100 -w /evidence/capture.pcap
tcpdump -i eth0 dst host 10.0.0.1 -w /evidence/capture.pcap

# Filter by port
tcpdump -i eth0 port 443 -w /evidence/capture.pcap
tcpdump -i eth0 port 80 or port 443 -w /evidence/capture.pcap

# Filter by network (subnet)
tcpdump -i eth0 net 192.168.1.0/24 -w /evidence/capture.pcap

# Filter by protocol
tcpdump -i eth0 tcp -w /evidence/capture.pcap
tcpdump -i eth0 udp -w /evidence/capture.pcap
tcpdump -i eth0 icmp -w /evidence/capture.pcap

# Exclude specific traffic
tcpdump -i eth0 not port 22 -w /evidence/capture.pcap
tcpdump -i eth0 not host 10.0.0.1 -w /evidence/capture.pcap

# Combined filters
tcpdump -i eth0 'host 192.168.1.100 and (port 80 or port 443)' -w /evidence/capture.pcap
tcpdump -i eth0 'src net 192.168.1.0/24 and dst port 53' -w /evidence/capture.pcap
```

## Capture with dumpcap

dumpcap is the Wireshark capture engine — optimized for long-duration,
high-volume capture.

```bash
# dumpcap (Wireshark)
# https://www.wireshark.org/

# Basic capture to PCAPNG file
dumpcap -i eth0 -w /evidence/capture.pcapng

# Capture with ring buffer (100MB per file, keep 50 files)
dumpcap -i eth0 -b filesize:102400 -b files:50 -w /evidence/capture.pcapng

# Capture with duration-based rotation (new file every hour)
dumpcap -i eth0 -b duration:3600 -w /evidence/capture.pcapng

# Capture with BPF filter
dumpcap -i eth0 -f "not port 22" -w /evidence/capture.pcapng

# Capture on multiple interfaces
dumpcap -i eth0 -i eth1 -w /evidence/capture.pcapng

# List available interfaces
dumpcap -D
```

## PCAP File Management

```bash
# Wireshark tools (editcap, mergecap, capinfos)
# https://www.wireshark.org/

# Show PCAP file statistics
capinfos /evidence/capture.pcap
# Displays: file type, packet count, time range, data size, average packet size

# Detailed statistics
capinfos -A /evidence/capture.pcap

# Merge multiple PCAP files
mergecap -w /evidence/merged.pcap capture1.pcap capture2.pcap capture3.pcap

# Merge all PCAPs in a directory
mergecap -w /evidence/merged.pcap /evidence/captures/*.pcap

# Split a PCAP by time interval (600 seconds = 10 minutes)
editcap -i 600 /evidence/capture.pcap /evidence/split.pcap

# Split by packet count (10000 packets per file)
editcap -c 10000 /evidence/capture.pcap /evidence/split.pcap

# Extract time range from a PCAP
editcap -A "2026-01-15 14:00:00" -B "2026-01-15 15:00:00" \
  /evidence/capture.pcap /evidence/timewindow.pcap

# Convert between PCAP and PCAPNG formats
editcap -F pcap /evidence/capture.pcapng /evidence/capture.pcap
editcap -F pcapng /evidence/capture.pcap /evidence/capture.pcapng

# Remove duplicate packets
editcap -d /evidence/capture.pcap /evidence/deduped.pcap
```

## Forensic Capture Best Practices

| Practice | Reason |
|---|---|
| Capture full packets (-s 0) | Truncated packets lose payload data |
| Use PCAPNG format | Supports interface info, comments, name resolution |
| Record capture start/end times (UTC) | Timeline correlation |
| Hash PCAP files after capture | Chain of custody / integrity |
| Capture on a span/mirror port or tap | Non-intrusive to network traffic |
| Document capture location | Which network segment, which interface |
| Use ring buffers for long captures | Prevents disk fill |
| Filter carefully | Overly aggressive filters lose evidence |

```bash
# Hash PCAP for chain of custody
sha256sum /evidence/capture.pcap > /evidence/capture.pcap.sha256

# Verify hash
sha256sum -c /evidence/capture.pcap.sha256
```

## References

### Tools

- [tcpdump](https://www.tcpdump.org/)
- [Wireshark / dumpcap](https://www.wireshark.org/)

### Further Reading

- [tcpdump manual](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html/)
