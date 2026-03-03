% Filename: 12-defensive/detection/network-monitoring.md
% Display name: Network Monitoring
% Last update: 2026-02-11
% Authors: @TristanInSec

# Network Monitoring

## Overview

Network monitoring provides visibility into traffic patterns, protocol usage,
and potential threats crossing the network. This includes intrusion detection
systems (IDS) that match known attack signatures, network traffic analysis
(NTA) for behavioral anomalies, and flow monitoring for connection metadata.
Suricata is the primary open-source IDS/IPS covered here.

## Suricata IDS/IPS

### Configuration

```bash
# Suricata
# https://suricata.io/

# Main configuration file
# /etc/suricata/suricata.yaml

# Key configuration settings:
#   HOME_NET: Define internal network ranges
#   EXTERNAL_NET: Define external networks (usually !$HOME_NET)
#   default-rule-path: Location of rule files
#   default-log-dir: Where Suricata writes logs

# Test configuration
suricata -T -c /etc/suricata/suricata.yaml

# Run Suricata on a network interface
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Run Suricata on a PCAP file (offline analysis)
suricata -c /etc/suricata/suricata.yaml -r capture.pcap

# Run as daemon
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D
```

### Rule Management

```bash
# suricata-update
# https://suricata.io/

# Update rules from default sources (Emerging Threats Open)
sudo suricata-update

# List available rule sources
sudo suricata-update list-sources

# Enable a specific source
sudo suricata-update enable-source et/open

# Update and reload rules
sudo suricata-update && sudo suricatasc -c reload-rules
```

### Suricata Rule Syntax

```bash
# Rule structure:
# action protocol src_ip src_port -> dst_ip dst_port (options;)

# Actions: alert, pass, drop (IPS mode), reject
# Protocols: tcp, udp, icmp, ip, http, dns, tls, smb, ssh, etc.

# Example: detect outbound connections to known C2 port
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"Possible C2 - port 4444 outbound"; sid:1000001; rev:1;)

# Example: detect PowerShell download cradle in HTTP
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PowerShell download cradle"; flow:to_server,established; content:"powershell"; nocase; content:"downloadstring"; nocase; sid:1000002; rev:1;)

# Example: detect DNS query to known malicious domain
alert dns $HOME_NET any -> any any (msg:"DNS query to suspicious domain"; dns.query; content:"malicious.example.com"; nocase; sid:1000003; rev:1;)

# Example: detect SSH brute force (threshold)
alert ssh $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH brute force"; flow:to_server; threshold:type both, track by_src, count 5, seconds 60; sid:1000004; rev:1;)

# Key rule options:
#   content:"string" — match byte content
#   nocase — case-insensitive match
#   pcre:"/regex/" — regex match
#   flow:to_server,established — match established connections to server
#   threshold:type,track,count,seconds — rate-based detection
#   sid:N — unique signature ID
#   rev:N — rule revision number
```

### Suricata Logs

```bash
# Suricata log files (default: /var/log/suricata/)

# eve.json — JSON event log (primary analysis source)
# Contains: alerts, DNS, HTTP, TLS, flow, fileinfo, stats

# View alerts from eve.json
cat /var/log/suricata/eve.json | \
  python3 -m json.tool | grep -A5 '"event_type": "alert"'

# Extract alert signatures
grep '"event_type":"alert"' /var/log/suricata/eve.json | \
  python3 -c "import sys,json; [print(json.loads(l)['alert']['signature']) for l in sys.stdin]" | \
  sort | uniq -c | sort -rn

# fast.log — one-line alert format (quick review)
# stats.log — engine performance statistics
```

## Network Traffic Analysis

### Baseline and Anomaly Detection

```text
Establish baselines for:

Traffic volume:
  - Average bytes/packets per hour by network segment
  - Normal peak hours vs. off-hours traffic ratios
  - Typical protocol distribution (HTTP, DNS, HTTPS percentages)

Connection patterns:
  - Normal internal-to-external connection counts
  - Expected DNS query rates per host
  - Typical session durations by protocol

Alert on deviations:
  - Sudden volume spikes (possible exfiltration or DDoS)
  - New protocols appearing (tunneling, C2)
  - Connections to new external IPs (especially from servers)
  - Off-hours traffic from workstations
```

### Detection with tcpdump

```bash
# tcpdump
# https://www.tcpdump.org/

# Monitor DNS traffic for suspicious queries
sudo tcpdump -i eth0 -n port 53 -l | grep -iE "txt|mx|null"

# Detect large DNS responses (possible DNS tunneling)
sudo tcpdump -i eth0 -n port 53 -l | awk '{if (length($0) > 200) print}'

# Monitor for non-standard ports
sudo tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-syn != 0 and not port 80 and not port 443 and not port 22 and not port 53'

# Detect ARP spoofing
sudo tcpdump -i eth0 -n arp
```

### Detection with tshark

```bash
# tshark (Wireshark)
# https://www.wireshark.org/

# Top DNS queries by volume (possible beaconing)
tshark -r capture.pcap -Y "dns.qr==0" -T fields -e dns.qry.name | \
  sort | uniq -c | sort -rn | head -20

# HTTP requests to non-standard ports
tshark -r capture.pcap -Y "http.request and tcp.dstport != 80 and tcp.dstport != 443"

# TLS connections with self-signed certificates
tshark -r capture.pcap -Y "tls.handshake.type==11" -T fields \
  -e ip.dst -e tls.handshake.certificate

# Detect beaconing — regular connection intervals
tshark -r capture.pcap -Y "ip.dst==suspicious.ip" -T fields -e frame.time_epoch | \
  awk 'NR>1{print $1-prev}{prev=$1}'
```

## Network Flow Monitoring

```bash
# nfpcapd / nfdump
# https://github.com/phaag/nfdump

# Convert PCAP to NetFlow data
nfpcapd -r capture.pcap -w /tmp/flows/

# Analyze flows — top talkers
nfdump -R /tmp/flows/ -s srcip/bytes -n 20

# Large outbound transfers (possible exfiltration)
nfdump -R /tmp/flows/ -o extended \
  'src net 10.0.0.0/8 and not dst net 10.0.0.0/8 and bytes > 100M'

# Connections to unusual ports
nfdump -R /tmp/flows/ -s dstport/flows \
  'dst port > 1024 and proto tcp' -n 20
```

## References

### Tools

- [Suricata](https://suricata.io/)
- [tcpdump](https://www.tcpdump.org/)
- [tshark (Wireshark)](https://www.wireshark.org/)
- [nfdump](https://github.com/phaag/nfdump)

### Further Reading

- [Suricata Documentation](https://docs.suricata.io/en/latest/)
- [SANS Network Forensics Poster](https://www.sans.org/posters/network-forensics-poster/)
