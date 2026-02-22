% Filename: 11-digital-forensics/network/pcap-analysis.md
% Display name: PCAP Analysis
% Last update: 2026-02-17
% Authors: @TristanInSec

# PCAP Analysis

## Overview

PCAP analysis examines captured network traffic to extract forensic evidence —
DNS queries, HTTP requests, file transfers, credentials, TLS metadata, and
communication patterns. tshark (the command-line Wireshark) is the primary tool
for forensic PCAP analysis, providing protocol dissection, filtering, and data
extraction from the command line.

## tshark Analysis

### Basic Analysis

```bash
# tshark (Wireshark)
# https://www.wireshark.org/

# Read a PCAP and display packets
tshark -r /evidence/capture.pcap

# Show packet count
tshark -r /evidence/capture.pcap | wc -l

# Display with specific fields
tshark -r /evidence/capture.pcap -T fields \
  -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e _ws.col.Protocol

# Protocol hierarchy statistics
tshark -r /evidence/capture.pcap -q -z io,phs

# Conversation statistics
tshark -r /evidence/capture.pcap -q -z conv,tcp
tshark -r /evidence/capture.pcap -q -z conv,ip

# Endpoint statistics
tshark -r /evidence/capture.pcap -q -z endpoints,ip
```

### Display Filters

Display filters are applied during analysis (not during capture) and use
Wireshark's filter syntax.

```bash
# tshark (Wireshark)
# https://www.wireshark.org/

# Filter by IP address
tshark -r /evidence/capture.pcap -Y "ip.addr == 192.168.1.100"
tshark -r /evidence/capture.pcap -Y "ip.src == 10.0.0.1"
tshark -r /evidence/capture.pcap -Y "ip.dst == 8.8.8.8"

# Filter by port
tshark -r /evidence/capture.pcap -Y "tcp.port == 443"
tshark -r /evidence/capture.pcap -Y "tcp.dstport == 4444"

# Filter by protocol
tshark -r /evidence/capture.pcap -Y "dns"
tshark -r /evidence/capture.pcap -Y "http"
tshark -r /evidence/capture.pcap -Y "tls"
tshark -r /evidence/capture.pcap -Y "smb2"

# Combined filters
tshark -r /evidence/capture.pcap -Y "ip.src == 192.168.1.100 && tcp.dstport == 80"
tshark -r /evidence/capture.pcap -Y "dns && !dns.response_in"
tshark -r /evidence/capture.pcap -Y 'http.request.method == "POST"'
```

## DNS Analysis

```bash
# tshark (Wireshark)
# https://www.wireshark.org/

# Extract all DNS queries
tshark -r /evidence/capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e frame.time -e ip.src -e dns.qry.name | sort -u -t$'\t' -k3

# Extract DNS queries with response codes
tshark -r /evidence/capture.pcap -Y "dns.flags.response == 1" \
  -T fields -e dns.qry.name -e dns.a -e dns.flags.rcode

# Find unique queried domains
tshark -r /evidence/capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | sort -u

# Find DNS TXT records (used for C2 and data exfiltration)
tshark -r /evidence/capture.pcap -Y "dns.qry.type == 16" \
  -T fields -e dns.qry.name -e dns.txt

# Find NXDOMAIN responses (possible DGA activity)
tshark -r /evidence/capture.pcap -Y "dns.flags.rcode == 3" \
  -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# DNS tunneling indicators: long subdomain labels, high query volume
tshark -r /evidence/capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | awk '{print length, $0}' | sort -rn | head -20
```

## HTTP Analysis

```bash
# tshark (Wireshark)
# https://www.wireshark.org/

# Extract HTTP requests
tshark -r /evidence/capture.pcap -Y "http.request" \
  -T fields -e frame.time -e ip.src -e http.request.method \
  -e http.host -e http.request.uri

# Extract HTTP POST data
tshark -r /evidence/capture.pcap -Y 'http.request.method == "POST"' \
  -T fields -e http.host -e http.request.uri -e http.file_data

# Extract User-Agent strings
tshark -r /evidence/capture.pcap -Y "http.user_agent" \
  -T fields -e ip.src -e http.user_agent | sort -u

# Extract HTTP response codes
tshark -r /evidence/capture.pcap -Y "http.response" \
  -T fields -e ip.src -e http.response.code -e http.content_type

# Export HTTP objects (downloaded files)
tshark -r /evidence/capture.pcap --export-objects http,/evidence/http_objects/

# Export SMB objects
tshark -r /evidence/capture.pcap --export-objects smb,/evidence/smb_objects/

# Follow a specific TCP stream
tshark -r /evidence/capture.pcap -q -z "follow,tcp,ascii,0"
```

## TLS Analysis

```bash
# tshark (Wireshark)
# https://www.wireshark.org/

# Extract TLS Server Name Indication (SNI) — reveals destination domains
tshark -r /evidence/capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

# Extract TLS certificate information
tshark -r /evidence/capture.pcap -Y "tls.handshake.type == 11" \
  -T fields -e ip.src -e x509ce.dNSName -e x509af.serialNumber

# Extract JA3 fingerprints (requires Wireshark with JA3 support)
tshark -r /evidence/capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e ip.dst -e tls.handshake.ja3

# Find self-signed certificates (common in C2)
tshark -r /evidence/capture.pcap -Y "tls.handshake.type == 11" \
  -T fields -e ip.src -e x509af.issuer.rdnSequence \
  -e x509af.subject.rdnSequence
# Self-signed: issuer == subject

# TLS version analysis
tshark -r /evidence/capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e tls.handshake.version | sort | uniq -c | sort -rn
```

## SMB and Lateral Movement Analysis

```bash
# tshark (Wireshark)
# https://www.wireshark.org/

# SMB2 file access (Tree Connect, Create, Read, Write)
tshark -r /evidence/capture.pcap -Y "smb2" \
  -T fields -e frame.time -e ip.src -e ip.dst -e smb2.cmd -e smb2.filename

# SMB2 authentication attempts
tshark -r /evidence/capture.pcap -Y "ntlmssp.auth" \
  -T fields -e ip.src -e ip.dst -e ntlmssp.auth.username -e ntlmssp.auth.domain

# Kerberos authentication
tshark -r /evidence/capture.pcap -Y "kerberos.CNameString" \
  -T fields -e ip.src -e ip.dst -e kerberos.CNameString -e kerberos.realm

# RDP connections
tshark -r /evidence/capture.pcap -Y "rdp" \
  -T fields -e frame.time -e ip.src -e ip.dst
```

## IOC Extraction

```bash
# tshark (Wireshark)
# https://www.wireshark.org/

# Extract all unique destination IPs
tshark -r /evidence/capture.pcap -T fields -e ip.dst | sort -u

# Extract all unique source IPs
tshark -r /evidence/capture.pcap -T fields -e ip.src | sort -u

# Extract all domains (from DNS and HTTP)
tshark -r /evidence/capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | sort -u > /evidence/domains.txt

# Extract IP:port pairs for outbound connections
tshark -r /evidence/capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | sort -u

# Count connections per destination (identify top talkers)
tshark -r /evidence/capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.dst | sort | uniq -c | sort -rn | head -20
```

## References

### Tools

- [Wireshark / tshark](https://www.wireshark.org/)

### Further Reading

- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [tshark Manual](https://www.wireshark.org/docs/man-pages/tshark.html)
