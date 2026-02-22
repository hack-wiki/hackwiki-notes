% Filename: 01-fundamentals/networking/osi-model.md
% Display name: OSI Model
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# OSI Model

## Overview

The Open Systems Interconnection (OSI) model is a seven-layer framework standardized by ISO (ISO/IEC 7498-1) that describes how network communication works from physical signals to application data. Each layer has a defined role and communicates with the layers directly above and below it. Understanding the OSI model is essential for network troubleshooting, packet analysis, firewall rule design, and attack surface identification.

The TCP/IP model (4 layers) is what the internet actually runs on, but the OSI model provides finer granularity that is useful for analysis and discussion — particularly at layers 1-2 and 5-7 where TCP/IP collapses distinctions.

## Key Concepts

### Layer 7 — Application

Provides network services directly to end-user applications. This is where users interact with the network.

**Protocols:** HTTP, HTTPS, FTP, SMTP, DNS, SSH, SNMP, LDAP, SMB

**PDU:** Data

**Security relevance:**
- Web application attacks target this layer (SQL injection, XSS, CSRF)
- Protocol-level vulnerabilities (SMTP open relays, DNS zone transfers)
- Application firewalls (WAFs) inspect traffic at this layer
- Authentication and authorization happen here

```bash
# DNS query — Layer 7 protocol over UDP
dig A example.com

# HTTP request — Layer 7 protocol over TCP
curl -I https://example.com

# SMTP session — direct Layer 7 interaction
nc -v mail.example.com 25
```

### Layer 6 — Presentation

Handles data formatting, encryption, and compression. Ensures data from the application layer is readable by the receiving system.

**Functions:** TLS/SSL encryption, character encoding (ASCII, UTF-8), data compression, serialization (JSON, XML, ASN.1)

**PDU:** Data

**Security relevance:**
- TLS/SSL operates here — downgrade attacks (POODLE, BEAST) target this layer
- Certificate validation and PKI trust chains
- Encoding issues can lead to security bypasses (double encoding, null bytes)

```bash
# OpenSSL
# https://www.openssl.org/
# Inspect TLS certificate and negotiated cipher — Layer 6 encryption
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates

# Show supported TLS versions
openssl s_client -connect example.com:443 -tls1_2 </dev/null 2>/dev/null | grep "Protocol"
```

### Layer 5 — Session

Manages sessions between applications — establishment, maintenance, and teardown of connections.

**Functions:** Session establishment, synchronization, dialog control (half-duplex/full-duplex)

**PDU:** Data

**Security relevance:**
- Session hijacking and session fixation attacks
- NetBIOS sessions (TCP 139) operate at this layer
- RPC session management
- Token replay and session persistence attacks

```bash
# NetBIOS session — Layer 5 session protocol
# Nmap
# https://nmap.org/
nmap -p 139 --script nbstat <target>

# RPC session enumeration
rpcclient -U "" -N <target>
```

### Layer 4 — Transport

Provides end-to-end communication between processes. Handles segmentation, flow control, and error recovery.

**Protocols:** TCP (connection-oriented, reliable), UDP (connectionless, fast)

**PDU:** Segment (TCP) / Datagram (UDP)

**Security relevance:**
- Port scanning operates at this layer (SYN scan, UDP scan)
- TCP handshake manipulation (SYN floods, RST injection)
- Firewall rules commonly filter by port and protocol at this layer
- Connection state tracking in stateful firewalls

```bash
# TCP SYN scan — sends SYN, reads SYN-ACK/RST response
# Nmap
# https://nmap.org/
nmap -sS -p 1-1000 <target>

# UDP scan — sends UDP probes, ICMP unreachable = closed
# Nmap
# https://nmap.org/
nmap -sU -p 53,161,500 <target>

# View active TCP connections and listening ports
ss -tuln
```

**TCP three-way handshake:**

```text
Client → SYN         → Server    (synchronize)
Client ← SYN-ACK     ← Server    (synchronize-acknowledge)
Client → ACK         → Server    (acknowledge)
```

**TCP connection teardown:**

```text
Client → FIN         → Server    (finish)
Client ← ACK         ← Server    (acknowledge)
Client ← FIN         ← Server    (finish)
Client → ACK         → Server    (acknowledge)
```

### Layer 3 — Network

Handles logical addressing and routing between different networks. This is where IP operates.

**Protocols:** IPv4, IPv6, ICMP, IGMP, IPsec

**PDU:** Packet

**Security relevance:**
- IP spoofing and source routing attacks
- ICMP-based reconnaissance (ping sweeps, traceroute)
- Routing protocol attacks (BGP hijacking, OSPF injection)
- VPNs and IPsec tunnels operate at this layer
- ACLs on routers filter at this layer

```bash
# ICMP ping sweep — Layer 3 reachability check
# Nmap
# https://nmap.org/
nmap -sn 192.168.1.0/24

# Traceroute — maps Layer 3 path
traceroute -n <target>

# Show routing table
ip route show
```

### Layer 2 — Data Link

Handles physical addressing (MAC) and frame delivery on the local network segment. Divided into two sublayers: LLC (Logical Link Control) and MAC (Media Access Control).

**Protocols:** Ethernet (IEEE 802.3), Wi-Fi (IEEE 802.11), ARP, PPP, STP

**PDU:** Frame

**Security relevance:**
- ARP spoofing/poisoning for man-in-the-middle attacks
- MAC flooding to overwhelm switch CAM tables
- VLAN hopping (double tagging, switch spoofing)
- 802.1X port-based authentication operates here
- Rogue DHCP servers

```bash
# View MAC addresses and ARP table — Layer 2 addressing
ip neighbour show

# ARP scan — discover hosts on local segment
# Nmap
# https://nmap.org/
nmap -sn -PR 192.168.1.0/24

# Show interface MAC addresses
ip link show
```

### Layer 1 — Physical

The physical medium — electrical signals, light pulses, or radio waves. Defines cables, connectors, voltages, and bit timing.

**Media:** Ethernet cables (Cat5e/Cat6), fiber optic, Wi-Fi radio, coaxial

**PDU:** Bit

**Security relevance:**
- Physical access attacks (cable tapping, rogue devices)
- Electromagnetic emanation (TEMPEST)
- Physical keyloggers
- Jamming attacks on wireless signals
- Network jack access in buildings

## Layer Summary Table

```text
Layer  Name          PDU       Key Protocols         Devices
-----  ------------  --------  --------------------  ----------------
7      Application   Data      HTTP, DNS, SSH, SMB   Proxy, WAF
6      Presentation  Data      TLS/SSL, MIME         -
5      Session       Data      NetBIOS, RPC          -
4      Transport     Segment   TCP, UDP              Firewall, LB
3      Network       Packet    IP, ICMP, IPsec       Router, L3 Switch
2      Data Link     Frame     Ethernet, ARP, STP    Switch, Bridge
1      Physical      Bit       Ethernet (physical)   Hub, Cable, NIC
```

## Practical Examples

### Packet Analysis with Wireshark

Wireshark displays captures using the OSI model structure. Each layer is visible as a protocol header in the packet detail pane:

```text
Frame (Layer 1-2): Ethernet II, Src: aa:bb:cc:dd:ee:ff, Dst: 11:22:33:44:55:66
Internet Protocol (Layer 3): Src: 192.168.1.10, Dst: 10.0.0.5
Transmission Control Protocol (Layer 4): Src Port: 49152, Dst Port: 443
Transport Layer Security (Layer 6): TLSv1.3 Application Data
Hypertext Transfer Protocol (Layer 7): GET /index.html HTTP/1.1
```

Filter by layer in Wireshark:

```text
Layer 2:  eth.addr == aa:bb:cc:dd:ee:ff
Layer 3:  ip.addr == 192.168.1.10
Layer 4:  tcp.port == 443
Layer 7:  http.request.method == "GET"
```

### Mapping Attacks to Layers

Understanding which layer an attack targets helps select the correct defense:

```text
Attack                    Layer  Defense
------------------------  -----  ---------------------------
SQL Injection             7      WAF, input validation
TLS Downgrade (POODLE)    6      Disable SSLv3/weak ciphers
Session Hijacking         5      Secure tokens, HTTPS
SYN Flood                 4      SYN cookies, rate limiting
IP Spoofing               3      Ingress filtering (BCP38)
ARP Spoofing              2      Dynamic ARP Inspection
Cable Tapping             1      Physical security, encryption
```

### Encapsulation

Data moves down the stack for transmission, gaining headers at each layer (encapsulation). The receiving host strips headers moving up the stack (decapsulation):

```text
Application Data   (HTTP, DNS, TLS — no separate OSI session/presentation headers in real packets)
  ↓ + TCP/UDP header
Transport Segment  [TCP Header | Data]
  ↓ + IP header
Network Packet     [IP Header | TCP Header | Data]
  ↓ + Ethernet header + trailer
Data Link Frame    [Eth Header | IP Header | TCP Header | Data | FCS]
  ↓ → transmitted as bits
Physical           01010110 11001010 ...
```

### OSI vs TCP/IP Model

The TCP/IP model is the practical implementation used on the internet. The OSI model provides more granular layer separation:

```text
OSI Model              TCP/IP Model
-----------            ---------------
7 Application    ─┐
6 Presentation    ├──  Application
5 Session        ─┘
4 Transport      ────  Transport
3 Network        ────  Internet
2 Data Link      ─┐
1 Physical       ─┘──  Network Access
```

## References

### Official Standards

- [ISO/IEC 7498-1 — OSI Basic Reference Model](https://www.iso.org/standard/20269.html)
- [RFC 1122 — Requirements for Internet Hosts: Communication Layers](https://datatracker.ietf.org/doc/html/rfc1122)

### Protocol RFCs

- [RFC 791 — Internet Protocol (IPv4)](https://datatracker.ietf.org/doc/html/rfc791)
- [RFC 793 — Transmission Control Protocol (TCP)](https://datatracker.ietf.org/doc/html/rfc793)
- [RFC 768 — User Datagram Protocol (UDP)](https://datatracker.ietf.org/doc/html/rfc768)
- [RFC 826 — Ethernet Address Resolution Protocol (ARP)](https://datatracker.ietf.org/doc/html/rfc826)
- [RFC 9110 — HTTP Semantics (HTTP/1.1, supersedes RFC 2616)](https://datatracker.ietf.org/doc/html/rfc9110)

### Tools

- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
