% Filename: 01-fundamentals/networking/tcp-ip.md
% Display name: TCP/IP Fundamentals
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# TCP/IP Fundamentals

## Overview

TCP/IP (Transmission Control Protocol / Internet Protocol) is the protocol suite that runs the internet. Unlike the OSI model's seven layers, TCP/IP uses four layers: Application, Transport, Internet, and Network Access. Every network scan, exploit delivery, and data exfiltration traverses this stack — understanding it is foundational to both offensive and defensive security work.

## Key Concepts

### The TCP/IP Model

```text
Layer            Protocols                    OSI Equivalent
--------------   -------------------------    ---------------
Application      HTTP, DNS, SSH, FTP, SMTP    Layers 5-7
Transport        TCP, UDP                     Layer 4
Internet         IPv4, IPv6, ICMP             Layer 3
Network Access   Ethernet, Wi-Fi, PPP         Layers 1-2
```

### Internet Layer — IP

IP provides logical addressing and routing. Each host gets a unique IP address, and routers forward packets between networks based on destination address.

**IPv4 header fields relevant to security:**

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |    DSCP   |ECN|         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Key fields:
- **TTL (Time to Live):** Decremented by each router. Prevents routing loops. Used by `traceroute` to map network paths — sends packets with incrementing TTL values (1, 2, 3...) and records ICMP Time Exceeded replies
- **Protocol:** Identifies the transport layer protocol (6 = TCP, 17 = UDP, 1 = ICMP)
- **Source/Destination Address:** 32-bit addresses. Source can be spoofed in connectionless protocols (UDP, ICMP)
- **Flags/Fragment Offset:** Controls packet fragmentation. IDS evasion techniques abuse fragmentation to split payloads across fragments

**IPv4 address classes and private ranges (RFC 1918):**

```text
Class   Range                          Private Range         CIDR
-----   -----------------------------  --------------------  -----------
A       1.0.0.0 - 126.255.255.255      10.0.0.0/8            /8
B       128.0.0.0 - 191.255.255.255    172.16.0.0/12         /12
C       192.0.0.0 - 223.255.255.255    192.168.0.0/16        /16
D       224.0.0.0 - 239.255.255.255    —                     Multicast
E       240.0.0.0 - 255.255.255.255    —                     Reserved
```

Special addresses:
- `127.0.0.0/8` — Loopback (localhost)
- `169.254.0.0/16` — Link-local (APIPA, no DHCP response)
- `0.0.0.0` — Default route / all interfaces
- `255.255.255.255` — Broadcast

```bash
# View IP configuration
ip addr show

# Show routing table — how packets reach destinations
ip route show

# Trace the Layer 3 path to a target (ICMP-based)
traceroute -n 8.8.8.8

# Trace using TCP SYN (bypasses ICMP-blocking firewalls)
traceroute -T -p 443 8.8.8.8
```

### Internet Layer — ICMP

ICMP (Internet Control Message Protocol) carries diagnostic and error messages. It rides on top of IP (protocol number 1) but is considered part of the Internet layer.

**Common ICMP types:**

```text
Type  Code  Description              Security Use
----  ----  -----------------------  -------------------------
0     0     Echo Reply               Ping response
3     0     Net Unreachable          Firewall mapping
3     1     Host Unreachable         Host discovery
3     3     Port Unreachable         UDP scan (closed port)
3     13    Comm. Admin. Prohibited  Firewall detected
8     0     Echo Request             Ping / host discovery
11    0     TTL Exceeded             Traceroute
```

```bash
# ICMP echo — basic host discovery
ping -c 3 <target>

# ICMP ping sweep — discover live hosts
# Nmap
# https://nmap.org/
nmap -sn -PE 192.168.1.0/24

# Timestamp request (can reveal host clock skew)
ping -c 1 -T tsonly <target>
```

### Internet Layer — ARP

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on the local network. It operates between Layers 2 and 3. ARP has no authentication — any host can claim any IP-to-MAC mapping, which is the basis of ARP spoofing attacks.

```bash
# View ARP cache
ip neighbour show

# ARP scan — discover hosts on local segment
# Nmap
# https://nmap.org/
nmap -sn -PR 192.168.1.0/24

# Manual ARP request
arping -c 3 192.168.1.1
```

### Transport Layer — TCP

TCP provides reliable, ordered, connection-oriented communication. Every byte is acknowledged, and lost segments are retransmitted.

**TCP header fields relevant to security:**

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Offset| Res.  |C|E|U|A|P|R|S|F|            Window             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**TCP flags and their use in scanning:**

```text
Flag  Name     Purpose                    Scan Type
----  -------  -------------------------  ------------------
SYN   Sync     Initiate connection        SYN scan (-sS)
ACK   Ack      Acknowledge data           ACK scan (-sA)
FIN   Finish   Close connection           FIN scan (-sF)
RST   Reset    Abort connection           Response analysis
PSH   Push     Deliver data immediately   -
URG   Urgent   Priority data              -
```

**TCP three-way handshake:**

```text
Client               Server
  |---- SYN ---------->|     Client sends SYN, seq=x
  |<--- SYN-ACK -------|     Server responds, seq=y, ack=x+1
  |---- ACK ---------->|     Client confirms, ack=y+1
  |                     |     Connection established
```

**TCP connection teardown (four-way):**

```text
Client               Server
  |---- FIN ---------->|     Client initiates close
  |<--- ACK -----------|     Server acknowledges
  |<--- FIN -----------|     Server initiates close
  |---- ACK ---------->|     Client acknowledges
```

**TCP scanning techniques:**

```bash
# SYN scan (half-open) — sends SYN, reads response, sends RST
# Does not complete handshake — stealthier, faster
# Nmap
# https://nmap.org/
nmap -sS -p 1-1000 <target>

# Connect scan — completes full handshake (no root needed)
# Nmap
# https://nmap.org/
nmap -sT -p 1-1000 <target>

# ACK scan — maps firewall rules (filtered vs unfiltered)
# Nmap
# https://nmap.org/
nmap -sA -p 1-1000 <target>
```

**How Nmap interprets TCP scan responses:**

```text
Response Received     SYN Scan Result    Connect Scan Result
--------------------  -----------------  -------------------
SYN-ACK               Open               Open
RST                   Closed             Closed
No response           Filtered           Filtered
ICMP unreachable      Filtered           Filtered
```

**TCP state tracking:**

```bash
# View all TCP connections with state
ss -tan

# Show only established connections
ss -tan state established

# Show listening sockets
ss -tln
```

### Transport Layer — UDP

UDP provides fast, connectionless, unreliable communication. No handshake, no acknowledgment, no ordering. Used where speed matters more than reliability (DNS, SNMP, DHCP, video streaming).

**UDP scanning is slower than TCP** because there is no equivalent of a SYN-ACK response. An open UDP port may simply not respond, making it indistinguishable from a filtered port. Closed ports respond with ICMP Port Unreachable:

```text
Response Received     Nmap Result
--------------------  -----------------
UDP response          Open
No response           Open|Filtered
ICMP Port Unreachable Closed
ICMP other            Filtered
```

```bash
# UDP scan — significantly slower than TCP scans
# Nmap
# https://nmap.org/
nmap -sU -p 53,161,500 <target>

# Combined TCP+UDP scan
# Nmap
# https://nmap.org/
nmap -sS -sU -p T:80,443,U:53,161 <target>

# Send a UDP packet manually
echo "test" | nc -u -w1 <target> 53
```

### Application Layer

The application layer in TCP/IP encompasses what the OSI model splits into Session, Presentation, and Application layers. Protocols at this layer define the format and rules for data exchange between applications.

**Common protocols and their default ports:**

```text
Protocol   Port     Transport  Purpose
--------   ------   ---------  ---------------------------
FTP        21       TCP        File transfer
SSH        22       TCP        Secure remote access
Telnet     23       TCP        Unencrypted remote access
SMTP       25       TCP        Email sending
DNS        53       TCP/UDP    Name resolution
DHCP       67/68    UDP        IP address assignment
HTTP       80       TCP        Web traffic
POP3       110      TCP        Email retrieval
IMAP       143      TCP        Email retrieval
HTTPS      443      TCP        Encrypted web traffic
SMB        445      TCP        File sharing (Windows)
LDAP       389      TCP        Directory services
RDP        3389     TCP        Remote desktop
```

```bash
# Manual HTTP request — direct application layer interaction
curl -v http://example.com/ 2>&1 | head -20

# Manual SMTP session
nc -v mail.example.com 25

# DNS query
dig A example.com @8.8.8.8

# Banner grab — read application layer response
nc -v <target> 22
```

## Practical Examples

### Packet Capture and Analysis

Capturing packets shows all four TCP/IP layers in action:

```bash
# tcpdump
# https://www.tcpdump.org/
# Capture TCP traffic on port 80
tcpdump -i eth0 tcp port 80 -nn

# Capture and save to file for Wireshark analysis
tcpdump -i eth0 -w capture.pcap

# Capture only SYN packets (connection initiations)
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0' -nn

# Capture ICMP traffic
tcpdump -i eth0 icmp -nn

# Read a saved capture file
tcpdump -r capture.pcap -nn
```

**tcpdump output breakdown:**

```text
14:30:01.123456 IP 192.168.1.10.49152 > 10.0.0.5.80: Flags [S], seq 12345, win 64240, length 0
│                  │                     │             │         │         │
│                  └ Source IP.Port       └ Dest IP.Port│         │         └ No payload (SYN)
└ Timestamp                                            └ SYN flag│
                                                                  └ Seq number
```

### Connection Flow Example

A complete HTTP request traverses all four layers:

```text
1. Application:  GET /index.html HTTP/1.1\r\nHost: example.com\r\n
2. Transport:    TCP segment — src port 49152, dst port 80, SYN→SYN-ACK→ACK, then data
3. Internet:     IP packet — src 192.168.1.10, dst 93.184.216.34, TTL 64
4. Network:      Ethernet frame — src MAC to default gateway MAC, type 0x0800 (IPv4)
```

### Socket States and Troubleshooting

Understanding TCP states helps diagnose connection issues:

```text
State            Meaning                          Common Cause of Problems
---------------  -------------------------------  --------------------------
LISTEN           Waiting for connections           Service running, port open
ESTABLISHED      Active connection                 Normal operation
TIME_WAIT        Connection closed, waiting        High connection churn
CLOSE_WAIT       Remote closed, local hasn't       Application bug (not closing)
SYN_SENT         SYN sent, waiting for SYN-ACK    Firewall blocking, host down
SYN_RECV         SYN received, SYN-ACK sent       SYN flood attack
FIN_WAIT_1       FIN sent, waiting for ACK         Normal close in progress
FIN_WAIT_2       FIN ACK'd, waiting for FIN        Remote not closing properly
```

```bash
# Count connections by state — useful for detecting SYN floods
ss -tan | awk '{print $1}' | sort | uniq -c | sort -rn

# Show connections to a specific port
ss -tan dport = :443

# Show process owning a connection (requires root)
ss -tanp
```

### IPv6 Basics

IPv6 uses 128-bit addresses (vs 32-bit IPv4). Security tools must account for IPv6 — hosts with IPv6 enabled may be reachable on addresses not covered by IPv4-only scans.

```text
IPv4:  192.168.1.10
IPv6:  fe80::1a2b:3c4d:5e6f:7890   (link-local)
IPv6:  2001:db8::1                  (global unicast, documentation range)
```

```bash
# Show IPv6 addresses
ip -6 addr show

# Ping via IPv6
ping6 -c 3 fe80::1%eth0

# Nmap IPv6 scan
# Nmap
# https://nmap.org/
nmap -6 -sS -p 80,443 <ipv6_target>
```

## References

### Official Standards

- [RFC 791 — Internet Protocol (IPv4)](https://datatracker.ietf.org/doc/html/rfc791)
- [RFC 9293 — Transmission Control Protocol (TCP)](https://datatracker.ietf.org/doc/html/rfc9293)
- [RFC 768 — User Datagram Protocol (UDP)](https://datatracker.ietf.org/doc/html/rfc768)
- [RFC 792 — Internet Control Message Protocol (ICMP)](https://datatracker.ietf.org/doc/html/rfc792)
- [RFC 8200 — Internet Protocol, Version 6 (IPv6)](https://datatracker.ietf.org/doc/html/rfc8200)

### Supplemental RFCs

- [RFC 1122 — Requirements for Internet Hosts: Communication Layers](https://datatracker.ietf.org/doc/html/rfc1122)
- [RFC 1918 — Address Allocation for Private Internets](https://datatracker.ietf.org/doc/html/rfc1918)
- [RFC 1180 — A TCP/IP Tutorial](https://datatracker.ietf.org/doc/html/rfc1180)

### Tools

- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
