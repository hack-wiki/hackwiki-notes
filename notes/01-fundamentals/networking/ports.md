% Filename: 01-fundamentals/networking/ports.md
% Display name: Ports
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Ports

## Overview

A port is a 16-bit number (0-65535) that identifies a specific process or service on a host. While IP addresses route traffic to a machine, ports route traffic to an application on that machine. The combination of IP address, protocol (TCP/UDP), and port number forms a socket — the endpoint for network communication. Knowing which ports map to which services is fundamental to scanning, enumeration, firewall analysis, and attack surface identification.

## Key Concepts

### Port Ranges

IANA (Internet Assigned Numbers Authority) divides the port space into three ranges:

```text
Range          Name              Description
-----------    ----------------  ------------------------------------------
0 - 1023       Well-Known        Assigned to common services (HTTP, SSH, DNS)
                                 Binding requires root/admin on most OS
1024 - 49151   Registered        Assigned by IANA on request (databases, apps)
                                 Any user can bind
49152 - 65535  Dynamic/Ephemeral  Client-side source ports, temporary
                                 Assigned by the OS for outbound connections
```

When a client connects to a server, the client's OS assigns a random ephemeral port as the source. The destination is the server's well-known or registered port:

```text
Client (192.168.1.10:49832) → Server (10.0.0.5:443)
       ephemeral source port         well-known dest port
```

### Sockets

A socket uniquely identifies a connection using five values:

```text
Protocol  Source IP       Source Port  Dest IP       Dest Port
--------  -------------  ----------   -----------   ---------
TCP       192.168.1.10   49832        10.0.0.5      443
```

A server can handle many clients on the same port because each connection has a unique socket (different source IP/port combination).

### TCP vs UDP Ports

TCP and UDP port spaces are independent. Port 53/TCP (DNS zone transfers) and port 53/UDP (DNS queries) are different sockets handled by the same or different processes. A full port scan must check both:

```bash
# Scan TCP and UDP ports
# Nmap
# https://nmap.org/
nmap -sS -sU -p T:1-1000,U:53,67,68,69,123,161,162,500,514 <target>
```

## Port Reference — Well-Known Services

### Core Infrastructure

```text
Port    Proto  Service         Description
------  -----  --------------- ------------------------------------------
20      TCP    FTP Data        FTP data transfer (active mode)
21      TCP    FTP Control     FTP command channel
22      TCP    SSH             Secure Shell, SCP, SFTP
23      TCP    Telnet          Unencrypted remote access
25      TCP    SMTP            Email delivery (server-to-server)
53      TCP/UDP DNS            Domain name resolution
67      UDP    DHCP Server     Dynamic IP assignment (server)
68      UDP    DHCP Client     Dynamic IP assignment (client)
69      UDP    TFTP            Trivial File Transfer (no auth)
80      TCP    HTTP            Web traffic (cleartext)
88      TCP/UDP Kerberos       AD authentication
110     TCP    POP3            Email retrieval
111     TCP/UDP RPCbind        RPC port mapper (NFS, NIS)
123     UDP    NTP             Time synchronization
135     TCP    MS-RPC          Microsoft RPC endpoint mapper
137     UDP    NetBIOS-NS      NetBIOS name service
138     UDP    NetBIOS-DGM     NetBIOS datagram service
139     TCP    NetBIOS-SSN     NetBIOS session (SMB over NetBIOS)
143     TCP    IMAP            Email retrieval (server-side)
161     UDP    SNMP            Network management (queries)
162     UDP    SNMP Trap       Network management (alerts)
389     TCP/UDP LDAP           Directory services
443     TCP    HTTPS           Web traffic (TLS encrypted)
445     TCP    SMB             File sharing (direct over TCP)
464     TCP/UDP Kpasswd        Kerberos password change
465     TCP    SMTPS           SMTP over TLS (implicit)
500     UDP    IKE/ISAKMP      IPsec key exchange
514     UDP    Syslog          Log forwarding
587     TCP    SMTP Submission Email submission (STARTTLS)
593     TCP    MS-RPC over HTTP RPC tunneled through HTTP
636     TCP    LDAPS           LDAP over TLS
993     TCP    IMAPS           IMAP over TLS
995     TCP    POP3S           POP3 over TLS
```

### Windows / Active Directory

```text
Port    Proto  Service         Description
------  -----  --------------- ------------------------------------------
88      TCP/UDP Kerberos       Authentication
135     TCP    MS-RPC          Endpoint mapper
137     UDP    NetBIOS-NS      NetBIOS name service
138     UDP    NetBIOS-DGM     NetBIOS datagram service
139     TCP    NetBIOS-SSN     NetBIOS session (SMB over NetBIOS)
389     TCP/UDP LDAP           Directory queries
445     TCP    SMB             File/printer sharing, lateral movement
464     TCP/UDP Kpasswd        Kerberos password changes
593     TCP    RPC-HTTP        RPC over HTTP proxy
636     TCP    LDAPS           Encrypted LDAP
3268    TCP    LDAP GC         Global Catalog (multi-domain)
3269    TCP    LDAPS GC        Global Catalog over TLS
3389    TCP/UDP RDP            Remote Desktop
5985    TCP    WinRM HTTP      Windows Remote Management
5986    TCP    WinRM HTTPS     Windows Remote Management (TLS)
9389    TCP    ADWS            AD Web Services
```

### Databases

```text
Port    Proto  Service         Description
------  -----  --------------- ------------------------------------------
1433    TCP    MSSQL           Microsoft SQL Server
1434    UDP    MSSQL Browser   SQL Server discovery
1521    TCP    Oracle          Oracle Database listener
3306    TCP    MySQL           MySQL / MariaDB
5432    TCP    PostgreSQL      PostgreSQL
6379    TCP    Redis           Redis key-value store
27017   TCP    MongoDB         MongoDB
```

### Web and Application Servers

```text
Port    Proto  Service         Description
------  -----  --------------- ------------------------------------------
80      TCP    HTTP            Standard web
443     TCP    HTTPS           Encrypted web
2082    TCP    cPanel          cPanel HTTP
2083    TCP    cPanel SSL      cPanel HTTPS
3000    TCP    Various         Grafana, Node.js dev servers
4443    TCP    HTTPS Alt       Common alternate HTTPS
8000    TCP    HTTP Alt        Python dev server, various apps
8080    TCP    HTTP Proxy      Tomcat, Burp, HTTP proxies
8443    TCP    HTTPS Alt       Tomcat HTTPS, various apps
8888    TCP    HTTP Alt        Jupyter, various apps
9090    TCP    Various         Prometheus, Cockpit
9200    TCP    Elasticsearch   Elasticsearch HTTP API
9443    TCP    HTTPS Alt       Various management consoles
```

### Remote Access and Management

```text
Port    Proto  Service         Description
------  -----  --------------- ------------------------------------------
22      TCP    SSH             Secure Shell
23      TCP    Telnet          Unencrypted terminal
161     UDP    SNMP            Device management
623     UDP    IPMI/BMC        Out-of-band management
2049    TCP/UDP NFS            Network File System
3389    TCP    RDP             Remote Desktop (Windows)
5800    TCP    VNC HTTP        VNC over HTTP
5900    TCP    VNC             Virtual Network Computing
5985    TCP    WinRM           Windows Remote Management
```

### Email

```text
Port    Proto  Service         Description
------  -----  --------------- ------------------------------------------
25      TCP    SMTP            Mail delivery
110     TCP    POP3            Mail retrieval (cleartext)
143     TCP    IMAP            Mail retrieval (cleartext)
465     TCP    SMTPS           Mail delivery (implicit TLS)
587     TCP    Submission      Mail submission (STARTTLS)
993     TCP    IMAPS           Mail retrieval (TLS)
995     TCP    POP3S           Mail retrieval (TLS)
```

### File Transfer and Sharing

```text
Port    Proto  Service         Description
------  -----  --------------- ------------------------------------------
21      TCP    FTP             File Transfer Protocol
22      TCP    SFTP/SCP        Secure file transfer (over SSH)
69      UDP    TFTP            Trivial FTP (no authentication)
111     TCP/UDP RPCbind        NFS port mapper
139     TCP    NetBIOS-SSN     SMB over NetBIOS
445     TCP    SMB             Direct file sharing
873     TCP    Rsync           File synchronization
2049    TCP/UDP NFS            Network File System
```

### VPN and Tunneling

```text
Port    Proto  Service         Description
------  -----  --------------- ------------------------------------------
500     UDP    IKE             IPsec key exchange
1194    TCP/UDP OpenVPN        OpenVPN
1701    UDP    L2TP            Layer 2 Tunneling Protocol
1723    TCP    PPTP            Point-to-Point Tunneling
4500    UDP    IPsec NAT-T     IPsec NAT traversal
51820   UDP    WireGuard       WireGuard VPN
```

## Port States

When scanning, Nmap classifies ports into six states:

```text
State            Meaning                          Typical Cause
---------------  -------------------------------  ---------------------------
open             Service accepting connections     Application listening
closed           Reachable but no service           No application on this port
filtered         Cannot determine (no response)    Firewall dropping packets
unfiltered       Reachable, open/closed unknown    ACK scan result
open|filtered    Cannot determine (UDP)            Open UDP port (no response)
closed|filtered  Cannot determine                  IP ID idle scan result
```

```bash
# Show only open ports (skip closed/filtered)
# Nmap
# https://nmap.org/
nmap -sS --open -p 1-65535 <target>

# Version detection on open ports
# Nmap
# https://nmap.org/
nmap -sV --open -p 22,80,443,445,3389 <target>
```

## Practical Examples

### Port Scanning Techniques

```bash
# Scan top 1000 most common ports (Nmap default)
# Nmap
# https://nmap.org/
nmap -sS <target>

# Scan top 100 ports (faster)
# Nmap
# https://nmap.org/
nmap -sS --top-ports 100 <target>

# Scan all 65535 TCP ports
# Nmap
# https://nmap.org/
nmap -sS -p- <target>

# Scan specific ports
# Nmap
# https://nmap.org/
nmap -sS -p 22,80,443,445,3389 <target>

# Scan a port range
# Nmap
# https://nmap.org/
nmap -sS -p 1-1000 <target>

# Combined TCP and UDP scan
# Nmap
# https://nmap.org/
nmap -sS -sU -p T:80,443,U:53,161 <target>

# Service version detection on all ports
# Nmap
# https://nmap.org/
nmap -sV -p- <target>
```

### Nmap Port Specification Syntax

```text
Syntax              Meaning
------------------  ----------------------------------
-p 22               Single port
-p 22,80,443        Comma-separated list
-p 1-1000           Range
-p-                 All 65535 ports (shorthand for -p 1-65535)
-p U:53,161,T:80    Protocol-specific
--top-ports 100     Top N most common ports
--exclude-ports 22  Skip specific ports
```

### Viewing Local Ports

```bash
# List all listening TCP ports with process names
ss -tlnp

# List all listening UDP ports with process names
ss -ulnp

# Show all connections (listening + established)
ss -tunap

# Find what process is using a specific port
ss -tlnp | grep ':8080'

# Alternative: use lsof to find port owners
lsof -i :443

# Show all listening sockets with lsof
lsof -i -P -n | grep LISTEN
```

**Interpreting ss output:**

```text
State    Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process
LISTEN   0       128     0.0.0.0:22           0.0.0.0:*          users:(("sshd",pid=1234))
│                        │       │                                │
│                        │       └ Port 22                        └ Process name and PID
│                        └ 0.0.0.0 = listening on all interfaces
└ LISTEN = waiting for connections
```

`0.0.0.0` means listening on all IPv4 interfaces. `127.0.0.1` means only accessible locally. `::` is the IPv6 equivalent of all interfaces.

### Common Non-Standard Port Assignments

Services are often moved to non-standard ports for obscurity or to avoid conflicts. During engagements, version detection (`-sV`) identifies the actual service regardless of port number:

```text
Non-Standard Port   Common Service              Why
-----------------   -------------------------   ---------------------------
2222, 2200          SSH                         Avoid automated scanning
8080, 8443          HTTP/HTTPS                  Proxy, dev server, Tomcat
8888                HTTP                        Jupyter, admin panels
10000               Webmin                      Server management
10443               HTTPS                       Various management consoles
27017               MongoDB                     Default, often exposed
6379                Redis                       Default, often no auth
9200                Elasticsearch               Default, often exposed
```

```bash
# Detect actual service on non-standard ports
# Nmap
# https://nmap.org/
nmap -sV -p 2222,8080,8443,10000 <target>
```

### Quick Port Check with Netcat

```bash
# Test if a single TCP port is open
nc -zv <target> 443

# Scan a range of ports
nc -zv <target> 20-25

# Test UDP port (less reliable — no response doesn't mean closed)
nc -zuv <target> 161
```

### Nmap Service Database

Nmap uses `/usr/share/nmap/nmap-services` to map port numbers to service names and frequency data. The frequency value indicates how often Nmap has found the port open in internet-wide scans — this is what `--top-ports` uses to rank ports:

```bash
# Nmap
# https://nmap.org/
# View port-to-service mappings
grep -E "^(ssh|http|smb)" /usr/share/nmap/nmap-services

# Find which service is associated with a port
grep -w "8080" /usr/share/nmap/nmap-services

# Count entries in the database
grep -c "^[^#]" /usr/share/nmap/nmap-services
```

## Port Security Considerations

**Reducing attack surface:**
- Close unnecessary ports — every open port is a potential entry point
- Use host-based firewalls (`iptables`/`nftables`, Windows Firewall) to restrict access
- Bind services to specific interfaces (127.0.0.1 for local-only, specific IP for restricted access)
- Change default ports only as defense-in-depth, not as a primary security measure — port scanning with `-sV` identifies services regardless of port

**Firewall analysis during engagements:**
- Compare SYN scan results with ACK scan results to identify filtered vs unfiltered ports
- A port showing `filtered` on SYN scan but `unfiltered` on ACK scan suggests a stateful firewall
- UDP `open|filtered` results require service-specific probes to confirm

```bash
# SYN scan — shows open/closed/filtered
# Nmap
# https://nmap.org/
nmap -sS -p 1-1000 <target>

# ACK scan — shows filtered/unfiltered (firewall mapping)
# Nmap
# https://nmap.org/
nmap -sA -p 1-1000 <target>
```

## References

### Official Standards

- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
- [RFC 6335 — Internet Assigned Numbers Authority (IANA) Procedures for the Management of the Service Name and Transport Protocol Port Number Registry](https://datatracker.ietf.org/doc/html/rfc6335)
- [RFC 793 — Transmission Control Protocol (TCP)](https://datatracker.ietf.org/doc/html/rfc793)
- [RFC 768 — User Datagram Protocol (UDP)](https://datatracker.ietf.org/doc/html/rfc768)

### Tools

- [Nmap Port Scanning Techniques](https://nmap.org/book/port-scanning.html)
- [Nmap Port Specification and Scan Order](https://nmap.org/book/man-port-specification.html)
- [Nmap Services File Reference](https://nmap.org/book/nmap-services.html)
