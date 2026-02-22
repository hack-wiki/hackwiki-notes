% Filename: 14-resources/cheatsheets/ports-protocols.md
% Display name: Ports & Protocols Reference
% Last update: 2026-02-11
% Authors: @TristanInSec

# Ports & Protocols Reference

## Overview

Quick reference of common TCP and UDP ports encountered during security
assessments. Organized by service category for fast lookup.

## Well-Known Service Ports

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 21 | TCP | FTP | File Transfer Protocol; check for anonymous login |
| 22 | TCP | SSH | Secure Shell; check for weak credentials, old versions |
| 23 | TCP | Telnet | Cleartext protocol; credentials sent in plaintext |
| 25 | TCP | SMTP | Simple Mail Transfer Protocol; check for open relay |
| 53 | TCP/UDP | DNS | Domain Name System; try zone transfers (TCP) |
| 69 | UDP | TFTP | Trivial FTP; no authentication |
| 80 | TCP | HTTP | Web server |
| 88 | TCP/UDP | Kerberos | AD authentication; Kerberoasting, AS-REP roasting |
| 110 | TCP | POP3 | Post Office Protocol; cleartext |
| 111 | TCP/UDP | RPCbind | SunRPC; enumerate RPC services |
| 135 | TCP | MSRPC | Microsoft RPC Endpoint Mapper |
| 137 | UDP | NetBIOS-NS | NetBIOS Name Service |
| 138 | UDP | NetBIOS-DGM | NetBIOS Datagram Service |
| 139 | TCP | NetBIOS-SSN | NetBIOS Session; legacy SMB |
| 143 | TCP | IMAP | Internet Message Access Protocol; cleartext |
| 161 | UDP/TCP | SNMP | Simple Network Management Protocol; community strings |
| 162 | UDP/TCP | SNMP-Trap | SNMP trap receiver |
| 389 | TCP | LDAP | Lightweight Directory Access Protocol |
| 443 | TCP | HTTPS | HTTP over TLS |
| 445 | TCP | SMB | Server Message Block; file sharing, RCE vector |
| 464 | TCP/UDP | Kpasswd | Kerberos password change |
| 465 | TCP | SMTPS | SMTP over TLS (implicit) |
| 500 | UDP | IKE | Internet Key Exchange (IPsec VPN) |
| 512 | TCP | rexec | Remote execution; cleartext |
| 513 | TCP | rlogin | Remote login; cleartext |
| 514 | TCP/UDP | RSH/Syslog | Remote shell (TCP) / Syslog (UDP) |
| 515 | TCP | LPD | Line Printer Daemon |
| 523 | TCP | IBM DB2 | DB2 database |
| 548 | TCP | AFP | Apple Filing Protocol |
| 554 | TCP | RTSP | Real Time Streaming Protocol |
| 587 | TCP | SMTP | Mail submission (STARTTLS) |
| 593 | TCP | RPC-HTTP | Microsoft RPC over HTTP |
| 623 | UDP | IPMI | Intelligent Platform Management Interface |
| 636 | TCP | LDAPS | LDAP over TLS |
| 873 | TCP | Rsync | File synchronization |
| 993 | TCP | IMAPS | IMAP over TLS |
| 995 | TCP | POP3S | POP3 over TLS |

## Database Ports

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle | Oracle Database TNS Listener |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 5432 | TCP | PostgreSQL | PostgreSQL database |
| 6379 | TCP | Redis | In-memory data store; often unauthenticated |
| 9200 | TCP | Elasticsearch | REST API; often unauthenticated |
| 27017 | TCP | MongoDB | NoSQL database; check for no-auth |

## Remote Access Ports

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 3389 | TCP | RDP | Remote Desktop Protocol |
| 5900 | TCP | VNC | Virtual Network Computing; often weak auth |
| 5985 | TCP | WinRM HTTP | Windows Remote Management |
| 5986 | TCP | WinRM HTTPS | WinRM over TLS |

## Web and Application Ports

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 8080 | TCP | HTTP-Alt | Common alternative HTTP port |
| 8443 | TCP | HTTPS-Alt | Common alternative HTTPS port |
| 8888 | TCP | HTTP-Alt | Alternative web port; Jupyter, proxies |
| 9090 | TCP | Web Admin | Management interfaces (Cockpit, WebLogic) |
| 10000 | TCP | Webmin | Webmin administration panel |

## Active Directory Ports

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 53 | TCP/UDP | DNS | AD-integrated DNS |
| 88 | TCP/UDP | Kerberos | Authentication |
| 135 | TCP | MSRPC | RPC Endpoint Mapper |
| 389 | TCP/UDP | LDAP | Directory queries |
| 445 | TCP | SMB | Group Policy, replication |
| 464 | TCP/UDP | Kpasswd | Password changes |
| 636 | TCP | LDAPS | Encrypted LDAP |
| 3268 | TCP | GC | Global Catalog (LDAP) |
| 3269 | TCP | GC-SSL | Global Catalog over TLS |
| 5985 | TCP | WinRM | PowerShell remoting |
| 9389 | TCP | ADWS | Active Directory Web Services |

## VPN and Tunneling Ports

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 500 | UDP | IKE | IPsec key exchange |
| 1194 | TCP/UDP | OpenVPN | OpenVPN default |
| 1701 | UDP | L2TP | Layer 2 Tunneling Protocol |
| 1723 | TCP | PPTP | Point-to-Point Tunneling (legacy) |
| 4500 | UDP | NAT-T | IPsec NAT traversal |
| 51820 | UDP | WireGuard | WireGuard VPN |

## Monitoring and Management Ports

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 161 | UDP | SNMP | Polling (community strings v1/v2c) |
| 162 | UDP | SNMP-Trap | Asynchronous alerts |
| 514 | UDP | Syslog | Log forwarding |
| 623 | UDP | IPMI | Baseboard management (hash disclosure) |
| 2049 | TCP/UDP | NFS | Network File System; check exports |
| 3260 | TCP | iSCSI | Storage access |
| 5000 | TCP | Docker Registry | Docker image registry; often unauthenticated |
| 8291 | TCP | Winbox | MikroTik router management |

## Quick Port Scan Reference

```bash
# Nmap
# https://nmap.org/

# Top 1000 ports (default)
nmap -sV <target>

# All TCP ports
nmap -p- --min-rate 5000 <target>

# Specific ports
nmap -sV -sC -p 22,80,443,445,3389 <target>

# Top 100 UDP ports
sudo nmap -sU --top-ports 100 <target>

# Service version + default scripts on discovered ports
nmap -sV -sC -p 22,80,445 <target>
```

## References

### Further Reading

- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
- [Nmap](https://nmap.org/)
