% Filename: 01-fundamentals/networking/protocols.md
% Display name: Network Protocols
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Network Protocols

## Overview

Network protocols define the rules for communication between systems. Each protocol specifies message format, ordering, error handling, and authentication. Security professionals need to understand how protocols work at a practical level — what ports they use, whether they transmit data in cleartext, how authentication is handled, and where the attack surface lies. This file covers the major protocols encountered during penetration testing and network defense.

## Key Concepts

### DNS (Domain Name System)

Translates domain names to IP addresses. Uses UDP 53 for queries and TCP 53 for zone transfers and large responses.

**How it works:** Client sends a query to a recursive resolver, which walks the DNS hierarchy (root → TLD → authoritative) to resolve the name. Responses are cached based on TTL values.

**Record types:**

```text
Type    Purpose                    Example
-----   -------------------------  ---------------------------
A       IPv4 address               example.com → 93.184.216.34
AAAA    IPv6 address               example.com → 2606:2800:...
CNAME   Alias to another name      www → example.com
MX      Mail server                mail.example.com (pri 10)
NS      Authoritative nameserver   ns1.example.com
TXT     Arbitrary text             SPF, DKIM, domain verification
PTR     Reverse lookup             93.184.216.34 → example.com
SOA     Zone authority info        Primary NS, admin email, serials
SRV     Service location           _ldap._tcp.corp.local
```

**Security implications:**
- DNS is unencrypted by default — queries reveal browsing activity
- Zone transfers (AXFR) can expose the entire domain structure if misconfigured
- DNS cache poisoning redirects users to attacker-controlled hosts
- DNS tunneling uses DNS queries/responses to exfiltrate data or establish C2 channels
- SRV records in Active Directory reveal domain controllers, Kerberos, LDAP services

```bash
# Query A record
dig A example.com

# Query all records for a domain
dig ANY example.com

# Attempt zone transfer (AXFR)
dig AXFR example.com @ns1.example.com

# Reverse lookup
dig -x 93.184.216.34

# Query specific nameserver
dig A example.com @8.8.8.8

# Short output format
host example.com
```

### HTTP / HTTPS

HTTP (Hypertext Transfer Protocol) is the foundation of web communication. Uses TCP 80 (HTTP) and TCP 443 (HTTPS with TLS). HTTPS wraps HTTP inside a TLS tunnel, providing encryption and server authentication.

**How it works:** Client sends a request (method, path, headers, optional body), server responds with a status code, headers, and optional body. HTTP is stateless — sessions are maintained through cookies or tokens.

**Request methods:**

```text
Method   Purpose                   Idempotent  Safe
-------  ------------------------  ----------  ----
GET      Retrieve resource         Yes         Yes
POST     Submit data               No          No
PUT      Replace resource          Yes         No
DELETE   Remove resource           Yes         No
HEAD     GET without body          Yes         Yes
OPTIONS  Query allowed methods     Yes         Yes
PATCH    Partial update            No          No
```

**Status code ranges:**

```text
Range   Meaning         Common Codes
------  --------------  ------------------------------------------
1xx     Informational   100 Continue, 101 Switching Protocols
2xx     Success         200 OK, 201 Created, 204 No Content
3xx     Redirection     301 Moved, 302 Found, 304 Not Modified
4xx     Client Error    400 Bad Request, 401 Unauth, 403 Forbidden, 404 Not Found
5xx     Server Error    500 Internal, 502 Bad Gateway, 503 Unavailable
```

**Security implications:**
- HTTP transmits everything in cleartext — credentials, cookies, and data are visible on the wire
- Response headers reveal server software, frameworks, and configuration (`Server`, `X-Powered-By`)
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`) control session security
- HTTPS does not guarantee a site is safe — it guarantees the connection is encrypted

```bash
# Inspect HTTP headers
curl -I http://example.com

# Verbose request showing full handshake and headers
curl -v https://example.com/ 2>&1 | head -30

# Send a POST request
curl -X POST -d "user=admin&pass=test" http://example.com/login

# Show only response headers (follow redirects)
curl -sIL http://example.com
```

### FTP (File Transfer Protocol)

Transfers files between client and server. Uses TCP 21 for control and TCP 20 (or a negotiated high port) for data. FTP predates modern security — credentials and data travel in cleartext.

**How it works:** Client connects to port 21 for the control channel. Data transfers use a separate connection: active mode (server initiates data connection from its port 20 to the client's specified high port) or passive mode (server opens a high port, client connects to it). Passive mode is more firewall-friendly.

**Security implications:**
- Credentials sent in cleartext (`USER` and `PASS` commands visible on the wire)
- Anonymous FTP may expose sensitive files
- Active mode requires the server to connect back to the client — blocked by most NAT/firewalls
- FTP bounce attacks use the `PORT` command to scan or relay through the FTP server

```bash
# Connect to FTP server
ftp <target>

# Anonymous login attempt
ftp <target>
# Username: anonymous
# Password: anonymous@

# Manual FTP session (shows raw protocol)
nc -v <target> 21
```

### SSH (Secure Shell)

Provides encrypted remote access, file transfer, and port forwarding. Uses TCP 22. SSH replaced Telnet and rsh by encrypting all traffic, including authentication.

**How it works:** Client and server negotiate encryption algorithms, exchange keys (Diffie-Hellman), and authenticate. Authentication methods include password, public key, and keyboard-interactive. After authentication, the client gets a shell or runs commands remotely.

**Security implications:**
- Weak passwords or leaked private keys grant full system access
- SSH key reuse across systems enables lateral movement
- SSH tunneling (-L, -R, -D) can bypass firewalls and create SOCKS proxies
- Banner reveals SSH version and OS hints
- Agent forwarding (`-A`) can be abused on compromised hosts

```bash
# Connect with password
ssh user@<target>

# Connect with private key
ssh -i id_rsa user@<target>

# Local port forward — access remote service through SSH
ssh -L 8080:127.0.0.1:80 user@<target>

# Dynamic SOCKS proxy
ssh -D 1080 user@<target>

# Banner grab
nc -v <target> 22
```

### SMTP (Simple Mail Transfer Protocol)

Sends email between mail servers and from clients to servers. Uses TCP 25 (server-to-server), TCP 587 (client submission with STARTTLS), and TCP 465 (SMTPS).

**How it works:** Client connects and issues commands (EHLO, MAIL FROM, RCPT TO, DATA) to send an email. The server relays the message to the recipient's mail server based on MX records.

**Security implications:**
- Open relays allow anyone to send email through the server (spam, phishing)
- VRFY and EXPN commands can enumerate valid email addresses
- SMTP is cleartext by default — STARTTLS upgrades the connection but is optional
- Email headers reveal internal server names and IP addresses
- SPF, DKIM, and DMARC records (in DNS) protect against spoofing but are often misconfigured

```bash
# Manual SMTP session
nc -v <target> 25
# EHLO test.local
# MAIL FROM:<test@test.local>
# RCPT TO:<admin@target.com>
# DATA
# Subject: Test
# Test message.
# .
# QUIT

# Check for open relay
nc -v <target> 25
# EHLO test.local
# MAIL FROM:<attacker@external.com>
# RCPT TO:<victim@external.com>
# (250 response = open relay)

# Enumerate users with VRFY
nc -v <target> 25
# VRFY admin
# (250 = exists, 550 = does not exist)
```

### DHCP (Dynamic Host Configuration Protocol)

Assigns IP addresses, subnet masks, gateways, and DNS servers to clients automatically. Uses UDP 67 (server) and UDP 68 (client).

**How it works (DORA process):**

```text
Client → Discover  (broadcast)    "Any DHCP servers out there?"
Server → Offer     (unicast/bc)   "Here's an IP you can use"
Client → Request   (broadcast)    "I'll take that IP"
Server → Acknowledge (unicast/bc) "It's yours for [lease time]"
```

**Security implications:**
- Rogue DHCP servers can redirect traffic by assigning attacker-controlled DNS servers and gateways (man-in-the-middle)
- DHCP starvation exhausts the address pool, denying service to legitimate clients
- DHCP snooping on managed switches is the primary defense

### SMB (Server Message Block)

File and printer sharing protocol used primarily in Windows environments. Uses TCP 445 (modern SMB) and TCP 139 (SMB over NetBIOS). SMB is central to Active Directory environments.

**Versions:**

```text
Version  Introduced     Notes
-------  -------------  --------------------------------
SMB 1.0  Windows NT     Deprecated, EternalBlue (MS17-010)
SMB 2.0  Windows Vista  Performance improvements
SMB 2.1  Windows 7      Opportunistic locking
SMB 3.0  Windows 8      Encryption support
SMB 3.1.1 Windows 10   Pre-auth integrity, preferred in modern AD
```

**Security implications:**
- SMB 1.0 is vulnerable to EternalBlue (CVE-2017-0144) — remote code execution
- Null sessions can enumerate shares, users, and groups on misconfigured hosts
- SMB signing disabled allows relay attacks (NTLM relay)
- Readable shares may contain credentials, configuration files, or sensitive data
- SMB is the transport for PsExec, WMI, and other lateral movement techniques

```bash
# List shares (null session)
smbclient -L //<target> -N

# Connect to a share
smbclient //<target>/sharename -U username

# Enumerate shares with credentials
smbclient -L //<target> -U 'domain\user%password'
```

### LDAP (Lightweight Directory Access Protocol)

Queries and modifies directory services (user accounts, groups, computers, policies). Uses TCP 389 (LDAP) and TCP 636 (LDAPS with TLS). LDAP is the primary query protocol for Active Directory.

**How it works:** Client binds (authenticates) to the directory, then searches using a base DN (Distinguished Name), scope, and filter. Results return as entries with attributes.

**Key concepts:**

```text
Term        Example                                Meaning
----------  -------------------------------------  -------------------------
Base DN     DC=corp,DC=local                       Search starting point
DN          CN=John Smith,OU=Users,DC=corp,DC=local  Unique entry identifier
Filter      (objectClass=user)                     Search criteria
Scope       subtree, onelevel, base                Search depth
Bind        Simple (password), SASL (Kerberos)     Authentication method
```

**Security implications:**
- Anonymous bind may be enabled — exposes the entire directory without credentials
- LDAP (port 389) transmits credentials in cleartext unless STARTTLS is used
- LDAP queries reveal AD structure: users, groups, computers, GPOs, trust relationships
- Password spraying targets accounts discovered through LDAP enumeration
- Service accounts with SPNs (found via LDAP) are Kerberoasting targets

```bash
# OpenLDAP (ldapsearch)
# https://openldap.org/
# Anonymous LDAP search
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local"

# Authenticated search for all users
ldapsearch -x -H ldap://<target> -D "CN=user,DC=corp,DC=local" -W -b "DC=corp,DC=local" "(objectClass=user)"
```

### SNMP (Simple Network Management Protocol)

Monitors and manages network devices (routers, switches, printers, servers). Uses UDP 161 (queries) and UDP 162 (traps/notifications).

**How it works:** A management station queries agents running on devices using community strings (essentially passwords). Agents respond with data from the MIB (Management Information Base) — a hierarchical database of device information identified by OIDs (Object Identifiers).

**Versions:**

```text
Version  Authentication       Encryption  Notes
-------  -------------------  ----------  ----------------------------
v1       Community string     None        Cleartext, widely deprecated
v2c      Community string     None        Bulk operations, still cleartext
v3       Username/password    Optional    Supports auth + encryption
```

**Security implications:**
- Default community strings (`public` for read, `private` for read-write) are often unchanged
- SNMPv1/v2c community strings travel in cleartext
- Read access reveals system info, interfaces, routing tables, running processes, installed software
- Write access (with `private` community) can modify device configuration

```bash
# Net-SNMP (snmpwalk)
# https://www.net-snmp.org/
# Walk the SNMP tree (v2c, default community)
snmpwalk -v 2c -c public <target>

# Get system description
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.1.1

# Enumerate network interfaces
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.2.2.1.2

# Enumerate running processes (Host Resources MIB)
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2
```

### Telnet

Provides remote terminal access over TCP 23. All data, including credentials, is transmitted in cleartext. Telnet is functionally obsolete for administration — replaced by SSH — but still found on legacy systems, network devices, and IoT equipment.

**Security implications:**
- Complete lack of encryption — credentials and session data are trivially captured
- Presence on a network often indicates legacy or poorly maintained systems
- Still used for banner grabbing and manual protocol interaction with other services (HTTP, SMTP, FTP)

```bash
# Connect to a Telnet service
nc -v <target> 23

# Use Telnet for banner grabbing on other ports
nc -v <target> 80
# GET / HTTP/1.0
# Host: target
# (blank line)
```

### RDP (Remote Desktop Protocol)

Provides graphical remote desktop access to Windows systems. Uses TCP 3389 (and UDP 3389 for performance).

**Security implications:**
- Exposed RDP is a top target for brute-force and credential stuffing attacks
- BlueKeep (CVE-2019-0708) enabled pre-auth remote code execution on older Windows versions
- Network Level Authentication (NLA) requires valid credentials before establishing a full session — reduces attack surface
- RDP sessions can be hijacked on compromised hosts without knowing the password (if running as SYSTEM)

### NTP (Network Time Protocol)

Synchronizes system clocks across a network. Uses UDP 123. Accurate time is critical for Kerberos authentication (default tolerance: 5 minutes), log correlation, and certificate validation.

**Security implications:**
- NTP amplification attacks abuse the monlist command in older ntpd implementations (CVE-2013-5211) to generate large responses for DDoS
- Time manipulation can break Kerberos authentication or enable replay attacks
- NTP reveals internal system time, which may assist time-based attacks

```bash
# Query NTP server
ntpq -p <target>

# Show NTP server time
ntpdate -q <target>
```

### POP3 / IMAP

Email retrieval protocols. POP3 (TCP 110, 995 with TLS) downloads mail to the client. IMAP (TCP 143, 993 with TLS) keeps mail on the server and syncs across devices.

**Security implications:**
- POP3/IMAP without TLS transmit credentials in cleartext
- User enumeration through login attempts (different errors for valid vs invalid users)
- Compromised email accounts may contain credentials, VPN configs, or sensitive data
- IMAP IDLE connections can be monitored for real-time email interception

```bash
# Manual POP3 session
nc -v <target> 110
# USER admin
# PASS password
# LIST
# RETR 1
# QUIT

# Manual IMAP session
nc -v <target> 143
# A1 LOGIN admin password
# A2 LIST "" "*"
# A3 SELECT INBOX
# A4 FETCH 1 BODY[]
# A5 LOGOUT
```

## Protocol Security Summary

```text
Protocol  Port(s)      Encrypted    Auth Type           Primary Risk
--------  -----------  ----------   ------------------  ---------------------------
DNS       53           No*          None                Cache poisoning, zone transfer
HTTP      80           No           Various             All web attacks, MitM
HTTPS     443          Yes (TLS)    Various             Misconfigured TLS, cert issues
FTP       21, 20       No           Cleartext           Credential theft, anon access
SSH       22           Yes          Key/password        Weak passwords, key theft
SMTP      25, 587      No*          Cleartext/STARTTLS  Open relay, user enumeration
DHCP      67, 68       No           None                Rogue server, starvation
SMB       445, 139     Optional**   NTLM/Kerberos       Relay, null sessions, RCE
LDAP      389, 636     No/TLS       Simple/SASL         Anon bind, credential exposure
SNMP      161, 162     No***        Community string     Default communities, info leak
Telnet    23           No           Cleartext           Full credential exposure
RDP       3389         Yes (TLS)    NLA/password         Brute-force, BlueKeep
NTP       123          No           None                Amplification DDoS
POP3      110, 995     No/TLS       Cleartext           Credential theft
IMAP      143, 993     No/TLS       Cleartext           Credential theft

*  DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) add encryption
** SMB 3.0+ supports encryption; SMB signing is separate from encryption
*** SNMPv3 supports authentication and encryption
```

## References

### Official Standards — Core Protocols

- [RFC 1035 — Domain Names: Implementation and Specification (DNS)](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 9110 — HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 959 — File Transfer Protocol (FTP)](https://datatracker.ietf.org/doc/html/rfc959)
- [RFC 4251 — The Secure Shell (SSH) Protocol Architecture](https://datatracker.ietf.org/doc/html/rfc4251)
- [RFC 5321 — Simple Mail Transfer Protocol (SMTP)](https://datatracker.ietf.org/doc/html/rfc5321)
- [RFC 2131 — Dynamic Host Configuration Protocol (DHCP)](https://datatracker.ietf.org/doc/html/rfc2131)

### Official Standards — Directory, Management, and Mail

- [RFC 4511 — Lightweight Directory Access Protocol (LDAP)](https://datatracker.ietf.org/doc/html/rfc4511)
- [RFC 1157 — Simple Network Management Protocol (SNMP)](https://datatracker.ietf.org/doc/html/rfc1157)
- [RFC 854 — Telnet Protocol Specification](https://datatracker.ietf.org/doc/html/rfc854)
- [RFC 5905 — Network Time Protocol Version 4 (NTPv4)](https://datatracker.ietf.org/doc/html/rfc5905)
- [RFC 1939 — Post Office Protocol Version 3 (POP3)](https://datatracker.ietf.org/doc/html/rfc1939)
- [RFC 9051 — Internet Message Access Protocol Version 4rev2 (IMAP)](https://datatracker.ietf.org/doc/html/rfc9051)

### Microsoft Protocol Specifications

- [MS-SMB2 — Server Message Block Protocol Versions 2 and 3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962)
- [MS-RDPBCGR — Remote Desktop Protocol: Basic Connectivity and Graphics Remoting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c)
