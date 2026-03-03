% Filename: 12-defensive/hardening/network.md
% Display name: Network Hardening
% Last update: 2026-02-11
% Authors: @TristanInSec

# Network Hardening

## Overview

Network hardening reduces the network attack surface through segmentation,
firewall configuration, protocol security, encryption enforcement, and
access controls. A well-hardened network limits an attacker's ability to
move laterally, intercept traffic, or reach sensitive assets.

## Network Segmentation

```text
Segmentation principles:

Separate by trust level:
  - DMZ (internet-facing servers)
  - Corporate (workstations, printers)
  - Server VLAN (internal servers, databases)
  - Management VLAN (admin access, out-of-band management)
  - IoT / OT (isolated, restricted access)

Inter-VLAN access controls:
  - Default deny between VLANs
  - Allow only required traffic with explicit firewall rules
  - Workstations → Servers: Only required application ports
  - DMZ → Internal: Deny (or very limited, specific rules)
  - Management → All: Allow from management stations only

Microsegmentation:
  - Host-based firewalls enforce per-host policies
  - Zero Trust: Verify every connection, no implicit trust by network location
```

## Firewall Configuration

### Linux (nftables)

```bash
# nftables
# https://wiki.nftables.org/

# Example nftables ruleset for a server
# /etc/nftables.conf

# Flush existing rules and create table
# nft flush ruleset

# Basic server firewall (allow SSH, HTTP, HTTPS, deny rest)
# table inet filter {
#     chain input {
#         type filter hook input priority 0; policy drop;
#         ct state established,related accept
#         iif lo accept
#         tcp dport 22 accept
#         tcp dport { 80, 443 } accept
#         icmp type echo-request accept
#         counter drop
#     }
#     chain forward {
#         type filter hook forward priority 0; policy drop;
#     }
#     chain output {
#         type filter hook output priority 0; policy accept;
#     }
# }

# Apply configuration
sudo nft -f /etc/nftables.conf

# List current ruleset
sudo nft list ruleset

# Add a rule interactively
sudo nft add rule inet filter input tcp dport 8443 accept
```

### Linux (iptables)

```bash
# iptables
# https://www.netfilter.org/

# Default deny policy
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from management network only
sudo iptables -A INPUT -s 10.0.100.0/24 -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Log dropped packets
sudo iptables -A INPUT -j LOG --log-prefix "iptables-dropped: " --log-level 4

# Save rules (Debian)
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### UFW (Simplified Firewall)

```bash
# ufw (Uncomplicated Firewall)
# https://wiki.ubuntu.com/UncomplicatedFirewall

# Enable UFW with default deny
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH from specific network
sudo ufw allow from 10.0.100.0/24 to any port 22

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable UFW
sudo ufw enable

# Check status
sudo ufw status verbose

# View numbered rules (for deletion)
sudo ufw status numbered

# Delete a rule by number
sudo ufw delete 3
```

## TLS Hardening

```text
Server-side TLS configuration principles:

Minimum TLS version: TLS 1.2 (prefer TLS 1.3)
  - Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1

Cipher suites (TLS 1.2):
  - Prefer AEAD ciphers: AES-GCM, ChaCha20-Poly1305
  - Require Perfect Forward Secrecy (ECDHE key exchange)
  - Disable: RC4, DES, 3DES, NULL, export ciphers

Certificate management:
  - Use certificates from trusted CAs (or internal PKI)
  - RSA keys: minimum 2048 bits (prefer 4096)
  - ECDSA keys: P-256 or P-384
  - Enable OCSP stapling
  - Set HSTS header (Strict-Transport-Security)

Testing:
  - Use testssl.sh or SSL Labs to audit TLS configuration
```

```bash
# openssl
# https://www.openssl.org/

# Test a server's TLS configuration
openssl s_client -connect example.com:443 -tls1_2

# Check certificate details
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates

# Check supported ciphers
openssl s_client -connect example.com:443 -cipher 'ALL' </dev/null 2>&1 | \
  grep -i cipher
```

## DNS Security

```text
DNS hardening measures:

Restrict zone transfers:
  - Allow zone transfers only to authorized secondary DNS servers
  - BIND: allow-transfer { trusted-secondaries; };
  - Monitor for unauthorized AXFR requests

DNSSEC:
  - Sign DNS zones to prevent spoofing
  - Validate DNSSEC signatures on resolvers

DNS over HTTPS/TLS:
  - Encrypt DNS queries to prevent eavesdropping
  - Configure internal resolvers for DoH/DoT where possible

Response Rate Limiting (RRL):
  - Limit DNS response rate to mitigate amplification attacks
  - BIND: rate-limit { responses-per-second 5; };

Split DNS:
  - Internal DNS resolves internal hostnames
  - External DNS exposes only public-facing services
  - Never expose internal hostnames to the internet
```

## Wireless Security

```text
Wireless hardening:

Authentication:
  - Use WPA3-Enterprise (802.1X with RADIUS)
  - If WPA2 required: WPA2-Enterprise with AES-CCMP only
  - Never use WEP, WPA-PSK, or TKIP in enterprise environments

Network isolation:
  - Guest wireless on separate VLAN with internet-only access
  - Corporate wireless requires 802.1X and machine certificates
  - IoT wireless on isolated VLAN with strict ACLs

Rogue AP detection:
  - Enable WIDS (Wireless Intrusion Detection System)
  - Monitor for unauthorized access points

SSID management:
  - Do not broadcast sensitive network names
  - Use descriptive names only for guest networks
```

## 802.1X Network Access Control

```text
802.1X (port-based network access control):

Components:
  - Supplicant: Client device requesting access
  - Authenticator: Switch or wireless AP
  - Authentication server: RADIUS server (FreeRADIUS, NPS)

Authentication methods:
  - EAP-TLS: Certificate-based (strongest, requires PKI)
  - PEAP-MSCHAPv2: Password-based with TLS tunnel
  - EAP-TTLS: Similar to PEAP, more flexible

Switch port configuration:
  - Default VLAN: Quarantine / limited access
  - On authentication success: Assign to correct VLAN
  - On failure: Remain in quarantine or deny

Benefits:
  - Prevents unauthorized devices from connecting
  - Dynamic VLAN assignment based on user/device
  - MAC Authentication Bypass (MAB) for devices without 802.1X
```

## References

### Tools

- [nftables](https://wiki.nftables.org/)
- [iptables (netfilter)](https://www.netfilter.org/)
- [ufw](https://wiki.ubuntu.com/UncomplicatedFirewall)
- [OpenSSL](https://www.openssl.org/)

### Further Reading

- [CIS Benchmarks (Network Devices)](https://www.cisecurity.org/cis-benchmarks)
- [NIST SP 800-41: Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/pubs/sp/800/41/r1/final)
