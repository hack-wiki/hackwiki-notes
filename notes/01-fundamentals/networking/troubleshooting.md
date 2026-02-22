% Filename: 01-fundamentals/networking/troubleshooting.md
% Display name: Network Troubleshooting
% Last update: 2026-02-19
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Network Troubleshooting

## Overview

Network troubleshooting is the systematic process of identifying why communication between systems is failing. For security professionals, these same techniques are used to diagnose scan failures, verify firewall rules, confirm tunnel connectivity, troubleshoot reverse shells, and validate exploit delivery paths. The approach follows the TCP/IP stack bottom-up: verify physical/link connectivity first, then IP routing, then transport (TCP/UDP), then application-layer services.

## Key Concepts

### Troubleshooting Methodology

Work bottom-up through the network stack. Each layer depends on the layer below it — if Layer 3 is broken, testing Layer 7 is pointless.

```text
Step  Layer        Question                        Tool
----  ----------   ------------------------------  ------------------
1     Physical     Is the cable/link up?            ip link, ethtool
2     Data Link    Is there L2 connectivity?        ip neighbour, arping
3     Network      Can I reach the gateway/target?  ping, traceroute, ip route
4     Transport    Is the port open/reachable?      ss, nc, nmap
5     Application  Is the service responding?       curl, dig, nc
6     Firewall     Is something being filtered?     iptables, nft, tcpdump
7     DNS          Is name resolution working?      dig, nslookup, host
```

### Layer 1-2 — Link and Interface

Verify the network interface is up, has an IP address, and has link-layer connectivity.

```bash
# arping
# https://github.com/ThomasHabets/arping
# Show all interfaces with status and IP addresses
ip addr show

# Check if a specific interface is UP
ip link show eth0
# Look for: state UP (good) or state DOWN (problem)

# Bring an interface up/down
ip link set eth0 up
ip link set eth0 down

# Check link speed and duplex (physical interface details)
ethtool eth0 2>/dev/null | grep -E "Speed|Duplex|Link detected"
# Link detected: yes = cable connected / no = no cable or no link

# View MAC address table / ARP cache
ip neighbour show

# Test Layer 2 reachability on local segment
arping -c 3 192.168.1.1
```

**Common issues:**
- Interface DOWN — cable unplugged, VM network adapter disconnected, driver issue
- No IP address — DHCP failure, static config missing
- No ARP entry for gateway — wrong VLAN, Layer 2 isolation

### Layer 3 — IP Connectivity

Verify IP-level reachability to the gateway and target.

```bash
# Ping the default gateway (first hop)
ping -c 3 $(ip route show default | awk '{print $3}')

# Ping the target
ping -c 3 <target>

# Ping with a specific source interface
ping -c 3 -I eth0 <target>

# Ping with specific packet size (test MTU issues)
ping -c 3 -s 1472 -M do <target>
# -M do = don't fragment — fails if MTU is too small

# Show routing table
ip route show

# Check which route a specific destination uses
ip route get <target>
```

**Interpreting ping results:**

```text
Result                        Meaning                      Next Step
----------------------------  ---------------------------  ----------------------
Reply, low latency            Connectivity works           Move to Layer 4
Request timed out             Host down or ICMP blocked    Try traceroute, TCP ping
Destination unreachable       No route to host             Check routing table
TTL exceeded                  Routing loop                 Check traceroute
Packet too large              MTU mismatch                 Reduce packet size
```

### Traceroute — Path Analysis

Maps every router hop between source and destination. Essential for identifying where packets are being dropped or filtered.

```bash
# ICMP traceroute (default)
traceroute -n <target>

# TCP traceroute (bypasses ICMP-blocking firewalls)
traceroute -T -p 443 <target>

# UDP traceroute (default method on Linux)
traceroute -U -p 33434 <target>

# Set maximum number of hops
traceroute -n -m 30 <target>
```

**Interpreting traceroute output:**

```text
 1  192.168.1.1     1.234 ms   1.102 ms   0.987 ms    ← Default gateway
 2  10.0.0.1        5.432 ms   4.321 ms   4.567 ms    ← ISP first hop
 3  * * *                                               ← No response (filtered)
 4  172.16.50.1     15.678 ms  14.890 ms  15.012 ms   ← Continues past filter
 5  <target>        20.123 ms  19.876 ms  20.345 ms   ← Destination reached
```

- `* * *` = router does not respond to probes (ICMP rate-limiting or firewall) — not necessarily a failure if subsequent hops respond
- Latency spike at a specific hop = possible congestion point
- Traceroute never completes = traffic being dropped at last responding hop

### mtr — Combined Ping and Traceroute

`mtr` continuously pings every hop, showing real-time packet loss and latency statistics. More informative than a single traceroute for intermittent issues.

```bash
# MTR
# https://www.bitwizard.nl/mtr/
# Install if not present
sudo apt install -y mtr

# Interactive mode
mtr <target>

# Report mode (non-interactive, runs 10 cycles)
mtr -r -c 10 <target>

# TCP mode (port 443)
mtr -T -P 443 <target>

# No DNS resolution (faster)
mtr -n <target>
```

**Interpreting mtr output:**

```text
HOST                   Loss%  Snt   Last   Avg  Best  Wrst
1. 192.168.1.1          0.0%   10    0.8   0.9   0.7   1.2
2. 10.0.0.1             0.0%   10    5.1   5.3   4.8   6.1
3. 172.16.50.1         30.0%   10   15.2  16.1  14.9  20.3   ← 30% loss here
4. <target>             0.0%   10   20.1  19.8  19.2  21.0
```

- Loss at hop 3 but 0% at hop 4 = hop 3 is rate-limiting ICMP (not a real problem)
- Loss at the final hop = real packet loss affecting the target
- Progressive loss increasing at each hop = congestion or link failure

### Layer 4 — Port and Service Reachability

Verify that the target port is open and accepting connections.

```bash
# Test TCP port connectivity
nc -zv <target> 443
# Connection to <target> 443 port [tcp/https] succeeded!  ← open
# nc: connect to <target> port 443 (tcp) failed: Connection refused  ← closed
# (hangs with no output)  ← filtered

# Test with timeout
nc -zv -w 3 <target> 443

# Test multiple ports
nc -zv <target> 22 80 443 445

# Test UDP port (less reliable)
nc -zuv -w 3 <target> 161

# Scan to confirm port state
# Nmap
# https://nmap.org/
nmap -sS -p 443 <target>

# Check local listening ports
ss -tlnp
```

**Quick TCP connectivity test with Bash (no nc needed):**

```bash
# Bash built-in TCP test
(echo > /dev/tcp/<target>/443) 2>/dev/null && echo "OPEN" || echo "CLOSED/FILTERED"

# With timeout
timeout 3 bash -c "(echo > /dev/tcp/<target>/443) 2>/dev/null" && echo "OPEN" || echo "CLOSED/FILTERED"
```

### Layer 7 — Application and Services

Once connectivity is confirmed, verify the application is responding correctly.

```bash
# Test HTTP — check response code and headers
curl -sI http://<target>/
# -s = silent, -I = headers only

# Test HTTPS with verbose TLS details
curl -sv https://<target>/ 2>&1 | head -30

# Test HTTPS ignoring certificate errors (self-signed, expired)
curl -sk https://<target>/

# Test specific HTTP response code
curl -so /dev/null -w "%{http_code}" http://<target>/

# Test DNS resolution
dig A <hostname>
dig A <hostname> @<dns_server>

# Test DNS with a specific record type
dig MX example.com
dig NS example.com

# Check if DNS server responds at all
dig +short google.com @<dns_server>

# Test SMTP service
nc -v <target> 25

# Test SSH banner
nc -v -w 3 <target> 22

# Test SMB connectivity
smbclient -L //<target> -N 2>&1 | head -10
```

### DNS Troubleshooting

DNS problems are among the most common causes of connectivity failures, especially in pentest environments (VPN tunnels, AD labs, custom resolv.conf).

```bash
# Check current DNS configuration
cat /etc/resolv.conf

# Test resolution with system resolver
host <hostname>
nslookup <hostname>

# Test against a specific DNS server
dig A <hostname> @8.8.8.8
dig A <hostname> @<target_DC>

# Trace the full resolution path
dig +trace A example.com

# Check reverse DNS
dig -x <ip_address>

# Test if DNS is the problem (bypass it with IP)
curl -sI http://<ip_address>/
# If this works but http://<hostname>/ doesn't → DNS issue
```

**Common DNS issues:**
- `/etc/resolv.conf` pointing to wrong server or overwritten by DHCP/NetworkManager
- VPN tunnel not pushing DNS, or split-DNS not configured
- AD domain name not resolving — add DC IP as nameserver
- `.local` domains conflicting with mDNS (Avahi) — add to `/etc/hosts`

```bash
# Quick fix: add a DNS entry manually
echo '<target_ip> target.corp.local' >> /etc/hosts

# Quick fix: change DNS server
echo 'nameserver <dc_ip>' > /etc/resolv.conf
```

### Firewall Diagnostics

When traffic is being blocked, determine if it is a local or remote firewall.

```bash
# Check local firewall rules (iptables)
iptables -L -n -v

# Check local firewall rules (nftables)
nft list ruleset

# Watch traffic in real time to confirm packets are leaving/arriving
tcpdump -i eth0 host <target> and port 443 -nn

# Capture all traffic to a target (save for analysis)
tcpdump -i eth0 host <target> -w debug.pcap

# Check if SYN packets are being sent but no SYN-ACK returns
tcpdump -i eth0 'host <target> and tcp[tcpflags] & (tcp-syn|tcp-ack) != 0' -nn

# Compare SYN scan vs ACK scan to detect stateful firewalls
# Nmap
# https://nmap.org/
nmap -sS -p 80,443 <target>
nmap -sA -p 80,443 <target>
# filtered on SYN + unfiltered on ACK = stateful firewall
```

**Firewall troubleshooting flowchart:**

```text
Can you ping the target?
├── Yes → Can you reach the port (nc -zv)?
│         ├── Yes → Service issue (check curl/application layer)
│         └── No  → Remote firewall blocking the port
│                   Try: nmap -sA to confirm filtering
└── No  → Is ICMP blocked, or is host unreachable?
          ├── traceroute -T -p 443 works → ICMP blocked, host is up
          └── traceroute fails entirely → routing issue or host down
              Check: ip route get <target>
```

### Packet Capture for Debugging

When higher-level tools don't reveal the problem, capture raw packets.

```bash
# tcpdump
# https://www.tcpdump.org/
# Capture traffic on a specific port
tcpdump -i eth0 port 443 -nn

# Capture only SYN packets (new connections)
tcpdump -i eth0 'tcp[tcpflags] == tcp-syn' -nn

# Capture DNS queries
tcpdump -i eth0 udp port 53 -nn

# Capture and display packet contents (hex + ASCII)
tcpdump -i eth0 -X port 80 -nn -c 10

# Save capture for Wireshark analysis
tcpdump -i eth0 -w capture.pcap

# Read a saved capture
tcpdump -r capture.pcap -nn

# Filter for specific host and port in saved capture
tcpdump -r capture.pcap host <target> and port 443 -nn
```

**tcpdump filter syntax quick reference:**

```text
Filter                         Captures
-----------------------------  ----------------------------------
host 10.0.0.5                  All traffic to/from this IP
src host 10.0.0.5              Only traffic from this IP
dst host 10.0.0.5              Only traffic to this IP
port 443                       TCP or UDP port 443
tcp port 443                   TCP port 443 only
udp port 53                    UDP port 53 only
net 192.168.1.0/24             All traffic on this subnet
tcp[tcpflags] == tcp-syn       Only SYN packets
tcp[tcpflags] & tcp-syn != 0   Packets with SYN flag set
icmp                           All ICMP traffic
not port 22                    Exclude SSH traffic
```

## Practical Examples

### Connectivity Checklist

Quick step-by-step when you cannot reach a target:

```bash
# tcpdump
# https://www.tcpdump.org/
# 1. Is the interface up with an IP?
ip addr show eth0

# 2. Is the gateway reachable?
ping -c 1 $(ip route show default | awk '{print $3}')

# 3. Is the target routable?
ip route get <target>

# 4. Does the target respond to ICMP?
ping -c 3 <target>

# 5. Does the target respond to TCP on a known port?
nc -zv -w 3 <target> 443

# 6. Is DNS working?
dig +short <hostname>

# 7. Is there a local firewall blocking?
iptables -L -n | grep -i drop

# 8. Are packets actually leaving the interface?
tcpdump -i eth0 host <target> -c 5 -nn
```

### VPN and Tunnel Troubleshooting

Common issues when connected through VPN or SSH tunnels during engagements:

```bash
# Check if VPN interface exists and has an IP
ip addr show tun0

# Verify routes were added for the target network
ip route show | grep tun0

# If target network is not routed through VPN, add manually
ip route add 10.10.10.0/24 dev tun0

# Test connectivity through the tunnel
ping -c 3 -I tun0 <target>

# Check if DNS is resolving through VPN
dig A internal.corp.local @<dc_ip>

# SSH tunnel — verify local port forward is listening
ss -tlnp | grep ':8080'

# SSH tunnel — test forwarded service
curl -s http://127.0.0.1:8080/
```

### Reverse Shell Troubleshooting

When a reverse shell fails to connect back:

```bash
# tcpdump
# https://www.tcpdump.org/
# 1. Verify listener is running and on the right port
ss -tlnp | grep ':<port>'

# 2. Verify attacker IP is reachable from target
# (on target): ping -c 1 <attacker_ip>

# 3. Check if firewall is blocking inbound connections
iptables -L INPUT -n | grep -i drop
# Do NOT flush all rules with iptables -F — this drops every rule including logging and rate limits.
# To temporarily allow a specific port, add a narrow rule and remove it immediately after testing:
#   iptables -I INPUT 1 -p tcp --dport <port> -j ACCEPT
#   iptables -D INPUT 1

# 4. Capture traffic to see if shell connection arrives
tcpdump -i tun0 port <port> -nn

# 5. Common causes:
#    - Wrong attacker IP in payload (use tun0 IP, not eth0)
#    - Local firewall blocking inbound on listener port
#    - Target's egress firewall blocking outbound to your port
#    - NAT between attacker and target
```

### Diagnosing Slow Connections

```bash
# Check for packet loss
ping -c 20 <target> | tail -3
# Look for: X% packet loss

# Check for MTU issues (path MTU discovery)
ping -c 3 -s 1472 -M do <target>
# "Frag needed" = MTU < 1500 on path
# Reduce: ping -c 3 -s 1400 -M do <target>

# Check for DNS latency
dig A <hostname> | grep "Query time"
# Query time > 500ms = slow DNS

# Check TCP connection establishment time
curl -so /dev/null -w "DNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTLS: %{time_appconnect}s\nTotal: %{time_total}s\n" https://<target>/
```

**curl timing breakdown:**

```text
DNS:     0.005s    ← Name resolution (slow = DNS issue)
Connect: 0.025s    ← TCP handshake (slow = network latency)
TLS:     0.085s    ← TLS handshake (slow = crypto overhead)
Total:   0.120s    ← Full request cycle
```

## Common Issues Quick Reference

```text
Symptom                          Likely Cause                     Fix
-------------------------------  ------------------------------   -------------------------
No IP address on interface       DHCP failure / static not set    dhcpcd eth0 / ip addr add
Can't ping gateway               Wrong subnet / cable / VLAN      Check ip addr, ip route
Can ping gateway, not target     Missing route / firewall         ip route add / traceroute
Can ping target, port closed     Service not running              ss -tlnp on target
Can ping, port filtered          Firewall blocking                Check iptables / nft rules
DNS resolution fails             Wrong nameserver                 Fix /etc/resolv.conf
curl works by IP, not hostname   DNS issue                        Add to /etc/hosts
nmap shows filtered              Firewall dropping SYN            Try ACK scan / TCP traceroute
Reverse shell doesn't connect    Wrong IP / firewall / NAT        Verify listener + tcpdump
SSH tunnel not forwarding        Local port not listening          Check ss -tlnp for bind
VPN connected, can't reach host  Routes not pushed                ip route add via tun0
Intermittent packet loss         MTU mismatch / congestion        ping -s 1400 -M do / mtr
```

## References

### Official Standards

- [RFC 792 — Internet Control Message Protocol (ICMP)](https://datatracker.ietf.org/doc/html/rfc792)
- [RFC 1035 — Domain Names: Implementation and Specification (DNS)](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 793 — Transmission Control Protocol (TCP)](https://datatracker.ietf.org/doc/html/rfc793)

### Tools

- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [tcpdump Manual Page](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Nmap Port Scanning Techniques](https://nmap.org/book/port-scanning.html)
- [nftables Quick Reference](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)
- [iptables Project Page](https://netfilter.org/projects/iptables/)
