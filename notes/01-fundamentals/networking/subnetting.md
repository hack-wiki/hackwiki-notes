% Filename: 01-fundamentals/networking/subnetting.md
% Display name: Subnetting
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Subnetting

## Overview

Subnetting divides a single IP network into smaller segments. Each subnet has its own network address, broadcast address, and usable host range. Security professionals need subnetting for scope definition (what to scan and what not to), network segmentation analysis, firewall rule interpretation, and understanding how hosts communicate within and across subnets. CIDR (Classless Inter-Domain Routing) notation is the standard way to express subnet sizes.

## Key Concepts

### Binary Foundation

An IPv4 address is 32 bits split into four octets. A subnet mask identifies which bits represent the network portion and which represent hosts.

```text
IP:      192.168.1.100
Binary:  11000000.10101000.00000001.01100100

Mask:    255.255.255.0
Binary:  11111111.11111111.11111111.00000000
         |-------- network --------||hosts-|

CIDR:    /24 (24 network bits, 8 host bits)
```

The network address is the result of a bitwise AND between the IP and the mask. Hosts on the same network share the same network address and can communicate directly (Layer 2). Hosts on different networks require a router.

```text
IP:        11000000.10101000.00000001.01100100  (192.168.1.100)
Mask:      11111111.11111111.11111111.00000000  (255.255.255.0)
AND:       11000000.10101000.00000001.00000000  (192.168.1.0) ← network address
Broadcast: 11000000.10101000.00000001.11111111  (192.168.1.255) ← all host bits = 1
```

### CIDR Notation

CIDR replaced classful addressing. The prefix length (`/N`) indicates how many bits are the network portion. The remaining bits are for hosts.

**Complete CIDR reference table:**

```text
CIDR   Subnet Mask       Wildcard Mask     Usable Hosts   Addresses
-----  ----------------  ----------------  -------------  ----------
/32    255.255.255.255   0.0.0.0           1 (host only)  1
/31    255.255.255.254   0.0.0.1           2 (P2P link)   2
/30    255.255.255.252   0.0.0.3           2              4
/29    255.255.255.248   0.0.0.7           6              8
/28    255.255.255.240   0.0.0.15          14             16
/27    255.255.255.224   0.0.0.31          30             32
/26    255.255.255.192   0.0.0.63          62             64
/25    255.255.255.128   0.0.0.127         126            128
/24    255.255.255.0     0.0.0.255         254            256
/23    255.255.254.0     0.0.1.255         510            512
/22    255.255.252.0     0.0.3.255         1,022          1,024
/21    255.255.248.0     0.0.7.255         2,046          2,048
/20    255.255.240.0     0.0.15.255        4,094          4,096
/19    255.255.224.0     0.0.31.255        8,190          8,192
/18    255.255.192.0     0.0.63.255        16,382         16,384
/17    255.255.128.0     0.0.127.255       32,766         32,768
/16    255.255.0.0       0.0.255.255       65,534         65,536
/15    255.254.0.0       0.1.255.255       131,070        131,072
/14    255.252.0.0       0.3.255.255       262,142        262,144
/13    255.248.0.0       0.7.255.255       524,286        524,288
/12    255.240.0.0       0.15.255.255      1,048,574      1,048,576
/11    255.224.0.0       0.31.255.255      2,097,150      2,097,152
/10    255.192.0.0       0.63.255.255      4,194,302      4,194,304
/9     255.128.0.0       0.127.255.255     8,388,606      8,388,608
/8     255.0.0.0         0.255.255.255     16,777,214     16,777,216
```

**Formulas:**
- Total addresses = 2^(32 - prefix)
- Usable hosts = 2^(32 - prefix) - 2  (subtract network and broadcast)
- Exception: /31 provides 2 usable addresses (RFC 3021, point-to-point links)
- Exception: /32 is a single host address

### Wildcard Mask

The inverse of the subnet mask. Used in ACLs (Cisco), OSPF configuration, and some firewall rules. Calculated by subtracting the subnet mask from 255.255.255.255.

```text
Subnet mask:   255.255.255.240  (/28)
Wildcard mask: 0.0.0.15

Meaning: match the first 28 bits exactly, ignore the last 4 bits
```

### Subnet Calculation Method

To calculate a subnet's properties from any IP/CIDR:

**Example: 10.50.100.200/21**

```text
Step 1 — Find the block size
  Host bits = 32 - 21 = 11
  Block size = 2^11 = 2048 addresses
  In the third octet: 2048 / 256 = 8 (block increments by 8 in the 3rd octet)

Step 2 — Find the network address
  Third octet: 100 / 8 = 12 remainder 4
  Network starts at: 12 × 8 = 96
  Network address: 10.50.96.0

Step 3 — Find the broadcast address
  Next network: 10.50.104.0
  Broadcast: 10.50.103.255

Step 4 — Usable host range
  First host: 10.50.96.1
  Last host:  10.50.103.254
  Usable hosts: 2046
```

**Quick method for common subnets (last octet):**

```text
CIDR  Block Size  Network Boundaries (last octet)
/25   128         0, 128
/26   64          0, 64, 128, 192
/27   32          0, 32, 64, 96, 128, 160, 192, 224
/28   16          0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240
/29   8           0, 8, 16, 24, 32, 40, ...
/30   4           0, 4, 8, 12, 16, 20, ...
```

To find which subnet an IP belongs to: divide the relevant octet by the block size, drop the remainder, multiply back.

**Example: Which /26 subnet contains 192.168.1.200?**

```text
Block size for /26 = 64
200 / 64 = 3 remainder 8
Network: 3 × 64 = 192 → 192.168.1.192/26
Broadcast: 192.168.1.255
Host range: 192.168.1.193 - 192.168.1.254
```

### Private Address Ranges (RFC 1918)

Reserved for internal use. Not routable on the public internet.

```text
Range                    CIDR          Addresses       Typical Use
-----------------------  -----------   --------------  -----------------
10.0.0.0 - 10.255.255.255    10.0.0.0/8     16,777,216  Enterprise networks
172.16.0.0 - 172.31.255.255  172.16.0.0/12  1,048,576   Mid-size networks
192.168.0.0 - 192.168.255.255 192.168.0.0/16 65,536     Home/small office
```

### Special-Purpose Addresses (RFC 6890)

```text
Range              CIDR             Purpose
-----------------  ---------------  ----------------------------
0.0.0.0            0.0.0.0/8        "This" network
127.0.0.0          127.0.0.0/8      Loopback
169.254.0.0        169.254.0.0/16   Link-local (APIPA)
192.0.2.0          192.0.2.0/24     Documentation (TEST-NET-1)
198.51.100.0       198.51.100.0/24  Documentation (TEST-NET-2)
203.0.113.0        203.0.113.0/24   Documentation (TEST-NET-3)
224.0.0.0          224.0.0.0/4      Multicast
240.0.0.0          240.0.0.0/4      Reserved
255.255.255.255    255.255.255.255/32  Limited broadcast
```

### Supernetting (Aggregation)

Combining multiple smaller subnets into a single larger prefix. Used for route summarization and scope definition.

```text
Individual subnets:
  192.168.0.0/24
  192.168.1.0/24
  192.168.2.0/24
  192.168.3.0/24

Aggregated (supernet):
  192.168.0.0/22  (covers .0.0 through .3.255)
```

Aggregation works when subnets are contiguous and align on the supernet boundary. Check alignment: the network address must be divisible by the total addresses in the supernet.

```text
192.168.0.0 / 1024 = 192 × 65536 + 168 × 256 + 0 = divisible → valid /22 boundary
192.168.1.0 / 1024 = not on boundary → cannot start a /22 here
```

## Practical Examples

### Subnet Calculation with Python

Python's `ipaddress` module (standard library, no install needed) handles all subnet calculations:

```python
# python3
import ipaddress

# Calculate subnet properties
net = ipaddress.ip_network('10.50.100.0/21', strict=False)
print(f'Network:   {net.network_address}')
print(f'Broadcast: {net.broadcast_address}')
print(f'Netmask:   {net.netmask}')
print(f'Wildcard:  {net.hostmask}')
print(f'Hosts:     {net.num_addresses - 2}')
print(f'First:     {list(net.hosts())[0]}')
print(f'Last:      {list(net.hosts())[-1]}')
```

Output:
```text
Network:   10.50.96.0
Broadcast: 10.50.103.255
Netmask:   255.255.248.0
Wildcard:  0.0.7.255
Hosts:     2046
First:     10.50.96.1
Last:      10.50.103.254
```

```python
# python3
import ipaddress

# Find which subnet an IP belongs to
ip = ipaddress.ip_address('192.168.1.200')
net = ipaddress.ip_network('192.168.1.192/26')
print(f'{ip} in {net}: {ip in net}')

# Check if two IPs are on the same subnet
net1 = ipaddress.ip_network('10.0.0.50/24', strict=False)
net2 = ipaddress.ip_network('10.0.0.200/24', strict=False)
print(f'Same subnet: {net1 == net2}')

# List all /28 subnets within a /24
parent = ipaddress.ip_network('192.168.1.0/24')
for subnet in parent.subnets(new_prefix=28):
    hosts = list(subnet.hosts())
    print(f'{subnet}  range: {hosts[0]} - {hosts[-1]}')
```

### Subnet Calculation with ipcalc

`ipcalc` provides quick subnet lookups from the command line:

```bash
# ipcalc
# https://jodies.de/ipcalc
# Install if not present
sudo apt install -y ipcalc

# Calculate subnet details
ipcalc 192.168.1.100/26
```

Output:
```text
Address:   192.168.1.100        11000000.10101000.00000001.01 100100
Netmask:   255.255.255.192 = 26 11111111.11111111.11111111.11 000000
Wildcard:  0.0.0.63             00000000.00000000.00000000.00 111111
=>
Network:   192.168.1.64/26      11000000.10101000.00000001.01 000000
HostMin:   192.168.1.65         11000000.10101000.00000001.01 000001
HostMax:   192.168.1.126        11000000.10101000.00000001.01 111110
Broadcast: 192.168.1.127        11000000.10101000.00000001.01 111111
Hosts/Net: 62                    Class C, Private Internet
```

### Scanning by Subnet

Understanding subnets is essential for scoping scans correctly:

```bash
# List all hosts in a subnet without scanning (dry run)
# Nmap
# https://nmap.org/
nmap -sL 192.168.1.0/24

# Ping sweep a specific subnet
# Nmap
# https://nmap.org/
nmap -sn 10.10.10.0/24

# Scan multiple subnets
# Nmap
# https://nmap.org/
nmap -sn 192.168.1.0/24 192.168.2.0/24 10.0.0.0/16

# Exclude specific hosts from a subnet scan
# Nmap
# https://nmap.org/
nmap -sn 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254

# Scan from a target list (one IP/CIDR per line)
# Nmap
# https://nmap.org/
nmap -sn -iL targets.txt
```

### Identifying the Local Subnet

```bash
# Show IP address and subnet mask for all interfaces
ip addr show

# Example output:
# inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
#   ↑ IP address  ↑ CIDR  ↑ broadcast

# Show routing table — reveals connected subnets and gateway
ip route show

# Example output:
# default via 192.168.1.1 dev eth0        ← default gateway
# 192.168.1.0/24 dev eth0 scope link      ← directly connected subnet
```

### Scope Definition for Penetration Testing

Engagements define scope using CIDR notation. Understanding subnetting prevents scanning out-of-scope targets.

```text
Scope: 10.10.10.0/24
  In scope:     10.10.10.1 through 10.10.10.254
  Out of scope: 10.10.11.1 (different subnet)

Scope: 172.16.0.0/20
  In scope:     172.16.0.1 through 172.16.15.254
  Out of scope: 172.16.16.1 (different subnet)
```

Verify before scanning:

```python
# python3
import ipaddress

scope = ipaddress.ip_network('172.16.0.0/20')
target = ipaddress.ip_address('172.16.15.200')
print(f'{target} in scope: {target in scope}')

target2 = ipaddress.ip_address('172.16.16.1')
print(f'{target2} in scope: {target2 in scope}')
```

Output:
```text
172.16.15.200 in scope: True
172.16.16.1 in scope: False
```

### VLSM (Variable Length Subnet Masking)

Real networks use different subnet sizes for different segments. VLSM allocates subnets efficiently by matching the prefix length to the number of required hosts.

**Example: Assign subnets from 10.0.0.0/24 for the following needs:**

```text
Requirement           Hosts Needed  Best Fit  Subnet            Range
--------------------  -----------   --------  ----------------  ---------------------
Server VLAN           50            /26 (62)  10.0.0.0/26       10.0.0.1 - .62
Workstation VLAN      25            /27 (30)  10.0.0.64/27      10.0.0.65 - .94
Management VLAN       10            /28 (14)  10.0.0.96/28      10.0.0.97 - .110
Point-to-point link   2             /30 (2)   10.0.0.112/30     10.0.0.113 - .114
```

Allocate largest subnets first to avoid fragmentation. Each subnet starts at the next available boundary aligned to its block size.

### IPv6 Subnetting Basics

IPv6 uses 128-bit addresses with a different subnetting model. The standard allocation is /64 for a single subnet (2^64 host addresses).

```text
IPv6 address:   2001:0db8:0001:000a:0000:0000:0000:0001
Structure:      |------ 48 ------||16|| -------- 64 --------|
                Global prefix     Sub  Interface ID
                                  net

Common allocations:
  /48  → Organization (65,536 subnets)
  /64  → Single subnet (standard)
  /128 → Single host
```

```bash
# Show IPv6 addresses and prefix length
ip -6 addr show

# Calculate IPv6 subnet
python3 -c "
import ipaddress
net = ipaddress.ip_network('2001:db8:1:a::/64')
print(f'Network: {net.network_address}')
print(f'Prefix:  /{net.prefixlen}')
print(f'Addresses: {net.num_addresses}')
"
```

## References

### Official Standards

- [RFC 950 — Internet Standard Subnetting Procedure](https://datatracker.ietf.org/doc/html/rfc950)
- [RFC 4632 — Classless Inter-Domain Routing (CIDR)](https://datatracker.ietf.org/doc/html/rfc4632)
- [RFC 1878 — Variable Length Subnet Table for IPv4](https://datatracker.ietf.org/doc/html/rfc1878)
- [RFC 1918 — Address Allocation for Private Internets](https://datatracker.ietf.org/doc/html/rfc1918)
- [RFC 6890 — Special-Purpose IP Address Registries](https://datatracker.ietf.org/doc/html/rfc6890)
- [RFC 791 — Internet Protocol (IPv4)](https://datatracker.ietf.org/doc/html/rfc791)
