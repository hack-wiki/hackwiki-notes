% Filename: 13-programming/python/networking.md
% Display name: Network Programming
% Last update: 2026-02-11
% Authors: @TristanInSec

# Network Programming

## Overview

Python's socket library provides low-level network access for building port
scanners, reverse shells, and custom protocol clients. Higher-level libraries
like scapy enable packet crafting and sniffing, while paramiko provides SSH
automation. This file covers practical network programming patterns used in
security testing.

## Socket Programming

### TCP Client

```python
# socket — low-level networking
# https://docs.python.org/3/library/socket.html

import socket

def tcp_connect(host, port, timeout=5):
    """Connect to a TCP service and return the banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            # Send data
            s.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
            # Receive response
            response = s.recv(4096)
            return response.decode(errors="replace")
    except socket.error as e:
        return f"Error: {e}"

banner = tcp_connect("10.0.0.1", 80)
print(banner)
```

### TCP Server (Listener)

```python
# socket — TCP server
# https://docs.python.org/3/library/socket.html

import socket

def start_listener(bind_ip="0.0.0.0", bind_port=4444):
    """Start a TCP listener (e.g., for catching reverse shells)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_ip, bind_port))
        server.listen(1)
        print(f"[*] Listening on {bind_ip}:{bind_port}")

        client, addr = server.accept()
        print(f"[+] Connection from {addr[0]}:{addr[1]}")

        with client:
            while True:
                data = client.recv(4096)
                if not data:
                    break
                print(data.decode(errors="replace"), end="")
```

### UDP Client

```python
# socket — UDP communication
# https://docs.python.org/3/library/socket.html

import socket

def udp_send(host, port, data, timeout=3):
    """Send a UDP datagram and receive a response."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(data, (host, port))
        try:
            response, addr = s.recvfrom(4096)
            return response
        except socket.timeout:
            return None

# UDP example: send data to a target
response = udp_send("10.0.0.1", 161, b"\x30\x26\x02\x01\x01")  # SNMP query bytes
```

## Port Scanner

```python
# socket — TCP port scanner
# https://docs.python.org/3/library/socket.html

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(host, port, timeout=1):
    """Check if a single TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                # Try to grab banner
                try:
                    s.send(b"\r\n")
                    banner = s.recv(1024).decode(errors="replace").strip()
                except (socket.timeout, socket.error):
                    banner = ""
                return port, True, banner
            return port, False, ""
    except socket.error:
        return port, False, ""

def port_scan(host, ports, threads=50):
    """Scan multiple ports concurrently."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port): port
            for port in ports
        }
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))
                info = f" — {banner}" if banner else ""
                print(f"  [+] {port}/tcp open{info}")
    return sorted(open_ports)

# Usage
target = "10.0.0.1"
print(f"Scanning {target}...")
results = port_scan(target, range(1, 1025))
print(f"\n{len(results)} open ports found")
```

## Packet Crafting with Scapy

### Basic Packet Construction

```python
# Scapy
# https://scapy.net/

from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, send, conf

# Disable verbose output
conf.verb = 0

# ICMP ping
pkt = IP(dst="10.0.0.1") / ICMP()
resp = sr1(pkt, timeout=2)
if resp:
    print(f"Host is up (TTL: {resp.ttl})")

# TCP SYN packet
syn = IP(dst="10.0.0.1") / TCP(dport=80, flags="S")
resp = sr1(syn, timeout=2)
if resp and resp.haslayer(TCP):
    if resp[TCP].flags == "SA":  # SYN-ACK
        print("Port 80 is open")
    elif resp[TCP].flags == "RA":  # RST-ACK
        print("Port 80 is closed")

# UDP packet
udp_pkt = IP(dst="10.0.0.1") / UDP(dport=53) / b"\x00\x00"
resp = sr1(udp_pkt, timeout=2)
```

### SYN Scan

```python
# Scapy — SYN scan
# https://scapy.net/

from scapy.all import IP, TCP, sr, conf

conf.verb = 0

def syn_scan(target, ports):
    """Perform a SYN scan using scapy."""
    # Send SYN packets to all ports at once
    pkt = IP(dst=target) / TCP(dport=ports, flags="S")
    answered, unanswered = sr(pkt, timeout=2)

    open_ports = []
    for sent, received in answered:
        if received.haslayer(TCP) and received[TCP].flags == 0x12:  # SYN-ACK
            open_ports.append(received[TCP].sport)
            # Send RST to close the half-open connection
            rst = IP(dst=target) / TCP(
                dport=received[TCP].sport, flags="R"
            )
            send(rst)

    return sorted(open_ports)

# Requires root privileges
results = syn_scan("10.0.0.1", list(range(1, 1025)))
for port in results:
    print(f"  {port}/tcp open")
```

### ARP Scanning

```python
# Scapy — ARP host discovery
# https://scapy.net/

from scapy.all import Ether, ARP, srp, conf

conf.verb = 0

def arp_scan(network):
    """Discover hosts on a local network via ARP."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=2)

    hosts = []
    for sent, received in answered:
        hosts.append({
            "ip": received[ARP].psrc,
            "mac": received[ARP].hwsrc
        })
    return hosts

# Requires root privileges
hosts = arp_scan("10.0.0.0/24")
for h in hosts:
    print(f"  {h['ip']:15s}  {h['mac']}")
```

### Packet Sniffing

```python
# Scapy — packet capture and filtering
# https://scapy.net/

from scapy.all import sniff, wrpcap, DNS, DNSQR, TCP, IP

def packet_callback(pkt):
    """Process each captured packet."""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode()
        print(f"DNS query: {query}")

    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport
        if pkt[TCP].flags == "S":
            print(f"SYN: {src} → {dst}:{dport}")

# Capture 100 packets on eth0 with a BPF filter
# Requires root privileges
packets = sniff(
    iface="eth0",
    count=100,
    filter="tcp port 80 or udp port 53",
    prn=packet_callback
)

# Save captured packets to PCAP
wrpcap("capture.pcap", packets)
```

## SSH Automation with Paramiko

```python
# Paramiko
# https://www.paramiko.org/

import paramiko

def ssh_execute(host, username, password, command, port=22):
    """Execute a command over SSH and return the output."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=username, password=password)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        errors = stderr.read().decode()
        return output, errors
    finally:
        client.close()

# Execute a command
output, errors = ssh_execute(
    "10.0.0.1", "admin", "password123", "id && hostname"
)
print(output)
```

### SSH Key Authentication

```python
# Paramiko — key-based authentication
# https://www.paramiko.org/

import paramiko

def ssh_key_execute(host, username, key_path, command, port=22):
    """Execute a command over SSH using key authentication."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.RSAKey.from_private_key_file(key_path)

    try:
        client.connect(host, port=port, username=username, pkey=key)
        stdin, stdout, stderr = client.exec_command(command)
        return stdout.read().decode()
    finally:
        client.close()

# SFTP file transfer
def sftp_download(host, username, password, remote_path, local_path, port=22):
    """Download a file over SFTP."""
    transport = paramiko.Transport((host, port))
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)

    try:
        sftp.get(remote_path, local_path)
        print(f"Downloaded: {remote_path} → {local_path}")
    finally:
        sftp.close()
        transport.close()
```

### SSH Command on Multiple Hosts

```python
# Paramiko — run commands on multiple hosts
# https://www.paramiko.org/

import paramiko
from concurrent.futures import ThreadPoolExecutor

def run_on_host(host, username, password, command):
    """Run a command on a single host and return results."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password, timeout=5)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        client.close()
        return host, output, None
    except Exception as e:
        return host, None, str(e)

# Run 'id' on multiple hosts
hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [
        executor.submit(run_on_host, h, "admin", "password", "id")
        for h in hosts
    ]
    for future in futures:
        host, output, error = future.result()
        if output:
            print(f"  {host}: {output}")
        else:
            print(f"  {host}: ERROR — {error}")
```

## DNS Resolution

```python
# socket — DNS lookups
# https://docs.python.org/3/library/socket.html

import socket

# Forward lookup
try:
    ip = socket.gethostbyname("example.com")
    print(f"A record: {ip}")
except socket.gaierror:
    print("Resolution failed")

# Get all addresses
addrs = socket.getaddrinfo("example.com", 443, socket.AF_INET)
for addr in addrs:
    print(f"  {addr[4][0]}")

# Reverse lookup
try:
    hostname, aliases, ips = socket.gethostbyaddr("8.8.8.8")
    print(f"PTR: {hostname}")
except socket.herror:
    print("Reverse lookup failed")
```

## References

### Tools

- [Scapy](https://scapy.net/)
- [Paramiko](https://www.paramiko.org/)

### Further Reading

- [Python Socket Programming HOWTO](https://docs.python.org/3/howto/sockets.html)
- [Scapy Documentation](https://scapy.readthedocs.io/en/latest/)
