% Filename: 13-programming/python/scripting.md
% Display name: Python Scripting
% Last update: 2026-02-11
% Authors: @TristanInSec

# Python Scripting

## Overview

Python scripting for security involves automating repetitive tasks, parsing
tool output, processing files, and building custom utilities. This file
covers the core Python patterns most useful in security work: file I/O,
subprocess execution, argument parsing, regular expressions, and data
encoding.

## File Operations

### Reading and Writing Files

```python
# Python 3 standard library
# https://docs.python.org/3/library/functions.html

# Read an entire file
with open("/etc/passwd", "r") as f:
    content = f.read()

# Read line by line (memory efficient for large files)
with open("/etc/passwd", "r") as f:
    for line in f:
        parts = line.strip().split(":")
        username, uid = parts[0], parts[2]
        print(f"{username} (UID: {uid})")

# Write output to a file
with open("results.txt", "w") as f:
    f.write("Scan results\n")
    f.write(f"Target: 10.0.0.1\n")

# Append to a file
with open("results.txt", "a") as f:
    f.write("Additional finding\n")

# Read binary file (e.g., for hash calculation)
with open("suspect.exe", "rb") as f:
    data = f.read()
```

### Working with Paths

```python
# pathlib — object-oriented filesystem paths
# https://docs.python.org/3/library/pathlib.html

from pathlib import Path

# Path operations
p = Path("/var/log/auth.log")
print(p.name)       # auth.log
print(p.stem)       # auth
print(p.suffix)     # .log
print(p.parent)     # /var/log
print(p.exists())   # True/False

# List directory contents
for f in Path("/etc").iterdir():
    if f.is_file():
        print(f.name)

# Recursive glob (find all .conf files)
for f in Path("/etc").rglob("*.conf"):
    print(f)

# Read/write with pathlib
content = Path("/etc/hostname").read_text()
Path("output.txt").write_text("results here\n")
```

## Subprocess Execution

```python
# subprocess — run external commands
# https://docs.python.org/3/library/subprocess.html

import subprocess

# Run a command and capture output
result = subprocess.run(
    ["nmap", "-sn", "10.0.0.0/24"],
    capture_output=True,
    text=True,
    timeout=120
)
print(result.stdout)
if result.returncode != 0:
    print(f"Error: {result.stderr}")

# Run with shell=True (use only with trusted input)
result = subprocess.run(
    "cat /etc/passwd | grep root",
    shell=True,
    capture_output=True,
    text=True
)

# Stream output line by line (for long-running commands)
proc = subprocess.Popen(
    ["tcpdump", "-i", "eth0", "-c", "10"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)
for line in proc.stdout:
    print(f"Captured: {line.strip()}")
proc.wait()

# Check if command succeeded
result = subprocess.run(["ping", "-c", "1", "10.0.0.1"], capture_output=True)
if result.returncode == 0:
    print("Host is up")
```

## Argument Parsing

```python
# argparse — command-line argument parsing
# https://docs.python.org/3/library/argparse.html

import argparse

parser = argparse.ArgumentParser(
    description="Port scanner"
)
parser.add_argument(
    "target",
    help="Target IP address or hostname"
)
parser.add_argument(
    "-p", "--ports",
    default="1-1024",
    help="Port range (default: 1-1024)"
)
parser.add_argument(
    "-t", "--threads",
    type=int,
    default=10,
    help="Number of threads (default: 10)"
)
parser.add_argument(
    "-v", "--verbose",
    action="store_true",
    help="Enable verbose output"
)
parser.add_argument(
    "-o", "--output",
    help="Output file path"
)

args = parser.parse_args()
print(f"Scanning {args.target} ports {args.ports}")
if args.verbose:
    print("Verbose mode enabled")
```

## Regular Expressions

```python
# re — regular expressions
# https://docs.python.org/3/library/re.html

import re

text = "Server at 192.168.1.100 responded on port 443"

# Find a single match
match = re.search(r"(\d{1,3}\.){3}\d{1,3}", text)
if match:
    print(f"Found IP: {match.group()}")  # 192.168.1.100

# Find all matches
ips = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)

# Common security-relevant patterns
ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
email_pattern = r"[\w.+-]+@[\w-]+\.[\w.]+"
url_pattern = r"https?://[^\s<>\"']+"
hash_md5 = r"[a-fA-F0-9]{32}"
hash_sha256 = r"[a-fA-F0-9]{64}"

# Extract usernames from auth.log
log_line = 'Failed password for admin from 10.0.0.50 port 22 ssh2'
match = re.search(r"Failed password for (\S+) from (\S+)", log_line)
if match:
    user, ip = match.group(1), match.group(2)
    print(f"Failed login: user={user}, source={ip}")

# Replace / sanitize
cleaned = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "[REDACTED]", text)
```

## Data Encoding and Hashing

```python
# base64, hashlib — encoding and hashing
# https://docs.python.org/3/library/base64.html
# https://docs.python.org/3/library/hashlib.html

import base64
import hashlib

# Base64 encoding/decoding
encoded = base64.b64encode(b"payload data").decode()
decoded = base64.b64decode(encoded)

# URL-safe base64
url_safe = base64.urlsafe_b64encode(b"data").decode()

# File hashing
def hash_file(filepath):
    """Calculate MD5, SHA1, and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }

hashes = hash_file("/bin/ls")
print(f"MD5:    {hashes['md5']}")
print(f"SHA1:   {hashes['sha1']}")
print(f"SHA256: {hashes['sha256']}")

# String hashing
password_hash = hashlib.sha256(b"password123").hexdigest()

# Hex encoding
data = b"\x41\x42\x43"
hex_str = data.hex()           # "414243"
back = bytes.fromhex(hex_str)  # b"ABC"
```

## JSON Handling

```python
# json — JSON encoding and decoding
# https://docs.python.org/3/library/json.html

import json

# Parse JSON string
data = json.loads('{"ip": "10.0.0.1", "ports": [22, 80, 443]}')
print(data["ip"])        # 10.0.0.1
print(data["ports"][0])  # 22

# Read JSON file
with open("scan_results.json", "r") as f:
    results = json.load(f)

# Write JSON file (formatted)
findings = {
    "target": "10.0.0.1",
    "open_ports": [22, 80, 443],
    "vulnerabilities": ["CVE-2024-1234"]
}
with open("report.json", "w") as f:
    json.dump(findings, f, indent=2)

# Pretty-print JSON
print(json.dumps(findings, indent=2))
```

## Threading for Concurrency

```python
# concurrent.futures — parallel execution
# https://docs.python.org/3/library/concurrent.futures.html

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

def check_port(host, port):
    """Check if a TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return port, result == 0
    except socket.error:
        return port, False

# Scan ports concurrently
target = "10.0.0.1"
ports = range(1, 1025)

with ThreadPoolExecutor(max_workers=50) as executor:
    futures = {
        executor.submit(check_port, target, port): port
        for port in ports
    }
    for future in as_completed(futures):
        port, is_open = future.result()
        if is_open:
            print(f"Port {port} is open")
```

## Script Template

```python
#!/usr/bin/env python3
"""Security tool description."""

# Python 3 standard library
# https://docs.python.org/3/

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Tool description")
    parser.add_argument("target", help="Target to scan")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    try:
        # Main logic here
        results = do_scan(args.target)

        if args.output:
            with open(args.output, "w") as f:
                f.write(results)
        else:
            print(results)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

def do_scan(target):
    """Perform the scan and return results."""
    return f"Scanned {target}"

if __name__ == "__main__":
    main()
```

## References

### Further Reading

- [Python 3 Standard Library](https://docs.python.org/3/library/)
- [Python argparse Tutorial](https://docs.python.org/3/howto/argparse.html)
