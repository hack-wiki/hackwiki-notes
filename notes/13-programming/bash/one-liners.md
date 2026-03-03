% Filename: 13-programming/bash/one-liners.md
% Display name: Useful One-Liners
% Last update: 2026-02-19
% Authors: @TristanInSec

# Useful One-Liners

## Overview

One-liners combine shell commands with pipes and redirection to accomplish
complex tasks in a single line. These are invaluable during engagements for
quick reconnaissance, data extraction, log analysis, and file processing
without writing full scripts.

## Network Reconnaissance

```bash
# Bash one-liners
# https://www.gnu.org/software/bash/

# Ping sweep — find live hosts on a /24
for i in {1..254}; do ping -c 1 -W 1 10.0.0.$i &>/dev/null && echo "10.0.0.$i is up" & done; wait

# TCP port check using /dev/tcp (no tools needed)
for port in 22 80 443 445 3389 8080; do (echo >/dev/tcp/10.0.0.1/$port) 2>/dev/null && echo "$port open"; done

# Scan a range of ports on a single host
for port in $(seq 1 1024); do (echo >/dev/tcp/10.0.0.1/$port) 2>/dev/null && echo "$port open" & done; wait

# Banner grabbing with /dev/tcp
exec 3<>/dev/tcp/10.0.0.1/80; printf "HEAD / HTTP/1.1\r\nHost: target\r\n\r\n" >&3; timeout 2 cat <&3; exec 3>&-

# DNS reverse lookup sweep
for i in {1..254}; do host 10.0.0.$i 2>/dev/null | grep "pointer" && true; done

# Find all listening ports on localhost
ss -tlnp | awk 'NR>1 {print $4}' | rev | cut -d: -f1 | rev | sort -un

# ARP table — show local network neighbors
ip neigh show | awk '{print $1, $5}'
```

## File Operations

```bash
# Bash one-liners — file operations
# https://www.gnu.org/software/bash/

# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find world-writable files
find / -perm -o+w -type f 2>/dev/null | grep -v "/proc\|/sys"

# Find files modified in the last 24 hours
find / -mtime -1 -type f 2>/dev/null | grep -v "/proc\|/sys\|/run"

# Find large files (over 100MB)
find / -type f -size +100M 2>/dev/null

# Find files owned by a specific user
find / -user www-data -type f 2>/dev/null

# Search for passwords in files
grep -rli "password" /etc/ 2>/dev/null

# Search for IP addresses in files
grep -rEo '([0-9]{1,3}\.){3}[0-9]{1,3}' /var/log/ 2>/dev/null | sort -u

# Search for private keys
find / -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null

# Calculate SHA256 hash of all files in a directory
find /suspicious/dir -type f -exec sha256sum {} \;

# Compare two directory listings
diff <(ls -la /dir1/) <(ls -la /dir2/)
```

## Text Processing

```bash
# Bash one-liners — text processing
# https://www.gnu.org/software/bash/

# Extract unique IPs from a log file
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' access.log | sort -u

# Top 20 IPs by request count
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20

# Extract URLs from a file
grep -oE 'https?://[^ >"]+' file.html | sort -u

# Extract email addresses
grep -oEi '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' file.txt | sort -u

# Count lines matching a pattern
grep -c "Failed password" /var/log/auth.log

# Extract specific field from CSV
cut -d',' -f2 data.csv | sort -u

# Remove duplicate lines (preserving order)
awk '!seen[$0]++' file.txt

# Sort IP addresses numerically
sort -t. -k1,1n -k2,2n -k3,3n -k4,4n ips.txt

# Convert Windows line endings to Unix
tr -d '\r' < windows_file.txt > unix_file.txt

# Extract between two patterns
sed -n '/START/,/END/p' file.txt

# Base64 decode a string
echo "dGVzdA==" | base64 -d

# URL decode a string
echo "%48%65%6c%6c%6f" | python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))"

# Hex dump first 16 bytes of a file
xxd -l 16 file.bin
```

## Log Analysis

```bash
# Bash one-liners — log analysis
# https://www.gnu.org/software/bash/

# Failed SSH logins by IP (top 20)
grep "Failed password" /var/log/auth.log | grep -oE 'from [0-9.]+' | awk '{print $2}' | sort | uniq -c | sort -rn | head -20

# Successful logins
grep "Accepted" /var/log/auth.log | awk '{print $1,$2,$3,$9,$11}'

# HTTP status code distribution
awk '{print $9}' access.log | sort | uniq -c | sort -rn

# Requests per minute (detect bursts)
awk '{print $4}' access.log | cut -d: -f1-3 | sort | uniq -c | sort -rn | head -20

# Find 404 errors with paths
awk '$9 == 404 {print $7}' access.log | sort | uniq -c | sort -rn | head -20

# User agents (detect scanners)
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn | head -20

# Events per hour from syslog
awk '{print $1, $2, substr($3,1,2)":00"}' /var/log/syslog | sort | uniq -c | sort -rn

# Extract sudo commands
grep "COMMAND=" /var/log/auth.log | awk -F'COMMAND=' '{print $2}' | sort | uniq -c | sort -rn
```

## Encoding and Hashing

```bash
# Bash one-liners — encoding
# https://www.gnu.org/software/bash/

# Base64 encode
echo -n "payload" | base64

# Base64 decode
echo "cGF5bG9hZA==" | base64 -d

# MD5 hash a string
echo -n "password123" | md5sum | awk '{print $1}'

# SHA256 hash a file
sha256sum /path/to/file

# Generate random hex string (e.g., for tokens)
openssl rand -hex 32

# Generate random base64 string
openssl rand -base64 32

# URL encode a string
python3 -c "import urllib.parse; print(urllib.parse.quote('test string & special=chars'))"

# Hex encode
echo -n "ABC" | xxd -p

# Hex decode
echo "414243" | xxd -r -p
```

## Process and System

```bash
# Bash one-liners — system enumeration
# https://www.gnu.org/software/bash/

# List all processes with full command lines
ps auxww

# Find processes running as root
ps aux | awk '$1 == "root" {print}'

# Find process by port
ss -tlnp | grep ":80 "

# Monitor file changes in real time
inotifywait -m -r /var/www/ -e modify,create,delete 2>/dev/null

# Watch for new network connections
watch -n 1 'ss -tn state established'

# List all cron jobs for all users
for user in $(cut -f1 -d: /etc/passwd); do crontab -u "$user" -l 2>/dev/null | grep -v '^#' | grep -v '^$' && echo "=== $user ===" ; done

# Find environment variables containing secrets
env | grep -iE "pass|key|secret|token"

# Check for capabilities on binaries
getcap -r / 2>/dev/null
```

## Web Testing

```bash
# Bash one-liners — web testing
# https://www.gnu.org/software/bash/

# Check HTTP status code
curl -s -o /dev/null -w "%{http_code}" https://target.com/

# Fetch page title
curl -sL https://target.com | grep -oP '<title>\K[^<]+'

# Test multiple URLs from a file
while IFS= read -r url; do echo -n "$url: "; curl -s -o /dev/null -w "%{http_code}" "$url"; echo; done < urls.txt

# Directory brute-force (basic, use gobuster for real work)
while IFS= read -r word; do code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$word"); [[ "$code" != "404" ]] && echo "$word: $code"; done < /usr/share/wordlists/dirb/common.txt

# Extract all links from a page
curl -sL https://target.com | grep -oE 'href="[^"]+"' | cut -d'"' -f2 | sort -u

# Check HTTP headers
curl -sI https://target.com

# Test for open redirect
curl -sI "https://target.com/redirect?url=https://evil.com" | grep -i "location"

# Send POST request with data
curl -s -X POST https://target.com/login -d "user=admin&pass=test" -c cookies.txt

# Follow redirects and show each step
curl -sLv https://target.com 2>&1 | grep -E "^< HTTP|^< Location"
```

## Data Transfer

```bash
# Bash one-liners — data transfer
# https://www.gnu.org/software/bash/

# Simple HTTP server (serve files from current directory)
python3 -m http.server 8000

# Download file
curl -sLO https://example.com/file.txt
wget -q https://example.com/file.txt

# Upload file via curl
curl -F "file=@/path/to/file" https://target.com/upload

# Transfer file via netcat
# Receiver:
nc -lvnp 4444 > received_file
# Sender:
nc 10.0.0.1 4444 < file_to_send

# Create a tar archive and send over network
tar czf - /directory | nc 10.0.0.1 4444
# Receiver:
nc -lvnp 4444 | tar xzf -

# Base64 file transfer (copy-paste friendly)
base64 -w 0 binary_file > encoded.txt
# On receiving end:
base64 -d encoded.txt > binary_file
```

## References

### Further Reading

- [Bash Reference Manual](https://www.gnu.org/software/bash/manual/bash.html)
- [Explainshell](https://explainshell.com/)
