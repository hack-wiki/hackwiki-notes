% Filename: 13-programming/bash/scripting.md
% Display name: Bash Script Writing
% Last update: 2026-02-19
% Authors: @TristanInSec

# Bash Script Writing

## Overview

Bash scripting automates command sequences, tool chains, and data processing
tasks. For security work, this means writing enumeration scripts, parsing tool
output, automating scans, and building reusable utilities. This file covers
Bash scripting fundamentals with a focus on patterns commonly used in security
automation.

## Variables and Data Types

```bash
#!/usr/bin/env bash
# Bash
# https://www.gnu.org/software/bash/

# Variable assignment (no spaces around =)
target="10.0.0.1"
port=80
wordlist="/usr/share/wordlists/dirb/common.txt"

# String interpolation
echo "Scanning $target on port $port"
echo "Target is: ${target}"

# Command substitution
current_ip=$(hostname -I | awk '{print $1}')
date_stamp=$(date +%Y%m%d_%H%M%S)
open_ports=$(nmap -sT -p- --min-rate 5000 "$target" 2>/dev/null | grep "open" | cut -d/ -f1 | tr '\n' ',')

# Read-only variables
readonly BASE_DIR="/opt/tools"

# Default values
output_file="${1:-results.txt}"    # use $1, default to results.txt
threads="${THREADS:-10}"           # use env var, default to 10

# String operations
filename="scan_results.txt"
echo "${filename%.txt}"            # scan_results (remove suffix)
echo "${filename##*.}"             # txt (extract extension)
echo "${filename^^}"               # SCAN_RESULTS.TXT (uppercase)
echo "${filename,,}"               # scan_results.txt (lowercase)
echo "${#filename}"                # 16 (string length)
```

## Arrays

```bash
#!/usr/bin/env bash
# Bash — arrays
# https://www.gnu.org/software/bash/

# Indexed arrays
ports=(22 80 443 8080 8443)
targets=("10.0.0.1" "10.0.0.2" "10.0.0.3")

# Access elements
echo "${ports[0]}"                 # 22
echo "${ports[@]}"                 # all elements
echo "${#ports[@]}"                # 5 (array length)

# Append to array
ports+=(3306 5432)

# Iterate over array
for port in "${ports[@]}"; do
    echo "Checking port $port"
done

# Build array from command output
live_hosts=()
while IFS= read -r line; do
    live_hosts+=("$line")
done < <(nmap -sn 10.0.0.0/24 2>/dev/null | grep "report for" | awk '{print $NF}' | tr -d '()')

# Associative arrays (dictionaries)
declare -A services
services[22]="ssh"
services[80]="http"
services[443]="https"

for port in "${!services[@]}"; do
    echo "Port $port: ${services[$port]}"
done
```

## Control Flow

### Conditionals

```bash
#!/usr/bin/env bash
# Bash — conditionals
# https://www.gnu.org/software/bash/

# if/elif/else
if [[ -f "/etc/shadow" ]]; then
    echo "Shadow file exists"
elif [[ -f "/etc/passwd" ]]; then
    echo "Only passwd exists"
else
    echo "Neither found"
fi

# String comparisons
if [[ "$response" == "200" ]]; then
    echo "Success"
fi

if [[ "$url" == *"admin"* ]]; then
    echo "Admin page found"
fi

# Numeric comparisons
if [[ "$port" -gt 0 && "$port" -lt 65536 ]]; then
    echo "Valid port"
fi

# File tests
[[ -f "$file" ]]      # file exists and is regular file
[[ -d "$dir" ]]       # directory exists
[[ -r "$file" ]]      # file is readable
[[ -w "$file" ]]      # file is writable
[[ -x "$file" ]]      # file is executable
[[ -s "$file" ]]      # file exists and is not empty
[[ -z "$var" ]]       # variable is empty
[[ -n "$var" ]]       # variable is not empty

# Command success check
if ping -c 1 -W 1 "$target" &>/dev/null; then
    echo "$target is up"
fi

if command -v nmap &>/dev/null; then
    echo "nmap is installed"
fi
```

### Loops

```bash
#!/usr/bin/env bash
# Bash — loops
# https://www.gnu.org/software/bash/

# For loop — iterate over values
for port in 22 80 443 8080; do
    echo "Scanning port $port"
done

# For loop — range
for i in {1..254}; do
    ping -c 1 -W 1 "10.0.0.$i" &>/dev/null && echo "10.0.0.$i is up" &
done
wait  # wait for all background jobs

# For loop — C-style
for ((i=1; i<=100; i++)); do
    echo "Iteration $i"
done

# While loop — read file line by line
while IFS= read -r line; do
    echo "Processing: $line"
done < targets.txt

# While loop — process command output
nmap -sn 10.0.0.0/24 2>/dev/null | grep "report for" | while IFS= read -r line; do
    ip=$(echo "$line" | awk '{print $NF}' | tr -d '()')
    echo "Found host: $ip"
done

# Until loop
attempts=0
until curl -s "http://$target/" &>/dev/null || [[ $attempts -ge 10 ]]; do
    attempts=$((attempts + 1))
    sleep 2
done
```

## Functions

```bash
#!/usr/bin/env bash
# Bash — functions
# https://www.gnu.org/software/bash/

# Function definition
scan_host() {
    local target="$1"
    local ports="${2:-22,80,443}"

    echo "[*] Scanning $target (ports: $ports)"
    nmap -sT -p "$ports" "$target" 2>/dev/null
}

# Call the function
scan_host "10.0.0.1" "22,80,443,8080"

# Function with return value (via stdout)
check_port() {
    local host="$1"
    local port="$2"
    timeout 3 bash -c "echo '' > /dev/tcp/$host/$port" 2>/dev/null && echo "open" || echo "closed"
}

status=$(check_port "10.0.0.1" 80)
echo "Port 80 is $status"

# Function with exit code
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[!] This script must be run as root" >&2
        return 1
    fi
    return 0
}

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'  # No Color

info()    { printf "${GREEN}[+]${NC} $1\n"; }
warning() { printf "${YELLOW}[!]${NC} $1\n"; }
error()   { printf "${RED}[-]${NC} $1\n" >&2; }
```

## Input and Output

```bash
#!/usr/bin/env bash
# Bash — I/O redirection
# https://www.gnu.org/software/bash/

# Redirect stdout to file
nmap -sn 10.0.0.0/24 > scan_results.txt

# Redirect stdout and stderr
nmap -sV 10.0.0.1 > results.txt 2>&1

# Append to file
echo "New finding" >> results.txt

# Redirect stderr only
nmap -sV 10.0.0.1 2>/dev/null

# Pipe output to another command
cat targets.txt | while IFS= read -r target; do
    nmap -sT -p 80 "$target" 2>/dev/null
done

# Process substitution
diff <(sort file1.txt) <(sort file2.txt)

# Here string
grep "admin" <<< "$response_body"

# Read user input
read -p "Enter target IP: " target
read -sp "Enter password: " password  # silent input
echo ""

# Read with timeout
if read -t 10 -p "Continue? [y/N] " answer; then
    [[ "$answer" =~ ^[Yy] ]] && echo "Continuing..."
fi
```

## Error Handling

```bash
#!/usr/bin/env bash
# Bash — error handling
# https://www.gnu.org/software/bash/

# Exit on error
set -e

# Exit on undefined variable
set -u

# Fail on pipe errors
set -o pipefail

# Combined (recommended for scripts)
set -euo pipefail

# Trap errors
cleanup() {
    echo "[*] Cleaning up temporary files..."
    rm -f /tmp/scan_*.tmp
}
trap cleanup EXIT        # run on script exit
trap cleanup ERR         # run on error
trap 'echo "Interrupted"; exit 1' INT  # handle Ctrl+C

# Check command exit status
if ! nmap -sn "$target" > /tmp/scan_$$.tmp 2>/dev/null; then
    echo "[!] Scan failed for $target"
    exit 1
fi
```

## Script Template

```bash
#!/usr/bin/env bash
# Description: Security automation script template
# Usage: ./script.sh <target> [options]

set -euo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
info()    { printf "${GREEN}[+]${NC} $1\n"; }
warning() { printf "${YELLOW}[!]${NC} $1\n"; }
error()   { printf "${RED}[-]${NC} $1\n" >&2; }

# Usage
usage() {
    echo "Usage: $0 <target> [-p ports] [-o output] [-v]"
    echo "  target      Target IP or hostname"
    echo "  -p ports    Port range (default: 1-1024)"
    echo "  -o output   Output file"
    echo "  -v          Verbose mode"
    exit 1
}

# Defaults
PORTS="1-1024"
OUTPUT=""
VERBOSE=false

# Parse arguments
[[ $# -lt 1 ]] && usage
TARGET="$1"; shift

while getopts "p:o:vh" opt; do
    case $opt in
        p) PORTS="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        v) VERBOSE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Cleanup on exit
cleanup() { rm -f /tmp/scan_$$.tmp; }
trap cleanup EXIT

# Check dependencies
for cmd in nmap curl; do
    if ! command -v "$cmd" &>/dev/null; then
        error "$cmd is required but not installed"
        exit 1
    fi
done

# Main logic
info "Scanning $TARGET (ports: $PORTS)"
# ... scan logic here ...
info "Done"
```

## References

### Further Reading

- [Bash Reference Manual](https://www.gnu.org/software/bash/manual/bash.html)
- [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
