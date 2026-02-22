% Filename: 01-fundamentals/linux-basics/bash-intro.md
% Display name: Bash Introduction
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Bash Introduction

## Overview

Bash (Bourne Again Shell) is the default shell on most Linux distributions and the scripting language penetration testers use most often for quick automation. Writing Bash scripts eliminates repetitive typing during engagements — automating port scans across subnets, parsing tool output, chaining enumeration steps, and building simple listeners.

This guide covers Bash fundamentals for security professionals: variables, conditionals, loops, functions, and practical scripting patterns used during penetration tests.

## Key Concepts

### Script Structure

```bash
#!/bin/bash
# Shebang line — tells the system to use Bash to execute this script

# Comments start with #
# Script description: what it does, usage, author
```

```bash
# Make a script executable
chmod +x script.sh

# Run it
./script.sh

# Or run with bash directly (no chmod needed)
bash script.sh
```

The shebang (`#!/bin/bash`) must be the first line. Without it, the system may try to interpret the script with a different shell.

### Variables

```bash
# Assignment — no spaces around the equals sign
name="value"
ip="192.168.1.1"
port=80
output_dir="/tmp/results"

# Usage — prefix with $
echo $ip
echo "Target: $ip on port $port"
echo "Target: ${ip}:${port}"     # Braces for clarity/concatenation
```

Curly braces `${var}` are required when appending text directly: `${ip}_scan.txt` works, `$ip_scan.txt` does not (Bash looks for variable `ip_scan`).

```bash
# Command substitution — capture command output
current_date=$(date +%Y-%m-%d)
my_ip=$(ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
host_count=$(wc -l < hosts.txt)

# Arithmetic
count=$((count + 1))
port=$((8000 + RANDOM % 1000))
```

### Special Variables

| Variable | Meaning |
|----------|---------|
| `$0` | Script name |
| `$1`, `$2`, ... | Positional arguments |
| `$#` | Number of arguments |
| `$@` | All arguments (each as a separate word when quoted: `"$@"`) |
| `$*` | All arguments joined into one word by the first character of `$IFS` when quoted: `"$*"`; identical to `$@` when unquoted |
| `$?` | Exit code of last command (0 = success) |
| `$$` | Current script's PID |
| `$!` | PID of last background process |

```bash
#!/bin/bash
# Example: using positional arguments
target=$1
port=$2

if [ -z "$target" ]; then
    echo "Usage: $0 <target> [port]"
    exit 1
fi

port=${port:-80}    # Default to 80 if not provided
echo "Scanning $target on port $port"
```

`${var:-default}` returns `default` if `var` is unset or empty. This is the standard way to handle optional arguments.

### Conditionals

### if/elif/else

```bash
if [ condition ]; then
    # commands
elif [ condition ]; then
    # commands
else
    # commands
fi
```

### Test Expressions

String comparisons:

```bash
[ "$var" = "value" ]      # Equal
[ "$var" != "value" ]     # Not equal
[ -z "$var" ]             # Empty string
[ -n "$var" ]             # Non-empty string
```

Numeric comparisons:

```bash
[ "$a" -eq "$b" ]         # Equal
[ "$a" -ne "$b" ]         # Not equal
[ "$a" -lt "$b" ]         # Less than
[ "$a" -gt "$b" ]         # Greater than
[ "$a" -le "$b" ]         # Less than or equal
[ "$a" -ge "$b" ]         # Greater than or equal
```

File tests:

```bash
[ -f "$file" ]            # File exists (regular file)
[ -d "$dir" ]             # Directory exists
[ -e "$path" ]            # Exists (any type)
[ -r "$file" ]            # Readable
[ -w "$file" ]            # Writable
[ -x "$file" ]            # Executable
[ -s "$file" ]            # Exists and not empty
```

Logical operators:

```bash
[ condition1 ] && [ condition2 ]    # AND
[ condition1 ] || [ condition2 ]    # OR
[ ! condition ]                     # NOT
```

**Always quote variables inside `[ ]`** — unquoted variables with spaces or empty values cause syntax errors.

### Practical Example

```bash
#!/bin/bash
target=$1

if [ -z "$target" ]; then
    echo "[-] No target specified"
    exit 1
fi

if ping -c 1 -W 2 "$target" > /dev/null 2>&1; then
    echo "[+] $target is alive"
else
    echo "[-] $target is not responding"
fi
```

### Loops

### for Loop

```bash
# Iterate over a list
for ip in 192.168.1.1 192.168.1.2 192.168.1.3; do
    ping -c 1 -W 1 "$ip" > /dev/null 2>&1 && echo "[+] $ip alive"
done

# Iterate over a range
for i in $(seq 1 254); do
    ping -c 1 -W 1 "192.168.1.$i" > /dev/null 2>&1 && echo "[+] 192.168.1.$i alive" &
done
wait    # Wait for all background pings to finish

# C-style for loop
for ((i=1; i<=254; i++)); do
    echo "192.168.1.$i"
done

# Iterate over file lines
while IFS= read -r line; do
    echo "Processing: $line"
done < targets.txt
```

The `&` after a command runs it in the background. The `wait` command pauses until all background jobs finish. This pattern parallelizes operations — the ping sweep above runs all 254 pings simultaneously instead of sequentially.

### while Loop

```bash
# Read file line by line (preferred method)
while IFS= read -r line; do
    echo "$line"
done < input.txt

# Counter-based
count=0
while [ $count -lt 10 ]; do
    echo "Attempt $count"
    count=$((count + 1))
done

# Infinite loop (useful for listeners/monitors)
while true; do
    nc -lvnp 4444
    echo "[*] Connection closed, restarting listener..."
    sleep 1
done
```

`IFS= read -r line` is the correct way to read file lines. `IFS=` prevents leading/trailing whitespace trimming. `-r` prevents backslash interpretation.

### Functions

```bash
# Define a function
scan_port() {
    local target=$1
    local port=$2

    if nc -z -w 1 "$target" "$port" 2>/dev/null; then
        echo "[+] $target:$port open"
        return 0
    else
        return 1
    fi
}

# Call the function
scan_port 192.168.1.1 80
scan_port 192.168.1.1 443
```

`local` scopes variables to the function — without it, variables are global. Use `local` for any variable that should not leak into the rest of the script.

### Input and Output

```bash
# Read user input
read -p "Enter target IP: " target
read -sp "Enter password: " password    # Silent input (no echo)
echo ""                                  # Newline after silent input

# Colored output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'    # No Color (reset)

echo -e "${GREEN}[+] Success${NC}"
echo -e "${RED}[-] Failure${NC}"
echo -e "${YELLOW}[*] Info${NC}"
```

### Exit Codes

Every command returns an exit code. `0` means success, any non-zero value indicates failure.

```bash
# Check exit code
command
if [ $? -eq 0 ]; then
    echo "Command succeeded"
fi

# Shorthand
command && echo "Success" || echo "Failed"

# Set exit code in scripts
exit 0    # Success
exit 1    # General failure
```

### Error Handling

```bash
#!/bin/bash
set -e          # Exit on any command failure
set -u          # Exit on undefined variable use
set -o pipefail # Pipe fails if any command in the pipe fails

# Combined (common in production scripts)
set -euo pipefail
```

`set -e` stops the script immediately if any command returns non-zero — prevents cascading failures from unnoticed errors. `set -u` catches typos in variable names. `set -o pipefail` ensures `command1 | command2` fails if `command1` fails (by default, only `command2`'s exit code is checked).

## Practical Examples

### Ping Sweep

```bash
#!/bin/bash
# Custom script created for this guide

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <subnet>"
    echo "Example: $0 192.168.1"
    exit 1
fi

subnet=$1
echo "[*] Ping sweep on $subnet.0/24"

for i in $(seq 1 254); do
    ping -c 1 -W 1 "$subnet.$i" > /dev/null 2>&1 && \
        echo "[+] $subnet.$i alive" &
done
wait
echo "[*] Sweep complete"
```

### Port Scanner

```bash
#!/bin/bash
# Custom script created for this guide

target=${1:?"Usage: $0 <target> [port_range]"}
range=${2:-"1-1024"}

start_port=$(echo "$range" | cut -d'-' -f1)
end_port=$(echo "$range" | cut -d'-' -f2)

echo "[*] Scanning $target ports $start_port-$end_port"

for ((port=start_port; port<=end_port; port++)); do
    nc -z -w 1 "$target" "$port" 2>/dev/null && \
        echo "[+] Port $port open" &
done
wait
echo "[*] Scan complete"
```

### Log Parser

```bash
#!/bin/bash
# Custom script created for this guide

logfile=${1:?"Usage: $0 <logfile>"}

if [ ! -f "$logfile" ]; then
    echo "[-] File not found: $logfile"
    exit 1
fi

echo "[*] Analyzing: $logfile"
echo ""
echo "=== Top 10 Source IPs ==="
grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" "$logfile" | \
    sort | uniq -c | sort -rn | head -10

echo ""
echo "=== HTTP Status Code Summary ==="
awk '{print $9}' "$logfile" | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== Top 10 Requested Paths ==="
awk '{print $7}' "$logfile" | sort | uniq -c | sort -rn | head -10
```

## References

### Official Documentation

- [Bash Reference Manual](https://www.gnu.org/software/bash/manual/)
- [The Linux man-pages Project — bash(1)](https://man7.org/linux/man-pages/man1/bash.1.html)
