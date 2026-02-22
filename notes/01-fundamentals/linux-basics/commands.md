% Filename: 01-fundamentals/linux-basics/commands.md
% Display name: Essential Commands
% Last update: 2026-02-19
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Essential Commands

## Overview

These are the core Linux commands security professionals use daily — navigating filesystems, processing text, managing files, gathering system information, and working with networks. Every command here is a standard utility available on any Linux distribution without additional installation.

## Key Concepts

### Getting Help

```bash
# Man pages — the definitive reference for any command
man ls
man -k "search term"    # Search man page descriptions

# Quick help — most commands support --help
ls --help
grep --help

# Which binary am I running?
which python3
# In scripts, prefer the POSIX-compatible builtin (works in bash, dash, zsh):
command -v python3
type -a python3
```

`man -k` (equivalent to `apropos`) searches all man page titles and descriptions. Useful when you know what you want to do but not the command name.

### File and Directory Operations

```bash
# Navigation
pwd                          # Print working directory
cd /var/log                  # Change directory (absolute path)
cd ../                       # Go up one level
cd ~                         # Go to home directory
cd -                         # Go to previous directory

# Listing
ls -la                       # Long format, all files (including hidden)
ls -lah                      # Add human-readable file sizes
ls -lt                       # Sort by modification time (newest first)
ls -lS                       # Sort by file size (largest first)
ls -laR /etc/                # Recursive listing

# File operations
cp source.txt dest.txt       # Copy file
cp -r dir1/ dir2/            # Copy directory recursively
mv old.txt new.txt           # Move or rename
rm file.txt                  # Delete file
rm -rf directory/            # Delete directory recursively (use with caution)
mkdir -p /path/to/nested/    # Create nested directories
touch newfile.txt            # Create empty file or update timestamp
```

### File Content

```bash
# Viewing files
cat file.txt                 # Print entire file
less file.txt                # Paginated viewer (q to quit, / to search)
head -20 file.txt            # First 20 lines
tail -20 file.txt            # Last 20 lines
tail -f /var/log/syslog      # Follow file in real-time (live log monitoring)

# Counting
wc -l file.txt               # Line count
wc -w file.txt               # Word count
wc -c file.txt               # Byte count
```

`tail -f` is essential during engagements for monitoring log files in real time — watching authentication logs during brute-force, tracking web server access logs during testing, or observing syslog during exploitation.

### Text Processing

Text processing is where Linux command-line power becomes apparent. These tools chain together with pipes to filter, transform, and extract data from command output and files.

```bash
# grep — search for patterns
grep "error" /var/log/syslog              # Search for string
grep -i "error" file.txt                  # Case-insensitive
grep -rI "password" /etc/                  # Recursive search (skip binary files)
grep -n "pattern" file.txt               # Show line numbers
grep -v "comment" file.txt               # Invert match (exclude lines)
grep -c "pattern" file.txt               # Count matching lines
grep -E "error|warning|critical" file.txt # Extended regex (OR)
grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" file.txt  # Extract IPs

# cut — extract columns/fields
cut -d':' -f1 /etc/passwd                # Extract usernames (field 1, colon-delimited)
cut -d',' -f2,4 data.csv                 # Extract CSV columns 2 and 4

# awk — field processing
awk '{print $1}' file.txt                # Print first column (whitespace-delimited)
awk -F: '{print $1, $3}' /etc/passwd     # Print username and UID
awk -F: '$3 >= 1000' /etc/passwd         # Filter: UID >= 1000
awk '{print NR, $0}' file.txt            # Add line numbers

# sed — stream editor
sed 's/old/new/g' file.txt               # Replace all occurrences
sed -n '5,10p' file.txt                  # Print lines 5-10
sed '/^#/d' config.txt                   # Delete comment lines
sed -i 's/old/new/g' file.txt            # Edit file in-place

# sort and uniq
sort file.txt                            # Alphabetical sort
sort -n file.txt                         # Numerical sort
sort -u file.txt                         # Sort and remove duplicates
sort file.txt | uniq -c | sort -rn       # Count occurrences, sort by frequency

# tr — translate/delete characters
echo "UPPER" | tr 'A-Z' 'a-z'           # Lowercase
cat file.txt | tr -d '\r'               # Remove Windows carriage returns
cat file.txt | tr -s ' '                # Squeeze repeated spaces
```

### Pipes and Redirection

```bash
# Pipes chain commands — output of one becomes input of next
cat access.log | grep "POST" | awk '{print $1}' | sort | uniq -c | sort -rn

# Redirection
command > file.txt            # Redirect stdout (overwrite)
command >> file.txt           # Redirect stdout (append)
command 2> errors.txt         # Redirect stderr
command &> all.txt            # Redirect both stdout and stderr
command 2>&1                  # Redirect stderr to stdout
command < input.txt           # Redirect stdin from file

# Tee — write to file AND display on screen
command | tee output.txt      # Save and display
command | tee -a output.txt   # Append mode
```

### Finding Files

```bash
# find — search by name, type, size, permissions, time
find / -name "*.conf" 2>/dev/null                    # Find by name
find / -type f -name "*.log" 2>/dev/null             # Files only
find / -type d -name "backup" 2>/dev/null            # Directories only
find / -perm -4000 -type f 2>/dev/null               # SUID files (privesc)
find / -perm -2000 -type f 2>/dev/null               # SGID files
find / -writable -type f 2>/dev/null                 # Files writable by current user
find / -user root -perm -4000 2>/dev/null            # Root-owned SUID files
find /home -mtime -7 2>/dev/null                     # Modified in last 7 days
find / -name "*.txt" -exec grep -l "password" {} \;  # Find files containing "password"

# locate — fast filename search (uses pre-built database)
locate *.conf
updatedb                     # Update locate database
```

The `2>/dev/null` redirect suppresses "Permission denied" errors that flood output when searching as a non-root user.

### Archives and Compression

```bash
# tar
tar -czf archive.tar.gz directory/      # Create gzipped archive
tar -xzf archive.tar.gz                 # Extract gzipped archive
tar -xjf archive.tar.bz2                # Extract bzip2 archive
tar -tf archive.tar.gz                  # List contents without extracting

# zip
zip -r archive.zip directory/           # Create zip
unzip archive.zip                       # Extract zip
unzip -l archive.zip                    # List contents

# gzip / gunzip
gzip file.txt                           # Compress (replaces original)
gunzip file.txt.gz                      # Decompress
```

`tar` flags: `-c` create, `-x` extract, `-z` gzip, `-j` bzip2, `-f` filename, `-t` list, `-v` verbose.

### Networking Commands

```bash
# Interface information
ip addr show                             # Show IP addresses (modern)
ip route show                            # Show routing table
ifconfig                                 # Show interfaces (legacy, still common)

# Connectivity
ping -c 4 192.168.1.1                    # ICMP ping (4 packets)
traceroute 192.168.1.1                   # Trace route
ss -tlnp                                 # Show listening TCP ports with process info
netstat -tlnp                            # Same (legacy, still common)

# DNS
dig example.com                          # DNS lookup
dig example.com +short                   # Concise output
host example.com                         # Simple DNS lookup
nslookup example.com                     # Interactive DNS

# Downloads and transfers
curl -s https://example.com              # HTTP request
curl -o file.txt https://example.com     # Save to file
wget https://example.com/file.zip        # Download file
wget -r -l 1 https://example.com/        # Recursive download (1 level)

# Netcat — the "Swiss army knife"
nc -lvnp 4444                            # Listen on port 4444
nc 192.168.1.1 80                        # Connect to port 80
echo "test" | nc -w 1 192.168.1.1 80    # Send data and disconnect
```

`ss` flags: `-t` TCP, `-l` listening, `-n` numeric (no DNS resolution), `-p` show process. `ss` is the modern replacement for `netstat`.

### System Information

```bash
# System
uname -a                                 # Kernel version, architecture
hostname                                 # System hostname
cat /etc/os-release                      # Distribution information
uptime                                   # System uptime and load

# Users
whoami                                   # Current user
id                                       # UID, GID, groups
who                                      # Logged-in users
w                                        # Logged-in users with activity
last                                     # Login history

# Disk
df -h                                    # Disk space (human-readable)
du -sh /var/log/                         # Directory size
lsblk                                    # Block devices

# Hardware
lscpu                                    # CPU information
free -h                                  # Memory usage
```

### Environment Variables

```bash
# View
env                                      # All environment variables
echo $PATH                               # Show PATH
echo $HOME                               # Home directory
echo $USER                               # Current username
echo $SHELL                              # Current shell

# Set
export VAR="value"                       # Set for current session and child processes
VAR="value"                              # Set for current shell only
unset VAR                                # Remove variable

# PATH manipulation
export PATH="$PATH:/opt/tools"           # Append to PATH
export PATH="/opt/tools:$PATH"           # Prepend to PATH
```

## Practical Examples

### Security-Relevant Command Chains

```bash
# Extract unique IPs from a log file, sorted by frequency
grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" access.log | \
  sort | uniq -c | sort -rn | head -20

# Find all world-writable files owned by root (privesc candidates)
find / -writable -type f -user root 2>/dev/null

# List all SUID binaries (privesc enumeration)
find / -perm -4000 -type f 2>/dev/null

# Extract usernames from /etc/passwd (non-system users, UID >= 1000)
awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd

# Monitor failed SSH logins in real time
tail -f /var/log/auth.log | grep "Failed password"

# Find files modified in the last 24 hours (incident response)
find / -mtime -1 -type f 2>/dev/null | grep -v "/proc\|/sys\|/run"
```

## References

### Official Documentation

- [GNU Coreutils Manual](https://www.gnu.org/software/coreutils/manual/)
- [Bash Reference Manual](https://www.gnu.org/software/bash/manual/)
- [The Linux man-pages Project](https://www.kernel.org/doc/man-pages/)
