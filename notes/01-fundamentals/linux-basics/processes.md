% Filename: 01-fundamentals/linux-basics/processes.md
% Display name: Processes
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Processes

## Overview

A process is a running instance of a program. Every command you execute, every service running on a target, and every exploit you deploy is a process. Understanding process management matters for penetration testers — you need to identify what is running on a compromised system, find processes running as root that you might hijack, manage long-running tools during engagements, and clean up after yourself.

## Key Concepts

### Viewing Processes

### ps — Process Snapshot

`ps` shows a snapshot of current processes. Two common syntax styles exist: BSD style (no dashes) and UNIX style (with dashes). Both work.

```bash
# BSD style — most common in pentest contexts
ps aux
```

| Column | Meaning |
|--------|---------|
| USER | Process owner |
| PID | Process ID |
| %CPU | CPU usage percentage |
| %MEM | Memory usage percentage |
| VSZ | Virtual memory size (KB) |
| RSS | Resident set size — physical memory (KB) |
| TTY | Terminal associated with the process (`?` = no terminal, daemon) |
| STAT | Process state |
| START | Start time |
| TIME | Cumulative CPU time |
| COMMAND | Command that started the process |

Process states (STAT column):

| State | Meaning |
|-------|---------|
| `R` | Running or runnable |
| `S` | Interruptible sleep (waiting for event) |
| `D` | Uninterruptible sleep (usually I/O) |
| `T` | Stopped (by signal or job control) |
| `Z` | Zombie (terminated but not reaped by parent) |
| `I` | Idle kernel thread (Linux 4.14+, common in `ps` output) |

Additional STAT modifiers: `s` = session leader, `l` = multi-threaded, `+` = foreground process group, `<` = high priority, `N` = low priority.

```bash
# UNIX style — full format
ps -ef

# Filter for specific user
ps -u root

# Filter by process name
ps aux | grep apache2
ps aux | grep -v grep | grep apache2   # Exclude grep itself

# Show process tree (parent-child relationships)
ps auxf
ps -ejH
```

`ps auxf` shows the process tree with indentation — useful for understanding which process spawned which. Web shells, reverse shells, and injected processes become visible in the tree structure.

### top / htop — Real-Time Monitoring

```bash
# top — built-in process monitor
top
```

Inside `top`: `P` sorts by CPU, `M` sorts by memory, `k` kills a process (prompts for PID), `q` quits. `top` updates every 5 seconds by default.

```bash
# Single snapshot (non-interactive)
top -bn1 | head -20
```

The `-b` flag enables batch mode (non-interactive), `-n1` limits to one iteration. Useful in scripts and when piping output.

### Process Information from /proc

Every running process has a directory under `/proc/[PID]/` containing detailed information.

```bash
# Command that started the process
cat /proc/[PID]/cmdline | tr '\0' ' '

# Environment variables (may contain secrets)
cat /proc/[PID]/environ | tr '\0' '\n'

# Current working directory
ls -la /proc/[PID]/cwd

# Executable path
ls -la /proc/[PID]/exe

# Open file descriptors
ls -la /proc/[PID]/fd/

# Process status (UID, GID, memory, state)
cat /proc/[PID]/status
```

`/proc/[PID]/environ` is a high-value target during post-exploitation. Applications frequently pass database passwords, API keys, and tokens through environment variables. These are readable by the process owner or root.

`/proc/[PID]/cmdline` often reveals command-line arguments including credentials passed as flags (e.g., `mysql -u admin -pSecretPass`).

### Signals

Signals are software interrupts sent to processes. The `kill` command sends signals despite its name — not all signals terminate the process.

```bash
# Send SIGTERM (15) — polite termination request
kill [PID]
kill -15 [PID]

# Send SIGKILL (9) — force kill (cannot be caught or ignored)
kill -9 [PID]

# Send SIGHUP (1) — hangup (often causes config reload)
kill -1 [PID]

# Send SIGSTOP (19) — pause process
kill -STOP [PID]

# Send SIGCONT (18) — resume paused process
kill -CONT [PID]

# Kill by name
killall apache2             # All processes named apache2
pkill -f "python3 server"   # Match against full command line
```

Key signals:

| Signal | Number | Default Action | Notes |
|--------|--------|---------------|-------|
| SIGHUP | 1 | Terminate | Many daemons reload config instead |
| SIGINT | 2 | Terminate | Ctrl+C sends this |
| SIGQUIT | 3 | Terminate + core dump | Ctrl+\ sends this |
| SIGKILL | 9 | Terminate (forced) | Cannot be caught, blocked, or ignored |
| SIGTERM | 15 | Terminate (graceful) | Default signal sent by `kill` |
| SIGSTOP | 19 | Stop (pause) | Cannot be caught or ignored (unlike SIGTSTP) |
| SIGTSTP | 20 | Stop (pause) | Ctrl+Z sends this; can be caught by programs |
| SIGCONT | 18 | Continue | Resumes a stopped process |

```bash
# List all available signals
kill -l
```

### Job Control

Job control lets you manage multiple processes from a single terminal — essential during engagements when running listeners, scans, and exploits simultaneously.

```bash
# Nmap
# https://nmap.org/
# Run command in background
nmap -sV 192.168.1.0/24 &

# Ctrl+Z — suspend current foreground process
# (sends SIGTSTP)

# List background jobs
jobs

# Resume job in background
bg %1               # Resume job 1 in background

# Bring job to foreground
fg %1               # Bring job 1 to foreground

# Disown — detach job from terminal (survives terminal close)
disown %1
```

Job numbers are shown in `jobs` output as `[1]`, `[2]`, etc. The `%` prefix references job numbers (not PIDs).

### Persistent Processes

Processes started in a terminal die when the terminal closes (SIGHUP). Several methods keep processes running after disconnection:

```bash
# nohup — immune to hangup signal, output goes to nohup.out
nohup ./long_scan.sh &

# screen — terminal multiplexer
screen -S scan              # Create named session
# (run commands inside screen)
# Ctrl+A then D — detach
screen -ls                  # List sessions
screen -r scan              # Reattach to session

# tmux — modern terminal multiplexer
tmux new -s scan            # Create named session
# (run commands inside tmux)
# Ctrl+B then D — detach
tmux ls                     # List sessions
tmux attach -t scan         # Reattach to session
```

`screen` and `tmux` are essential for engagements — run Metasploit in one pane, a listener in another, and enumeration in a third. If your SSH connection drops, everything keeps running.

### Service Management (systemd)

Most modern Linux distributions use systemd to manage services.

```bash
# Check service status
systemctl status ssh
systemctl status apache2

# Start, stop, restart
systemctl start ssh
systemctl stop apache2
systemctl restart nginx

# Enable/disable at boot
systemctl enable ssh         # Start on boot
systemctl disable apache2    # Don't start on boot

# List all running services
systemctl list-units --type=service --state=running

# List all enabled services
systemctl list-unit-files --type=service --state=enabled
```

During post-exploitation, `systemctl list-units --type=service --state=running` shows every active service — databases, web servers, monitoring agents, and security tools that might detect your presence.

## Practical Examples

### Post-Exploitation Process Enumeration

```bash
# What's running?
ps aux

# What's running as root?
ps aux | awk '$1 == "root" {print}'

# What's listening on the network?
ss -tlnp

# Check for credentials in process arguments
ps aux | grep -iE "pass|pwd|key|token|secret" | grep -v grep

# Check for credentials in environment variables
for pid in $(ls /proc/ | grep -E "^[0-9]+$"); do
  cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | \
    grep -iE "pass|pwd|key|token|secret" && echo "  ^ PID: $pid"
done

# Find processes running from unusual locations
ps aux | awk '{print $11}' | sort -u | grep -vE "^\[|^/usr|^/sbin|^/bin|^/lib"
```

## References

### Official Documentation

- [The Linux man-pages Project — ps(1)](https://man7.org/linux/man-pages/man1/ps.1.html)
- [The Linux man-pages Project — signal(7)](https://man7.org/linux/man-pages/man7/signal.7.html)
- [The Linux man-pages Project — proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)
- [GNU Screen Manual](https://www.gnu.org/software/screen/manual/)
- [tmux GitHub Repository](https://github.com/tmux/tmux)
