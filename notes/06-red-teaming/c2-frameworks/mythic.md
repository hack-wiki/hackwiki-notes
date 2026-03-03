% Filename: 06-red-teaming/c2-frameworks/mythic.md
% Display name: Mythic C2
% Last update: 2026-02-11
% ATT&CK Tactics: TA0011 (Command and Control)
% ATT&CK Techniques: T1071.001 (Application Layer Protocol: Web Protocols), T1071.004 (Application Layer Protocol: DNS)
% Authors: @TristanInSec

# Mythic C2

## Overview

Mythic is an open-source, modular C2 framework built on Docker and designed for collaborative red team operations. Unlike monolithic C2 frameworks, Mythic ships with zero agents and zero C2 profiles — everything is installed as separate Docker containers. This modular architecture means agents can be written in any language (C#, Go, Rust, Python, C, Swift) and C2 profiles can use any transport (HTTP, DNS, WebSocket, Discord, Slack, GitHub). Mythic is sponsored by SpecterOps and provides a modern React web UI.

## ATT&CK Mapping

- **Tactic:** TA0011 - Command and Control
- **Techniques:**
  - T1071.001 - Application Layer Protocol: Web Protocols
  - T1071.004 - Application Layer Protocol: DNS

## Prerequisites

- Docker Engine 20.10.22+ (any recent version satisfies this; Docker now uses date-based versioning, e.g. 26.x, 27.x)
- Docker Compose plugin
- Minimum: 2 CPU, 4 GB RAM
- Linux recommended

## Techniques

### Installation

```bash
# Mythic
# https://github.com/its-a-feature/Mythic

# Clone and build
git clone https://github.com/its-a-feature/Mythic --depth 1 --single-branch
cd Mythic
sudo make

# Start Mythic (all core containers)
sudo ./mythic-cli start

# Web UI: https://<server_ip>:7443
# Default user: mythic_admin (random password in .env file)
# View generated password:
cat .env | grep MYTHIC_ADMIN_PASSWORD

# Install agents (each is a separate Docker container)
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo
sudo ./mythic-cli install github https://github.com/MythicAgents/Poseidon
sudo ./mythic-cli install github https://github.com/MythicAgents/Athena

# Install C2 profiles
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/websocket
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/dns

# Start specific containers
sudo ./mythic-cli payload start Apollo
sudo ./mythic-cli c2 start http
```

### Architecture

```bash
# Mythic
# https://github.com/its-a-feature/Mythic

# Core containers (started by default):
#   mythic_server     — GoLang server (gRPC + REST API)
#   mythic_postgres   — PostgreSQL database
#   mythic_react      — React web UI
#   mythic_nginx      — NGINX reverse proxy (SSL on port 7443)
#   mythic_graphql    — Hasura GraphQL API engine
#   mythic_rabbitmq   — RabbitMQ message bus (inter-container comms)
#   mythic_jupyter    — Jupyter notebook for scripting
#   mythic_documentation — Hugo-based docs

# Agent containers (installed separately):
#   Each agent runs as its own Docker container
#   Communicates with mythic_server via RabbitMQ
#   Handles payload building, command processing, response parsing

# C2 Profile containers (installed separately):
#   Each C2 profile runs as its own Docker container
#   Handles network transport (HTTP, DNS, etc.)
#   Routes traffic between agents and mythic_server
```

### Primary Agents

```bash
# Mythic
# https://github.com/its-a-feature/Mythic

# Apollo — Windows agent (C# .NET 4.0, SpecterOps training agent)
# https://github.com/MythicAgents/Apollo
#
# Key commands (must be selected at payload build time — not all included by default):
#   shell <cmd>                   — cmd.exe execution
#   powershell <cmd>              — PowerShell execution
#   powerpick <cmd>               — PowerShell without powershell.exe
#   execute_assembly <path> [args] — .NET assembly in-memory
#   execute_coff <path> [args]    — Beacon Object File execution
#   execute_pe <path> [args]      — PE execution in-memory
#   mimikatz <cmd>                — Mimikatz in-memory
#   dcsync <domain> <user>        — DCSync attack
#   make_token <user> <pass>      — Create access token
#   steal_token <pid>             — Steal token from process
#   rev2self                      — Revert to original token
#   inject <pid> <shellcode>      — Process injection
#   socks <port>                  — SOCKS5 proxy
#   link / unlink                 — P2P communication (SMB/TCP)
#   download / upload             — File transfer
#   screenshot                    — Capture screen
#   keylog_inject <pid>           — Keylogger injection
#   pth <user> <hash>             — Pass-the-hash

# Poseidon — Linux/macOS agent (Go)
# https://github.com/MythicAgents/Poseidon
#
# Compiles to native x64 executables for Linux and macOS

# Athena — Cross-platform agent (C# .NET)
# https://github.com/MythicAgents/Athena
#
# Supports: Windows, Linux, macOS
# Features: SOCKS5, reverse port forwarding, BOF support
# C2 profiles: HTTP, WebSocket, SMB, GitHub

# Thanatos — Windows/Linux agent (Rust)
# https://github.com/MythicAgents/Thanatos
#
# Features: Built-in SSH client, port scanner, TCP redirectors
```

### C2 Profiles

```bash
# Mythic
# https://github.com/its-a-feature/Mythic

# --- Egress Profiles (Agent → Server) ---

# HTTP/HTTPS (basic async, GET/POST)
# https://github.com/MythicC2Profiles/http
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http

# HTTPX (advanced HTTP with domain rotation, message transforms)
# https://github.com/MythicC2Profiles/httpx
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/httpx

# WebSocket (persistent connection, push/poll)
# https://github.com/MythicC2Profiles/websocket
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/websocket

# DNS (TXT query-based C2)
# https://github.com/MythicC2Profiles/dns
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/dns

# Discord (C2 over Discord REST API)
# https://github.com/MythicC2Profiles/discord
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/discord

# GitHub (C2 via GitHub issue comments)
# https://github.com/MythicC2Profiles/github
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/github

# --- P2P Profiles (Agent → Agent) ---

# SMB (named pipes)
# https://github.com/MythicC2Profiles/smb
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/smb

# TCP (raw TCP sockets)
# https://github.com/MythicC2Profiles/tcp
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/tcp
```

### Payload Generation (Web UI)

```bash
# Mythic
# https://github.com/its-a-feature/Mythic

# Payloads are generated through the web UI:
# 1. Navigate to https://<server>:7443
# 2. Click "Create Payload" (or Payloads menu)
# 3. Select agent type (Apollo, Poseidon, Athena, etc.)
# 4. Select C2 profile (http, websocket, dns, etc.)
# 5. Configure C2 parameters:
#    - Callback host/domain
#    - Callback port
#    - Callback interval (sleep)
#    - Jitter percentage
#    - Kill date
#    - Encryption keys (auto-generated)
# 6. Select commands to include in the payload
# 7. Build — payload is compiled in the agent's Docker container
# 8. Download the compiled payload

# The build process happens inside the agent's Docker container
# Each agent handles its own compilation (C#, Go, Rust, etc.)
```

### Operations and Collaboration

```bash
# Mythic
# https://github.com/its-a-feature/Mythic

# Operations — isolated workspaces for engagements
# Each operation has:
#   - Separate callback/task history
#   - Operator role assignments (operator, lead, spectator)
#   - Command block lists (restrict dangerous commands)
#   - Credential tracking
#   - File tracking
#   - MITRE ATT&CK mapping

# Operator roles:
#   Operation Admin — full access, can modify operation settings
#   Operator  — can task callbacks, view data
#   Spectator — read-only access

```

### Scripting and API

```python
# Mythic
# https://github.com/its-a-feature/Mythic

# Mythic provides a Python scripting library and Jupyter notebooks

# Install the scripting library
# pip install mythic

# GraphQL API available at https://<server>:7443/graphql
# API tokens generated through the web UI

# Jupyter notebooks accessible at https://<server>:8888
# Pre-configured to connect to the Mythic API
```

## Detection Methods

### Network-Based Detection

- HTTP/S beaconing patterns to the Mythic server
- DNS C2: high-volume TXT queries to a single domain
- WebSocket connections with encoded payloads
- Traffic to Discord/GitHub/Slack APIs from unexpected hosts

### Host-Based Detection

- Agent-specific indicators (Go binary for Poseidon, .NET for Apollo)
- In-memory .NET execution (execute_assembly, execute_coff)
- Token manipulation (make_token, steal_token)
- SOCKS proxy creation

## Mitigation Strategies

- **Network monitoring** — profile C2 traffic for each supported transport
- **EDR** — detect agent-specific behaviors (process injection, credential access)
- **API monitoring** — detect abuse of Discord/GitHub/Slack for C2
- **Application control** — block unauthorized binaries

## References

### Official Documentation

- [Mythic C2 Framework](https://github.com/its-a-feature/Mythic)
- [Mythic Documentation](https://docs.mythic-c2.net/)
- [MythicAgents (GitHub Org)](https://github.com/MythicAgents)
- [MythicC2Profiles (GitHub Org)](https://github.com/MythicC2Profiles)

### MITRE ATT&CK

- [T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
