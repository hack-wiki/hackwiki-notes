% Filename: 02-reconnaissance/enum-database/overview.md
% Display name: Database Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Database Enumeration

## Overview

Database services exposed to the network are high-value enumeration targets. Default credentials, missing authentication, and excessive privileges frequently provide direct access to sensitive data and, in many cases, command execution on the underlying host.

## Topics in This Section

- [MongoDB Enumeration](mongodb.md) — NoSQL document store, unauthenticated access, data extraction
- [MSSQL Enumeration](mssql.md) — Windows integration, xp_cmdshell, impersonation, linked servers
- [MySQL Enumeration](mysql.md) — Credential extraction, FILE privilege, UDF, config files
- [Oracle Enumeration](oracle.md) — TNS Listener, SID discovery, ODAT, default credentials
- [PostgreSQL Enumeration](postgresql.md) — COPY command, file read/write, command execution
- [Redis Enumeration](redis.md) — Key-value store, unauthenticated access, SSH key injection, webshell

## General Approach

1. **Detect the service and version** — Nmap version scan reveals the database type and version
2. **Test default and empty credentials** — `sa:''` (MSSQL), `root:''` (MySQL), `postgres:postgres` (PostgreSQL), no auth (Redis, MongoDB)
3. **Enumerate databases, tables, and users** — map the data available
4. **Check privileges** — superuser/sysadmin access opens file read/write and command execution
5. **Extract credentials** — password hashes, application configs, connection strings
6. **Test credential reuse** — database passwords often work on SSH, SMB, RDP, and WinRM
